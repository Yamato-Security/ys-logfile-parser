//! Logs built byte by byte from the published layouts: restart pages, log
//! record pages with update sequence arrays, records spanning pages and
//! wrapping round the circular area, buffer pages, damage; the content of
//! file records, attributes and index entries; and no input makes the
//! reader panic.

use ntfslog::{
    Body, Namespace, Operation, Options, ProblemKind, SizeSource, Update, parse, parse_with,
};
use proptest::prelude::*;

const PAGE: usize = 4096;
const SECTOR: usize = 512;
/// Where records start in a log record page, and how long their headers are.
const DATA: usize = 0x40;
const HEADER: usize = 48;
/// The update sequence array of a log record page.
const PAGE_ARRAY: usize = 0x28;
/// A 1 MiB log: 20 sequence number bits leave 44 for offsets.
const FILE_SIZE: usize = 256 * PAGE;
const SEQUENCE_BITS: u32 = 44;
/// 2024-03-01T12:00:00Z.
const FILETIME: u64 = 133_537_680_000_000_000;
const ROOT: u64 = 0x0005_0000_0000_0005;

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn put(bytes: &mut [u8], at: usize, value: &[u8]) {
    bytes[at..at + value.len()].copy_from_slice(value);
}

/// Write the update sequence array at `array` and protect each sector.
fn protect(block: &mut [u8], array: usize) {
    let sectors = block.len() / SECTOR;
    put(block, 4, &(array as u16).to_le_bytes());
    put(block, 6, &(sectors as u16 + 1).to_le_bytes());
    put(block, array, &[0x2A, 0x00]);
    for sector in 0..sectors {
        let last = (sector + 1) * SECTOR - 2;
        let saved = [block[last], block[last + 1]];
        put(block, array + 2 + 2 * sector, &saved);
        put(block, last, &[0x2A, 0x00]);
    }
}

/// A log under construction: unprotected pages, all `0xFF` until written.
struct Log {
    major: i16,
    pages: Vec<Vec<u8>>,
    current_lsn: u64,
}

impl Log {
    fn new(major: i16) -> Self {
        Self {
            major,
            pages: vec![vec![0xFF; PAGE]; FILE_SIZE / PAGE],
            current_lsn: 0,
        }
    }

    fn first_circular(&self) -> usize {
        if self.major >= 2 { 34 } else { 4 }
    }

    fn lsn(pass: u64, offset: usize) -> u64 {
        pass << (64 - SEQUENCE_BITS) | (offset as u64 >> 3)
    }

    /// The page at `index`, made a log record page if it isn't one.
    fn page(&mut self, index: usize) -> &mut Vec<u8> {
        let page = &mut self.pages[index];
        if page[..4] != *b"RCRD" {
            page.fill(0);
            put(page, 0, b"RCRD");
        }
        page
    }

    /// Record that `page` holds records up to `lsn`, ending one there when
    /// `ends`, with free space from `free`.
    fn mark(&mut self, index: usize, lsn: u64, ends: bool, free: usize) {
        let page = self.page(index);
        let field =
            |page: &Vec<u8>, at: usize| u64::from_le_bytes(page[at..at + 8].try_into().unwrap());
        let last = field(page, 8).max(lsn);
        put(page, 8, &last.to_le_bytes());
        put(page, 16, &1_u32.to_le_bytes());
        put(page, 20, &[1, 0, 1, 0]);
        put(page, 24, &(free as u16).to_le_bytes());
        if ends {
            put(page, 32, &lsn.to_le_bytes());
        }
    }

    /// Write a record at byte `offset` of the log in `pass`, its client
    /// data continuing in the next pages and wrapping round. Returns its
    /// LSN.
    fn record(&mut self, pass: u64, offset: usize, kind: u32, data: &[u8]) -> u64 {
        let lsn = Self::lsn(pass, offset);
        let mut header = Vec::new();
        header.extend(lsn.to_le_bytes());
        header.extend(self.current_lsn.to_le_bytes());
        header.extend(0_u64.to_le_bytes());
        header.extend((data.len() as u32).to_le_bytes());
        header.extend([0; 4]); // client 0, sequence 0
        header.extend(kind.to_le_bytes());
        header.extend(0x18_u32.to_le_bytes());
        let spans = offset % PAGE + HEADER + data.len() > PAGE;
        header.extend(u16::from(spans).to_le_bytes());
        header.resize(HEADER, 0);
        let (mut index, mut at) = (offset / PAGE, offset % PAGE);
        put(self.page(index), at, &header);
        at += HEADER;
        let mut rest = data;
        loop {
            let here = rest.len().min(PAGE - at);
            put(self.page(index), at, &rest[..here]);
            rest = &rest[here..];
            if rest.is_empty() {
                self.mark(index, lsn, true, at + here);
                break;
            }
            self.mark(index, lsn, false, PAGE);
            index += 1;
            if index == self.pages.len() {
                index = self.first_circular();
            }
            at = DATA;
        }
        self.current_lsn = lsn;
        lsn
    }

    /// A copy of page `index` in buffer page `buffer`, as it is now.
    fn copy_to_buffer(&mut self, index: usize, buffer: usize) {
        let mut copy = self.pages[index].clone();
        if self.major >= 2 {
            put(&mut copy, 60, &((index * PAGE) as u32).to_le_bytes());
        } else {
            put(&mut copy, 8, &((index * PAGE) as u64).to_le_bytes());
        }
        self.pages[buffer] = copy;
    }

    fn restart_page(&self) -> Vec<u8> {
        let mut page = vec![0; PAGE];
        put(&mut page, 0, b"RSTR");
        put(&mut page, 16, &(PAGE as u32).to_le_bytes());
        put(&mut page, 20, &(PAGE as u32).to_le_bytes());
        put(&mut page, 24, &0x30_u16.to_le_bytes());
        // Version 1.1, or 2.0.
        let minor = i16::from(self.major < 2);
        put(&mut page, 26, &minor.to_le_bytes());
        put(&mut page, 28, &self.major.to_le_bytes());
        let area = 0x30;
        put(&mut page, area, &self.current_lsn.to_le_bytes());
        put(&mut page, area + 8, &[1, 0, 0xFF, 0xFF, 0, 0, 2, 0]);
        put(&mut page, area + 16, &SEQUENCE_BITS.to_le_bytes());
        put(&mut page, area + 20, &[0xE0, 0, 0x40, 0]);
        put(&mut page, area + 24, &(FILE_SIZE as u64).to_le_bytes());
        put(&mut page, area + 36, &[0x30, 0, 0x40, 0]);
        let client = area + 0x40;
        put(&mut page, client, &self.current_lsn.to_le_bytes());
        put(&mut page, client + 16, &[0xFF, 0xFF, 0xFF, 0xFF]);
        put(&mut page, client + 28, &8_u32.to_le_bytes());
        put(&mut page, client + 32, &utf16("NTFS"));
        protect(&mut page, 0x1E);
        page
    }

    fn build(&self) -> Vec<u8> {
        let mut data = self.restart_page();
        data.extend(self.restart_page());
        for page in &self.pages[2..] {
            let mut page = page.clone();
            if page[..4] == *b"RCRD" {
                protect(&mut page, PAGE_ARRAY);
            }
            data.extend(page);
        }
        data
    }
}

/// An update record's client data.
#[derive(Default)]
struct Spec<'a> {
    redo: u16,
    undo: u16,
    redo_data: &'a [u8],
    undo_data: &'a [u8],
    target: u16,
    vcn: i64,
    record_offset: u16,
    attribute_offset: u16,
    lcns: &'a [i64],
}

impl Spec<'_> {
    fn bytes(&self) -> Vec<u8> {
        let header = 32 + 8 * self.lcns.len();
        let undo_at = header + self.redo_data.len().next_multiple_of(8);
        let mut data = Vec::new();
        for value in [
            self.redo,
            self.undo,
            header as u16,
            self.redo_data.len() as u16,
            undo_at as u16,
            self.undo_data.len() as u16,
            self.target,
            self.lcns.len() as u16,
            self.record_offset,
            self.attribute_offset,
            0,
            2, // 1 KiB file records
        ] {
            data.extend(value.to_le_bytes());
        }
        data.extend(self.vcn.to_le_bytes());
        for lcn in self.lcns {
            data.extend(lcn.to_le_bytes());
        }
        data.extend(self.redo_data);
        data.resize(undo_at, 0);
        data.extend(self.undo_data);
        data.resize(data.len().next_multiple_of(8), 0);
        data
    }
}

/// An update with only a redo side.
fn simple(redo: u16, redo_data: &[u8]) -> Vec<u8> {
    Spec {
        redo,
        redo_data,
        ..Spec::default()
    }
    .bytes()
}

/// A `$FILE_NAME` value.
fn file_name(parent: u64, name: &str) -> Vec<u8> {
    let mut value = parent.to_le_bytes().to_vec();
    for _ in 0..4 {
        value.extend(FILETIME.to_le_bytes());
    }
    value.extend(4096_u64.to_le_bytes());
    value.extend(12_u64.to_le_bytes());
    value.extend(0x20_u32.to_le_bytes());
    value.extend([0; 4]);
    value.push(name.encode_utf16().count() as u8);
    value.push(1);
    value.extend(utf16(name));
    value
}

/// A resident attribute record.
fn attribute(kind: u32, value: &[u8]) -> Vec<u8> {
    let length = (0x18 + value.len()).next_multiple_of(8);
    let mut record = kind.to_le_bytes().to_vec();
    record.extend((length as u32).to_le_bytes());
    record.extend([0; 8]);
    record.extend((value.len() as u32).to_le_bytes());
    record.extend(0x18_u16.to_le_bytes());
    record.extend([0, 0]);
    record.extend(value);
    record.resize(length, 0);
    record
}

/// A directory index entry for `file`, keyed by its `$FILE_NAME`.
fn index_entry(file: u64, name: &[u8]) -> Vec<u8> {
    let length = (16 + name.len()).next_multiple_of(8);
    let mut entry = file.to_le_bytes().to_vec();
    entry.extend((length as u16).to_le_bytes());
    entry.extend((name.len() as u16).to_le_bytes());
    entry.extend([0; 4]);
    entry.extend(name);
    entry.resize(length, 0);
    entry
}

/// A whole file record: number 64, sequence 3, with `$STANDARD_INFORMATION`
/// and a `$FILE_NAME`.
fn file_record(name: &str) -> Vec<u8> {
    let mut record = vec![0; 0x38];
    put(&mut record, 0, b"FILE");
    put(&mut record, 0x10, &3_u16.to_le_bytes());
    put(&mut record, 0x14, &0x38_u16.to_le_bytes());
    put(&mut record, 0x2C, &64_u32.to_le_bytes());
    let mut times = Vec::new();
    for _ in 0..4 {
        times.extend(FILETIME.to_le_bytes());
    }
    times.resize(0x48, 0);
    record.extend(attribute(0x10, &times));
    record.extend(attribute(0x30, &file_name(ROOT, name)));
    record.extend(0xFFFF_FFFF_u32.to_le_bytes());
    record
}

fn first_update(log: &ntfslog::LogFile) -> &Update {
    log.records
        .iter()
        .find_map(ntfslog::LogRecord::update)
        .unwrap()
}

#[test]
fn restart_area() {
    let mut log = Log::new(2);
    log.record(1, 34 * PAGE + DATA, 1, &simple(0x1A, &[]));
    let parsed = parse(&log.build());
    assert_eq!(parsed.restart_pages.len(), 2);
    let restart = parsed.restart().unwrap();
    assert_eq!(
        (restart.offset, restart.version.to_string()),
        (0, "2.0".to_owned())
    );
    assert_eq!(
        (restart.system_page_size, restart.log_page_size),
        (4096, 4096)
    );
    let area = &restart.area;
    assert_eq!(area.current_lsn, Log::lsn(1, 34 * PAGE + DATA));
    assert!(area.is_clean() && !area.single_page_io());
    assert_eq!(
        (area.sequence_number_bits, area.file_size),
        (SEQUENCE_BITS, FILE_SIZE as u64)
    );
    assert_eq!(
        (area.record_header_length, area.log_page_data_offset),
        (48, 64)
    );
    assert_eq!(area.client_in_use_list, Some(0));
    assert_eq!(area.client_free_list, None);
    assert_eq!(area.clients.len(), 1);
    assert_eq!(area.clients[0].name, "NTFS");
    assert_eq!(parsed.problems, [] as [ntfslog::Problem; 0]);
}

#[test]
fn update_fields_and_targets() {
    let mut log = Log::new(2);
    let data = Spec {
        redo: 0x07,
        undo: 0x07,
        redo_data: &[1; 8],
        undo_data: &[2; 8],
        target: 0x18,
        vcn: 9,
        record_offset: 0x98,
        attribute_offset: 0x32,
        lcns: &[262_153],
    }
    .bytes();
    let lsn = log.record(1, 40 * PAGE + 200, 1, &data);
    let parsed = parse(&log.build());
    let record = &parsed.records[0];
    assert_eq!((record.lsn, record.offset), (lsn, (40 * PAGE + 200) as u64));
    assert_eq!((record.transaction_id, record.client.index), (0x18, 0));
    assert!(!record.spans_pages());
    let update = record.update().unwrap();
    assert_eq!(
        (update.redo, update.undo),
        (
            Operation::UpdateResidentValue,
            Operation::UpdateResidentValue
        )
    );
    assert_eq!(
        (update.redo_data.as_slice(), update.undo_data.as_slice()),
        (&[1; 8][..], &[2; 8][..])
    );
    assert_eq!(
        (update.target_vcn, update.lcns.as_slice()),
        (9, &[262_153][..])
    );
    // No checkpoint: 4 KiB clusters, 1 KiB records (two blocks).
    assert_eq!(
        (parsed.cluster_size, parsed.cluster_size_source),
        (4096, SizeSource::Inferred)
    );
    assert_eq!(update.mft_record, Some(36));
    assert_eq!(update.offset_in_target, Some(0xCA));
    assert_eq!(update.redo_times, None);
    // The caller's cluster size wins.
    let options = Options {
        cluster_size: Some(1024),
        record_size: None,
    };
    let parsed = parse_with(&log.build(), &options);
    assert_eq!(first_update(&parsed).mft_record, Some(9));
}

#[test]
fn records_spanning_pages() {
    let mut log = Log::new(2);
    let big: Vec<u8> = (0..9000_u32).map(|i| i as u8).collect();
    let lsn = log.record(1, 50 * PAGE + 3000, 1, &simple(0x08, &big));
    let after = log.record(1, 52 * PAGE + 4016, 1, &simple(0x1A, &[]));
    let parsed = parse(&log.build());
    assert_eq!(
        parsed.records.iter().map(|r| r.lsn).collect::<Vec<_>>(),
        [lsn, after]
    );
    assert!(parsed.records[0].spans_pages());
    assert_eq!(first_update(&parsed).redo_data, big);
    assert_eq!(parsed.problems, [] as [ntfslog::Problem; 0]);
}

#[test]
fn records_wrapping_round_the_circular_area() {
    let mut log = Log::new(2);
    let data: Vec<u8> = (0..3000_u32).map(|i| (i % 251) as u8).collect();
    let lsn = log.record(1, FILE_SIZE - 1000, 1, &simple(0x08, &data));
    let parsed = parse(&log.build());
    assert_eq!(parsed.records[0].lsn, lsn);
    assert_eq!(first_update(&parsed).redo_data, data);
}

#[test]
fn a_continuation_from_a_later_pass_cuts_a_record_short() {
    let mut log = Log::new(2);
    log.record(1, 60 * PAGE + 3800, 1, &simple(0x08, &[7; 2000]));
    // Pass 2 has since rewritten the page the record continued in.
    log.pages[61] = vec![0xFF; PAGE];
    let newer = log.record(2, 61 * PAGE + DATA, 1, &simple(0x1A, &[]));
    let parsed = parse(&log.build());
    assert_eq!(parsed.records.len(), 2);
    assert_eq!(parsed.records[1].lsn, newer);
    let problem = parsed.problems[0];
    assert_eq!(problem.offset, (60 * PAGE + 3800) as u64);
    assert!(matches!(problem.kind, ProblemKind::RecordCutShort { missing, .. } if missing > 0));
    assert!(problem.to_string().contains("cut short"));
}

#[test]
fn fast_pages_hold_the_last_pages_written() {
    let mut log = Log::new(2);
    let old = log.record(1, 70 * PAGE + DATA, 1, &simple(0x1A, &[]));
    log.copy_to_buffer(70, 5);
    // Written to a fast page only: never in place.
    let newest = log.record(1, 70 * PAGE + DATA + 80, 1, &simple(0x1B, &[]));
    log.copy_to_buffer(70, 6);
    log.pages[70] = log.pages[5].clone();
    let parsed = parse(&log.build());
    let found: Vec<_> = parsed.records.iter().map(|r| (r.lsn, r.offset)).collect();
    assert_eq!(
        found,
        [
            (old, (70 * PAGE + DATA) as u64),
            (newest, (6 * PAGE + DATA + 80) as u64)
        ]
    );
}

#[test]
fn tail_pages_of_version_1() {
    let mut log = Log::new(1);
    let lsn = log.record(1, 10 * PAGE + DATA, 1, &simple(0x1A, &[]));
    log.copy_to_buffer(10, 2);
    log.pages[10] = vec![0xFF; PAGE];
    let parsed = parse(&log.build());
    assert_eq!(parsed.restart().unwrap().version.to_string(), "1.1");
    assert_eq!(
        (parsed.records[0].lsn, parsed.records[0].offset),
        (lsn, (2 * PAGE + DATA) as u64)
    );
}

#[test]
fn torn_pages_are_skipped() {
    let mut log = Log::new(2);
    log.record(1, 40 * PAGE + DATA, 1, &simple(0x1A, &[]));
    let kept = log.record(1, 41 * PAGE + DATA, 1, &simple(0x1A, &[]));
    let mut data = log.build();
    data[40 * PAGE + 3 * SECTOR - 2] ^= 0xFF;
    let parsed = parse(&data);
    assert_eq!(
        parsed.records.iter().map(|r| r.lsn).collect::<Vec<_>>(),
        [kept]
    );
    assert_eq!(parsed.problems[0].offset, (40 * PAGE) as u64);
    assert_eq!(parsed.problems[0].kind, ProblemKind::TornPage { sector: 2 });
}

#[test]
fn without_restart_pages_records_are_still_found() {
    let mut log = Log::new(2);
    // The sequence number bits Windows gives a 1 MiB log.
    let lsn = log.record(3, 100 * PAGE + DATA, 1, &simple(0x1A, &[]));
    let mut data = log.build();
    data[..2 * PAGE].fill(0);
    let parsed = parse(&data);
    assert_eq!(parsed.restart_pages, [] as [ntfslog::RestartPage; 0]);
    let kinds: Vec<_> = parsed.problems.iter().map(|p| p.kind).collect();
    assert_eq!(
        kinds,
        [
            ProblemKind::BadRestartPage,
            ProblemKind::NoRestartPage,
            ProblemKind::BadRestartPage
        ]
    );
    assert_eq!(parsed.records[0].lsn, lsn);
}

#[test]
fn an_unused_log() {
    let parsed = parse(&vec![0xFF; FILE_SIZE]);
    assert!(parsed.is_unused());
    assert!(!parse(&[0; 16]).is_unused());
}

#[test]
fn checkpoints_give_the_cluster_size() {
    let mut log = Log::new(2);
    let mut checkpoint = vec![0; 88];
    put(&mut checkpoint, 0, &1_u32.to_le_bytes());
    put(&mut checkpoint, 8, &77_u64.to_le_bytes());
    put(&mut checkpoint, 16, &78_u64.to_le_bytes());
    put(&mut checkpoint, 48, &984_u32.to_le_bytes());
    put(&mut checkpoint, 80, &65_536_u32.to_le_bytes());
    log.record(1, 40 * PAGE + DATA, 2, &checkpoint);
    log.record(
        1,
        41 * PAGE + DATA,
        1,
        &Spec {
            redo: 0x03,
            undo: 0x02,
            vcn: 3,
            ..Spec::default()
        }
        .bytes(),
    );
    let parsed = parse(&log.build());
    let Body::Checkpoint(checkpoint) = &parsed.records[0].body else {
        panic!("not a checkpoint");
    };
    assert_eq!((checkpoint.major_version, checkpoint.start_lsn), (1, 77));
    assert_eq!(
        (
            checkpoint.open_attribute_table.lsn,
            checkpoint.open_attribute_table.length
        ),
        (78, 984)
    );
    assert_eq!(checkpoint.bytes_per_cluster, Some(65_536));
    assert_eq!(parsed.cluster_size_source, SizeSource::Checkpoint);
    assert_eq!(parsed.records[1].update().unwrap().mft_record, Some(192));
}

#[test]
fn names_from_new_file_records() {
    let mut log = Log::new(2);
    let image = file_record("evil.exe");
    log.record(
        1,
        40 * PAGE + DATA,
        1,
        &Spec {
            redo: 0x02,
            undo: 0x00,
            redo_data: &image,
            vcn: 16,
            ..Spec::default()
        }
        .bytes(),
    );
    let parsed = parse(&log.build());
    let update = first_update(&parsed);
    let name = &update.redo_names[0];
    assert_eq!(
        (name.name.as_str(), name.namespace),
        ("evil.exe", Namespace::Win32)
    );
    assert_eq!(name.file.unwrap().to_string(), "64-3");
    assert_eq!(name.parent.to_string(), "5-5");
    assert_eq!(
        (name.size, name.allocated_size, name.attributes),
        (12, 4096, 0x20)
    );
    assert_eq!(
        name.created.to_iso8601().as_deref(),
        Some("2024-03-01T12:00:00.0000000Z")
    );
    let times = update.redo_times.unwrap();
    assert!(times.created.is_some() && times.accessed.is_some());
    assert!(update.undo_names.is_empty() && update.undo_times.is_none());
}

#[test]
fn names_from_directory_entries_and_attributes() {
    let mut log = Log::new(2);
    let name = file_name(ROOT, "notes.txt");
    let entry = index_entry(0x0001_0000_0000_0040, &name);
    // A directory entry added, then deleted (its undo data re-adds it).
    log.record(
        1,
        40 * PAGE + DATA,
        1,
        &Spec {
            redo: 0x0E,
            undo: 0x0F,
            redo_data: &entry,
            target: 0x40,
            record_offset: 0x40,
            ..Spec::default()
        }
        .bytes(),
    );
    log.record(
        1,
        41 * PAGE + DATA,
        1,
        &Spec {
            redo: 0x0F,
            undo: 0x0E,
            undo_data: &entry,
            target: 0x40,
            record_offset: 0x40,
            ..Spec::default()
        }
        .bytes(),
    );
    // A rename: one $FILE_NAME attribute deleted, another created.
    let renamed = attribute(0x30, &file_name(ROOT, "invoice.pdf.exe"));
    log.record(
        1,
        42 * PAGE + DATA,
        1,
        &Spec {
            redo: 0x05,
            undo: 0x06,
            redo_data: &renamed,
            vcn: 4,
            record_offset: 0x98,
            ..Spec::default()
        }
        .bytes(),
    );
    let parsed = parse(&log.build());
    let updates: Vec<&Update> = parsed.records.iter().filter_map(|r| r.update()).collect();
    assert_eq!(updates[0].redo_names[0].name, "notes.txt");
    assert_eq!(updates[0].redo_names[0].file.unwrap().to_string(), "64-1");
    assert_eq!(updates[1].redo_names, [] as [ntfslog::FileName; 0]);
    assert_eq!(updates[1].undo_names[0].name, "notes.txt");
    assert_eq!(updates[2].redo_names[0].name, "invoice.pdf.exe");
    assert_eq!(updates[2].redo_names[0].file, None);
}

#[test]
fn timestamps_written_over_standard_information() {
    let mut log = Log::new(2);
    let new = 125_911_584_000_000_000_u64.to_le_bytes(); // 2000-01-01
    let old = FILETIME.to_le_bytes();
    let (two_new, two_old) = ([new, new].concat(), [old, old].concat());
    // Modified and changed, at value offset 8 of the first attribute.
    log.record(
        1,
        40 * PAGE + DATA,
        1,
        &Spec {
            redo: 0x07,
            undo: 0x07,
            redo_data: &two_new,
            undo_data: &two_old,
            record_offset: 0x38,
            attribute_offset: 0x20,
            ..Spec::default()
        }
        .bytes(),
    );
    // Elsewhere in the record: not timestamps.
    log.record(
        1,
        41 * PAGE + DATA,
        1,
        &Spec {
            redo: 0x07,
            undo: 0x07,
            redo_data: &two_new,
            undo_data: &two_old,
            record_offset: 0x98,
            attribute_offset: 0x20,
            ..Spec::default()
        }
        .bytes(),
    );
    let parsed = parse(&log.build());
    let updates: Vec<&Update> = parsed.records.iter().filter_map(|r| r.update()).collect();
    let (redo, undo) = (
        updates[0].redo_times.unwrap(),
        updates[0].undo_times.unwrap(),
    );
    assert_eq!(redo.created, None);
    assert_eq!(
        redo.modified.unwrap().to_iso8601().as_deref(),
        Some("2000-01-01T00:00:00.0000000Z")
    );
    assert_eq!(
        undo.changed.unwrap().to_iso8601().as_deref(),
        Some("2024-03-01T12:00:00.0000000Z")
    );
    assert_eq!(updates[1].redo_times, None);
}

#[test]
fn open_attributes_name_nonresident_targets() {
    let mut log = Log::new(2);
    let mut entry = vec![0; 40];
    put(&mut entry, 0, &0xFFFF_FFFF_u32.to_le_bytes());
    put(&mut entry, 8, &0xA0_u32.to_le_bytes());
    put(&mut entry, 16, &ROOT.to_le_bytes());
    log.record(
        1,
        40 * PAGE + DATA,
        1,
        &Spec {
            redo: 0x1C,
            undo: 0x00,
            redo_data: &entry,
            undo_data: &utf16("$I30"),
            target: 0x40,
            ..Spec::default()
        }
        .bytes(),
    );
    let added = index_entry(0x0001_0000_0000_0041, &file_name(ROOT, "a.txt"));
    log.record(
        1,
        41 * PAGE + DATA,
        1,
        &Spec {
            redo: 0x0E,
            undo: 0x0F,
            redo_data: &added,
            target: 0x40,
            vcn: 2,
            record_offset: 0x40,
            attribute_offset: 0x18,
            ..Spec::default()
        }
        .bytes(),
    );
    let parsed = parse(&log.build());
    let update = parsed.records[1].update().unwrap();
    let target = update.target.as_ref().unwrap();
    assert_eq!(
        (
            target.file.to_string(),
            target.attribute_type,
            target.name.as_deref()
        ),
        ("5-5".to_owned(), 0xA0, Some("$I30"))
    );
    assert_eq!(update.mft_record, None);
    assert_eq!(update.offset_in_target, Some(2 * 4096 + 0x58));
}

/// An open attribute table entry, Windows 8's layout (40 bytes) or
/// Windows 7's (44).
fn open_entry(file: u64, kind: u32, windows7: bool) -> Vec<u8> {
    let (size, file_at, type_at) = if windows7 { (44, 8, 28) } else { (40, 16, 8) };
    let mut entry = vec![0; size];
    put(&mut entry, 0, &0xFFFF_FFFF_u32.to_le_bytes());
    put(&mut entry, file_at, &file.to_le_bytes());
    put(&mut entry, type_at, &kind.to_le_bytes());
    entry
}

/// A checkpoint: the NTFS restart area, naming the records that hold its
/// copies of the open attribute table and of the names (0 for none: a
/// mount or a clean dismount).
fn checkpoint(table: u64, names: u64) -> Vec<u8> {
    let mut area = vec![0; 88];
    put(&mut area, 0, &1_u32.to_le_bytes());
    put(&mut area, 16, &table.to_le_bytes());
    put(&mut area, 24, &names.to_le_bytes());
    put(&mut area, 80, &4096_u32.to_le_bytes());
    area
}

fn opens(target: u16, entry: &[u8], name: &str) -> Vec<u8> {
    Spec {
        redo: 0x1C,
        redo_data: entry,
        undo_data: &utf16(name),
        target,
        ..Spec::default()
    }
    .bytes()
}

fn writes(redo: u16, target: u16) -> Vec<u8> {
    Spec {
        redo,
        undo: redo,
        redo_data: &[1; 8],
        undo_data: &[0; 8],
        target,
        ..Spec::default()
    }
    .bytes()
}

#[test]
fn open_attributes_by_stretch_of_the_log() {
    const JOURNAL: u64 = 0x0002_0000_0000_0040;
    let mut log = Log::new(2);
    let mut page = 40;
    let mut add = |log: &mut Log, kind: u32, data: &[u8]| {
        page += 1;
        log.record(1, page * PAGE + DATA, kind, data)
    };
    // Stretch 1: written to before the record that opens it survives.
    let before = add(&mut log, 1, &writes(0x0E, 0x40));
    let opened = add(
        &mut log,
        1,
        &opens(0x40, &open_entry(ROOT, 0xA0, false), "$I30"),
    );
    add(&mut log, 1, &opens(0x18, &open_entry(0, 0x80, false), ""));
    let resident = add(&mut log, 1, &writes(0x07, 0x18));
    add(&mut log, 2, &checkpoint(0, 0));
    // Stretch 2, after a mount: the same offset is another attribute.
    let remounted = add(&mut log, 1, &writes(0x08, 0x40));
    add(
        &mut log,
        1,
        &opens(0x40, &open_entry(JOURNAL, 0x80, false), "$J"),
    );
    add(&mut log, 2, &checkpoint(0, 0));
    // Stretch 3: nothing says what it is.
    let unknown = add(&mut log, 1, &writes(0x08, 0x40));
    let committed = add(&mut log, 1, &simple(0x1B, &[]));

    let parsed = parse(&log.build());
    let update = |lsn: u64| {
        parsed
            .records
            .iter()
            .find(|record| record.lsn == lsn)
            .and_then(|record| record.update())
            .unwrap()
    };
    let target = |lsn: u64| {
        let update = update(lsn);
        let target = update.target.as_ref().unwrap();
        (
            target.file.raw(),
            target.attribute_type,
            target.name.clone().unwrap(),
            update.target_inferred,
        )
    };
    let index = (ROOT, 0xA0, "$I30".to_owned(), false);
    assert_eq!(
        target(before),
        index,
        "the oldest definition in its stretch"
    );
    assert_eq!(target(opened), index, "an open record's own attribute");
    assert_eq!(target(resident), (0, 0x80, String::new(), false));
    assert_eq!(update(resident).mft_record, Some(0));
    assert_eq!(target(remounted), (JOURNAL, 0x80, "$J".to_owned(), false));
    assert_eq!(target(unknown), (JOURNAL, 0x80, "$J".to_owned(), true));
    assert_eq!(update(committed).target, None, "no target");
    // Each record's previous LSN is the one before it here: one transaction.
    assert!(
        parsed
            .records
            .iter()
            .all(|record| record.transaction_first_lsn == before)
    );
}

#[test]
fn windows_7_open_records_get_their_names_from_a_later_table_copy() {
    let mut log = Log::new(1);
    let entry = open_entry(ROOT, 0xA0, true);
    let opened = log.record(
        1,
        40 * PAGE + DATA,
        1,
        &Spec {
            redo: 0x1C,
            redo_data: &entry,
            target: 0x18,
            ..Spec::default()
        }
        .bytes(),
    );
    let mut table = vec![0; 24];
    put(&mut table, 0, &44_u16.to_le_bytes());
    table.extend(&entry);
    let table_lsn = log.record(1, 41 * PAGE + DATA, 1, &simple(0x1D, &table));
    let mut names = 0x18_u16.to_le_bytes().to_vec();
    names.extend(8_u16.to_le_bytes());
    names.extend(utf16("$I30"));
    names.extend([0; 6]);
    let names_lsn = log.record(1, 42 * PAGE + DATA, 1, &simple(0x1E, &names));
    log.record(1, 43 * PAGE + DATA, 2, &checkpoint(table_lsn, names_lsn));
    let parsed = parse(&log.build());
    let open = parsed
        .records
        .iter()
        .find(|record| record.lsn == opened)
        .and_then(|record| record.update()?.target.clone())
        .unwrap();
    assert_eq!(open.name.as_deref(), Some("$I30"));
}

/// A log with something of everything.
fn mixed() -> Vec<u8> {
    let mut log = Log::new(2);
    log.record(
        1,
        40 * PAGE + DATA,
        1,
        &Spec {
            redo: 0x02,
            undo: 0x00,
            redo_data: &file_record("a"),
            vcn: 16,
            lcns: &[5],
            ..Spec::default()
        }
        .bytes(),
    );
    log.record(1, 40 * PAGE + 2000, 1, &simple(0x08, &[3; 6000]));
    log.record(
        1,
        FILE_SIZE - 600,
        1,
        &simple(0x0E, &index_entry(1, &file_name(ROOT, "b"))),
    );
    log.copy_to_buffer(41, 2);
    log.build()
}

fn check(parsed: &ntfslog::LogFile, length: usize) {
    for pair in parsed.records.windows(2) {
        assert!(pair[0].lsn < pair[1].lsn);
    }
    for problem in &parsed.problems {
        assert!(problem.offset <= length as u64);
        let _ = problem.to_string();
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Any bytes: never a panic.
    #[test]
    fn arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..20_000)) {
        check(&parse(&data), data.len());
    }

    /// A valid restart page, then anything.
    #[test]
    fn arbitrary_pages(tail in proptest::collection::vec(any::<u8>(), 0..40_000)) {
        let mut data = mixed()[..2 * PAGE].to_vec();
        data.extend(tail);
        check(&parse(&data), data.len());
    }

    /// Built and real logs, damaged anywhere, cut anywhere.
    #[test]
    fn damaged_logs(
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..60),
        cut in any::<usize>(),
        real in any::<bool>(),
    ) {
        let mut data = if real { real_log() } else { mixed() };
        for (at, byte) in flips {
            let len = data.len();
            data[at % len] = byte;
        }
        data.truncate(data.len() - cut % 4096);
        check(&parse(&data), data.len());
    }
}

fn real_log() -> Vec<u8> {
    let compressed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/go-ntfs/LogFile.gz"
    ))
    .unwrap();
    let mut data = Vec::new();
    std::io::Read::read_to_end(
        &mut flate2::read::GzDecoder::new(compressed.as_slice()),
        &mut data,
    )
    .unwrap();
    data
}
