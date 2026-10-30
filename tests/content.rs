//! What go-ntfs's test volume's `$LogFile` says about its files
//! (Apache-2.0, `tests/fixtures/go-ntfs/`), checked against the same
//! volume's `$MFT`: the names new file records carry are in those records,
//! the timestamps decoded from `$STANDARD_INFORMATION` updates land on that
//! attribute, and the last ones written are what the MFT holds. And
//! dfVFS's volume, whose log was never written.

use std::collections::BTreeMap;
use std::io::Read;

use common::time::Ts;
use ntfslog::{parse, LogFile, Operation, Update};

const RECORD: usize = 1024;

fn gunzip(path: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{path}", env!("CARGO_MANIFEST_DIR"));
    let compressed = std::fs::read(path).unwrap();
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}

fn log() -> LogFile {
    parse(&gunzip("go-ntfs/LogFile.gz"))
}

fn updates(log: &LogFile) -> impl Iterator<Item = &Update> {
    log.records.iter().filter_map(|record| record.update())
}

/// MFT record `number`, its update sequence array applied.
fn mft_record(mft: &[u8], number: u64) -> Vec<u8> {
    let start = usize::try_from(number).unwrap() * RECORD;
    let mut record = mft[start..start + RECORD].to_vec();
    let array = usize::from(u16::from_le_bytes([record[4], record[5]]));
    for sector in 0..RECORD / 512 {
        let last = (sector + 1) * 512 - 2;
        let saved = array + 2 + 2 * sector;
        record.copy_within(saved..saved + 2, last);
    }
    record
}

/// The `$STANDARD_INFORMATION` timestamps of an MFT record.
fn mft_times(record: &[u8]) -> [Ts; 4] {
    let first = usize::from(u16::from_le_bytes([record[0x14], record[0x15]]));
    assert_eq!(record[first..first + 4], 0x10_u32.to_le_bytes());
    let value = first + usize::from(u16::from_le_bytes([record[first + 20], record[first + 21]]));
    std::array::from_fn(|i| {
        let at = value + 8 * i;
        Ts::from_filetime(u64::from_le_bytes(record[at..at + 8].try_into().unwrap()))
    })
}

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[test]
fn the_restart_area() {
    let log = log();
    let restart = log.restart().unwrap();
    assert_eq!(restart.version.to_string(), "1.1");
    assert_eq!(restart.area.current_lsn, 1_574_933);
    assert_eq!(restart.area.sequence_number_bits, 45);
    assert_eq!(restart.area.file_size, 2 * 1024 * 1024);
    assert!(restart.area.is_clean());
    assert_eq!(restart.area.clients[0].name, "NTFS");
    assert_eq!(restart.area.clients[0].restart_lsn, 1_574_933);
    assert_eq!(log.cluster_size, 1024);
    assert!(log.problems.is_empty());
}

#[test]
fn files_created_renamed_and_deleted() {
    let log = log();
    let created: Vec<&str> = updates(&log)
        .filter(|update| update.redo == Operation::InitializeFileRecordSegment)
        .flat_map(|update| &update.redo_names)
        .map(|name| name.name.as_str())
        .collect();
    for name in [
        "deleted.bin",
        "ones.bin",
        "New folder",
        "New Text Document.txt",
    ] {
        assert!(created.contains(&name), "{name}");
    }
    // Directory entries taken away: the undo data of their deletions.
    let removed: Vec<String> = updates(&log)
        .filter(|update| update.redo == Operation::DeleteIndexEntryAllocation)
        .flat_map(|update| &update.undo_names)
        .map(|name| format!("{} in {}", name.name, name.parent))
        .collect();
    assert_eq!(
        removed,
        ["$Quota in 5-5", "New folder in 5-5", "deleted.bin in 5-5"]
    );
    // Renames: one $FILE_NAME attribute deleted, another created.
    let renamed: Vec<(String, String)> = updates(&log)
        .filter(|update| update.redo == Operation::DeleteAttribute)
        .filter_map(|update| {
            let old = update.undo_names.first()?;
            let new = updates(&log)
                .filter(|other| other.redo == Operation::CreateAttribute)
                .filter(|other| other.mft_record == update.mft_record)
                .flat_map(|other| &other.redo_names)
                .find(|new| new.name != old.name)?;
            Some((old.name.clone(), new.name.clone()))
        })
        .collect();
    assert!(renamed.contains(&("New folder".to_owned(), "Folder A".to_owned())));
    assert!(renamed.contains(&(
        "New Text Document.txt".to_owned(),
        "Hello world text document.txt".to_owned()
    )));
}

#[test]
fn new_file_records_are_the_mft_records_they_name() {
    let (log, mft) = (log(), gunzip("go-ntfs/MFT.gz"));
    // Names taken away since, by a rename ($Quota became $Secure).
    let renamed: Vec<(Option<u64>, &str)> = updates(&log)
        .filter(|update| update.redo == Operation::DeleteAttribute)
        .flat_map(|update| {
            update
                .undo_names
                .iter()
                .map(|n| (update.mft_record, n.name.as_str()))
        })
        .collect();
    let mut checked = 0;
    for update in updates(&log).filter(|u| u.redo == Operation::InitializeFileRecordSegment) {
        let number = update.mft_record.unwrap();
        for name in &update.redo_names {
            if renamed.contains(&(Some(number), name.name.as_str())) {
                continue;
            }
            assert_eq!(name.file.unwrap().entry(), number);
            let record = mft_record(&mft, number);
            let utf16 = utf16(&name.name);
            assert!(
                record.windows(utf16.len()).any(|w| w == utf16),
                "{}",
                name.name
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 26);
}

#[test]
fn standard_information_timestamps_land_on_it_and_end_as_the_mft_holds_them() {
    let (log, mft) = (log(), gunzip("go-ntfs/MFT.gz"));
    let mut last: BTreeMap<u64, [Option<Ts>; 4]> = BTreeMap::new();
    for update in updates(&log) {
        let Some(times) = update.redo_times else {
            continue;
        };
        let number = update.mft_record.unwrap();
        // The record's first attribute is $STANDARD_INFORMATION.
        let _ = mft_times(&mft_record(&mft, number));
        let fields = last.entry(number).or_default();
        for (field, time) in
            fields
                .iter_mut()
                .zip([times.created, times.modified, times.changed, times.accessed])
        {
            *field = time.or(*field);
        }
    }
    assert_eq!(last.len(), 31);
    for (number, times) in last {
        let in_mft = mft_times(&mft_record(&mft, number));
        for (logged, current) in times.iter().zip(in_mft) {
            if let Some(logged) = logged {
                assert_eq!(*logged, current, "record {number}");
            }
        }
    }
}

#[test]
fn a_log_never_written() {
    let log = parse(&gunzip("dfvfs/LogFile.gz"));
    assert!(log.is_unused());
}
