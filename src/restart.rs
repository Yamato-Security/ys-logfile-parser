//! Restart pages (`RSTR`): the two copies, at the start of the log, of
//! where it stands and how it is laid out.

use core::fmt;

use common::bytes::Reader;
use common::text::utf16le;

use crate::fixup::unprotect;
use crate::layout::{MAX_PAGE_SIZE, MIN_PAGE_SIZE};
use crate::{Problem, ProblemKind};

/// A restart page's signature; `CHKD` once chkdsk has modified the log.
const RESTART: &[u8; 4] = b"RSTR";
const CHECKED: &[u8; 4] = b"CHKD";
/// Where the second copy is when the first doesn't say.
const DEFAULT_SYSTEM_PAGE_SIZE: usize = 4096;
/// Where a restart page's own size is.
const SYSTEM_PAGE_SIZE_AT: usize = 16;
/// The restart area starts after the page header and its array.
const MIN_RESTART_OFFSET: usize = 0x20;
/// The restart area's fixed part.
const AREA_HEADER: usize = 44;
/// A client record's allocated size, and the most its name takes.
const CLIENT_RECORD: usize = 160;
const CLIENT_NAME_AT: usize = 32;
const MAX_CLIENT_NAME: usize = CLIENT_RECORD - CLIENT_NAME_AT;
/// No client: the end of a list.
const NO_CLIENT: u16 = 0xFFFF;
/// Restart area flags.
const SINGLE_PAGE_IO: u16 = 0x0001;
const CLEAN: u16 = 0x0002;

/// A restart page: one of the two copies at the start of the log of where
/// it stands. Windows writes them in turn; the one with the higher current
/// LSN is the latest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartPage {
    /// Byte offset of the page in the log: 0 for the first copy, one
    /// system page in for the second.
    pub offset: u64,
    /// Whether chkdsk has modified the log (signature `CHKD`, not `RSTR`).
    pub chkdsk: bool,
    /// The last LSN chkdsk found, when it has run.
    pub chkdsk_lsn: u64,
    /// The size of a restart page.
    pub system_page_size: u32,
    /// The size of a log record page.
    pub log_page_size: u32,
    /// The log's format version: 1.1 up to Windows 7, 2.0 from Windows 8.
    pub version: Version,
    /// What the page says about the log.
    pub area: RestartArea,
}

/// A log format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Version {
    /// 1 or 2.
    pub major: i16,
    /// 1 for version 1.1, else 0.
    pub minor: i16,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// A restart area: the log's settings and its clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartArea {
    /// The LSN of the last record written when the area was.
    pub current_lsn: u64,
    /// How many client records there are, used or free.
    pub log_clients: u16,
    /// The first free client record, if any.
    pub client_free_list: Option<u16>,
    /// The first client record in use, if any.
    pub client_in_use_list: Option<u16>,
    /// Flags: see [`RestartArea::is_clean`] and
    /// [`RestartArea::single_page_io`].
    pub flags: u16,
    /// How many of an LSN's 64 bits hold its sequence number (the pass over
    /// the circular area); the rest hold the file offset in 8-byte units.
    pub sequence_number_bits: u32,
    /// The area's length in bytes, client records included.
    pub length: u16,
    /// Offset of the client records from the start of the area.
    pub client_array_offset: u16,
    /// The size of the log file.
    pub file_size: u64,
    /// Client data length of the last record written.
    pub last_lsn_data_length: u32,
    /// Length of a log record header (48).
    pub record_header_length: u16,
    /// Offset of the first record in a log record page.
    pub log_page_data_offset: u16,
    /// Incremented each time the area is written.
    pub revision: u32,
    /// The client records: `NTFS` is the only one Windows uses.
    pub clients: Vec<Client>,
}

impl RestartArea {
    /// Whether the volume was cleanly dismounted: nothing in the log is
    /// waiting to be redone or undone.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.flags & CLEAN != 0
    }

    /// Whether the log writes one page per I/O.
    #[must_use]
    pub fn single_page_io(&self) -> bool {
        self.flags & SINGLE_PAGE_IO != 0
    }
}

/// A client of the log: a component writing records to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    /// Its name: `NTFS`.
    pub name: String,
    /// The oldest LSN it still needs.
    pub oldest_lsn: u64,
    /// The LSN of its latest restart record (its checkpoint).
    pub restart_lsn: u64,
    /// The previous client record in its list, if any.
    pub previous: Option<u16>,
    /// The next client record in its list, if any.
    pub next: Option<u16>,
    /// Incremented each time the client record is reused; part of each of
    /// its records' client identifier.
    pub sequence_number: u16,
}

/// Read both restart pages. A copy that can't be read is a problem; one
/// never written (all `0xFF`, as a new log is) is not.
pub(crate) fn read(data: &[u8], problems: &mut Vec<Problem>) -> Vec<RestartPage> {
    let second = declared_page_size(data).unwrap_or(DEFAULT_SYSTEM_PAGE_SIZE);
    let mut pages = Vec::new();
    for offset in [0, second] {
        let Some(head) = data.get(offset..) else {
            continue;
        };
        if head
            .iter()
            .take(DEFAULT_SYSTEM_PAGE_SIZE)
            .all(|&b| b == 0xFF)
        {
            continue;
        }
        match RestartPage::read(head, offset as u64) {
            Some(page) => pages.push(page),
            None => problems.push(Problem {
                offset: offset as u64,
                kind: ProblemKind::BadRestartPage,
            }),
        }
    }
    pages
}

/// The size the first restart page gives itself, when plausible.
fn declared_page_size(data: &[u8]) -> Option<usize> {
    let mut r = Reader::new(data);
    r.seek(SYSTEM_PAGE_SIZE_AT).ok()?;
    let size = usize::try_from(r.u32_le().ok()?).ok()?;
    is_page_size(size).then_some(size)
}

fn is_page_size(size: usize) -> bool {
    size.is_power_of_two() && (MIN_PAGE_SIZE..=MAX_PAGE_SIZE).contains(&size)
}

impl RestartPage {
    /// The restart page at the start of `data`, at `offset` in the log.
    fn read(data: &[u8], offset: u64) -> Option<Self> {
        let signature = data.get(..4)?;
        if signature != RESTART && signature != CHECKED {
            return None;
        }
        let mut r = Reader::new(data);
        r.seek(8).ok()?;
        let chkdsk_lsn = r.u64_le().ok()?;
        let system_page_size = r.u32_le().ok()?;
        let log_page_size = r.u32_le().ok()?;
        let restart_offset = usize::from(r.u16_le().ok()?);
        let minor = r.i16_le().ok()?;
        let major = r.i16_le().ok()?;
        let size = usize::try_from(system_page_size).ok()?;
        if !is_page_size(size) || !is_page_size(usize::try_from(log_page_size).ok()?) {
            return None;
        }
        let mut page = data.get(..size)?.to_vec();
        let array_end = unprotect(&mut page).ok()?;
        if restart_offset < MIN_RESTART_OFFSET.max(array_end) || restart_offset % 8 != 0 {
            return None;
        }
        Some(Self {
            offset,
            chkdsk: signature == CHECKED,
            chkdsk_lsn,
            system_page_size,
            log_page_size,
            version: Version { major, minor },
            area: RestartArea::read(page.get(restart_offset..)?)?,
        })
    }
}

impl RestartArea {
    /// The restart area at the start of `area` (the rest of its page).
    fn read(area: &[u8]) -> Option<Self> {
        let mut r = Reader::new(area);
        let current_lsn = r.u64_le().ok()?;
        let log_clients = r.u16_le().ok()?;
        let client_free_list = client_index(r.u16_le().ok()?);
        let client_in_use_list = client_index(r.u16_le().ok()?);
        let flags = r.u16_le().ok()?;
        let sequence_number_bits = r.u32_le().ok()?;
        let length = r.u16_le().ok()?;
        let client_array_offset = r.u16_le().ok()?;
        let file_size = r.u64_le().ok()?;
        let last_lsn_data_length = r.u32_le().ok()?;
        let record_header_length = r.u16_le().ok()?;
        let log_page_data_offset = r.u16_le().ok()?;
        let revision = r.u32_le().ok()?;
        let array = usize::from(client_array_offset);
        if array < AREA_HEADER || array % 8 != 0 {
            return None;
        }
        let clients = area
            .get(array..)?
            .chunks(CLIENT_RECORD)
            .take(usize::from(log_clients))
            .map(Client::read)
            .collect::<Option<Vec<_>>>()?;
        (clients.len() == usize::from(log_clients)).then_some(Self {
            current_lsn,
            log_clients,
            client_free_list,
            client_in_use_list,
            flags,
            sequence_number_bits,
            length,
            client_array_offset,
            file_size,
            last_lsn_data_length,
            record_header_length,
            log_page_data_offset,
            revision,
            clients,
        })
    }
}

impl Client {
    /// A client record: `record` is its allocated 160 bytes, or what's
    /// left of the page.
    fn read(record: &[u8]) -> Option<Self> {
        let mut r = Reader::new(record);
        let oldest_lsn = r.u64_le().ok()?;
        let restart_lsn = r.u64_le().ok()?;
        let previous = client_index(r.u16_le().ok()?);
        let next = client_index(r.u16_le().ok()?);
        let sequence_number = r.u16_le().ok()?;
        r.seek(CLIENT_NAME_AT - 4).ok()?;
        let name_length = usize::try_from(r.u32_le().ok()?).ok()?;
        if name_length > MAX_CLIENT_NAME {
            return None;
        }
        Some(Self {
            name: utf16le(r.bytes(name_length).ok()?).text,
            oldest_lsn,
            restart_lsn,
            previous,
            next,
            sequence_number,
        })
    }
}

/// A client record index, `None` for the end of a list.
fn client_index(index: u16) -> Option<u16> {
    (index != NO_CLIENT).then_some(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unused_restart_pages_are_not_problems() {
        let mut problems = Vec::new();
        assert!(read(&[0xFF; 8192], &mut problems).is_empty());
        assert!(problems.is_empty());
        assert!(read(&[0; 8192], &mut problems).is_empty());
        assert_eq!(
            problems.iter().map(|p| p.offset).collect::<Vec<_>>(),
            [0, 4096]
        );
    }

    #[test]
    fn short_data_never_panics() {
        let mut problems = Vec::new();
        for length in 0..40 {
            let mut data = b"RSTR".to_vec();
            data.resize(length.max(4), 0);
            let _ = read(&data, &mut problems);
        }
    }
}
