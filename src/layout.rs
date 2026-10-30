//! The geometry of a log: page sizes, where the circular area is, and the
//! arithmetic between log sequence numbers and file offsets.

use crate::restart::RestartPage;

/// Restart pages, then buffer pages, then the circular area.
const RESTART_PAGES: u64 = 2;
/// Version 1.x keeps two tail copies of the last page written.
const TAIL_PAGES: u64 = 2;
/// Version 2.0 and later keep 32 fast copies of the last pages written.
const FAST_PAGES: u64 = 32;
/// The usual page size, assumed when no restart page can be read.
const DEFAULT_PAGE_SIZE: usize = 4096;
/// The usual log record header length.
const DEFAULT_HEADER_LENGTH: usize = 48;
/// The usual offset of the first record in a log record page.
const DEFAULT_DATA_OFFSET: usize = 64;
/// A sequence number takes at least this many bits of an LSN, so that an
/// offset (in 8-byte units) can never overflow its share.
const MIN_SEQUENCE_BITS: u32 = 3;
/// A log record page's header, before its update sequence array: records
/// start after it.
const PAGE_HEADER: usize = 40;
/// The largest page size accepted.
pub(crate) const MAX_PAGE_SIZE: usize = 64 * 1024;
/// The smallest page size accepted: one sector.
pub(crate) const MIN_PAGE_SIZE: usize = 512;

/// What reading pages and records needs to know about a log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Layout {
    /// Size of a log record page.
    pub(crate) page_size: usize,
    /// Bits of an LSN holding the sequence number (the pass over the
    /// circular area); the rest hold the file offset in 8-byte units.
    pub(crate) sequence_bits: u32,
    /// Pages in the log: the circular area ends, and wraps, here.
    pub(crate) page_count: u64,
    /// The first page of the circular area.
    pub(crate) first_circular: u64,
    /// Whether the buffer pages store their target's offset as version 1.x
    /// tail pages do (a 64-bit offset at byte 8) rather than as version 2.0
    /// fast pages do (a 32-bit offset at byte 60).
    pub(crate) tail_buffers: bool,
    /// Length of a log record header.
    pub(crate) header_length: usize,
    /// Offset of the first record (or continuation) in a log record page.
    pub(crate) data_offset: usize,
}

impl Layout {
    /// The layout a restart page describes, for a log of `length` bytes.
    /// `None` when its values can't describe a log.
    pub(crate) fn from_restart(page: &RestartPage, length: usize) -> Option<Self> {
        let area = &page.area;
        let page_size = usize::try_from(page.log_page_size).ok()?;
        let tail_buffers = page.version.major < 2;
        let layout = Self {
            page_size,
            sequence_bits: area.sequence_number_bits,
            page_count: page_count(area.file_size, length, page_size),
            first_circular: first_circular(tail_buffers),
            tail_buffers,
            header_length: usize::from(area.record_header_length),
            data_offset: usize::from(area.log_page_data_offset),
        };
        layout.is_sound().then_some(layout)
    }

    /// The usual layout of a log of `length` bytes, for when no restart page
    /// can be read: 4 KiB pages, version 2.0, and as many sequence number
    /// bits as Windows gives a log of that size.
    pub(crate) fn assumed(length: usize) -> Self {
        let file_size = length as u64;
        Self {
            page_size: DEFAULT_PAGE_SIZE,
            sequence_bits: sequence_bits_for(file_size),
            page_count: page_count(file_size, length, DEFAULT_PAGE_SIZE),
            first_circular: first_circular(false),
            tail_buffers: false,
            header_length: DEFAULT_HEADER_LENGTH,
            data_offset: DEFAULT_DATA_OFFSET,
        }
    }

    /// Whether the values can describe a log: the arithmetic below relies
    /// on it.
    fn is_sound(&self) -> bool {
        self.page_size.is_power_of_two()
            && (MIN_PAGE_SIZE..=MAX_PAGE_SIZE).contains(&self.page_size)
            && (MIN_SEQUENCE_BITS..u64::BITS).contains(&self.sequence_bits)
            && self.header_length >= DEFAULT_HEADER_LENGTH
            && self.header_length.is_multiple_of(8)
            && self.data_offset >= PAGE_HEADER
            && self.data_offset.is_multiple_of(8)
            && self.data_offset.saturating_add(self.header_length) <= self.page_size
    }

    /// The byte offset in the file an LSN points to.
    pub(crate) fn offset_of(&self, lsn: u64) -> u64 {
        (lsn << self.sequence_bits) >> (self.sequence_bits - MIN_SEQUENCE_BITS)
    }

    /// The sequence number of an LSN: which pass over the circular area
    /// wrote it.
    pub(crate) fn sequence_of(&self, lsn: u64) -> u64 {
        lsn >> (u64::BITS - self.sequence_bits)
    }

    /// The page after `page` in the circular area, and whether reaching it
    /// wraps around to the start (which starts a new pass).
    pub(crate) fn next_page(&self, page: u64) -> (u64, bool) {
        match page.checked_add(1) {
            Some(next) if next < self.page_count => (next, false),
            _ => (self.first_circular, true),
        }
    }

    /// The pages holding copies of the last pages written.
    pub(crate) fn is_buffer_page(&self, page: u64) -> bool {
        (RESTART_PAGES..self.first_circular).contains(&page)
    }

    /// Whether `page` is in the circular area.
    pub(crate) fn is_circular(&self, page: u64) -> bool {
        (self.first_circular..self.page_count).contains(&page)
    }

    /// The most client data one record can carry: all of the circular
    /// area. Longer claims are damage.
    pub(crate) fn max_client_data(&self) -> u64 {
        let pages = self.page_count.saturating_sub(self.first_circular);
        pages.saturating_mul((self.page_size - self.data_offset) as u64)
    }

    /// The byte offset of `page`.
    pub(crate) fn page_offset(&self, page: u64) -> u64 {
        page.saturating_mul(self.page_size as u64)
    }
}

/// The first page of the circular area.
fn first_circular(tail_buffers: bool) -> u64 {
    RESTART_PAGES + if tail_buffers { TAIL_PAGES } else { FAST_PAGES }
}

/// How many pages the circular area spans: up to the size the restart area
/// declares, so that a log cut short never wraps early; the data's own
/// length when the declared size is no use.
fn page_count(declared: u64, length: usize, page_size: usize) -> u64 {
    let page_size = page_size as u64;
    let usable = |size: u64| size / page_size > RESTART_PAGES + FAST_PAGES;
    let size = if usable(declared) {
        declared
    } else {
        length as u64
    };
    size / page_size
}

/// The sequence number bits Windows gives a log of `file_size` bytes: what
/// is left once the offset, in 8-byte units, has the bits it needs.
pub(crate) fn sequence_bits_for(file_size: u64) -> u32 {
    let offset_bits = file_size.bit_width().max(MIN_SEQUENCE_BITS + 1);
    u64::BITS + MIN_SEQUENCE_BITS - offset_bits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout(sequence_bits: u32) -> Layout {
        Layout {
            sequence_bits,
            page_count: 100,
            ..Layout::assumed(400 * 1024)
        }
    }

    #[test]
    fn lsn_arithmetic() {
        // 43 sequence bits leave 21 bits of offset in 8-byte units.
        let layout = layout(43);
        let lsn = 4 << 21 | 0x6158;
        assert_eq!(layout.offset_of(lsn), 0x6158 * 8);
        assert_eq!(layout.sequence_of(lsn), 4);
    }

    #[test]
    fn sequence_bits_follow_the_file_size() {
        assert_eq!(sequence_bits_for(0x20_0000), 45);
        assert_eq!(sequence_bits_for(0x8a_0000), 43);
        assert_eq!(sequence_bits_for(64 * 1024 * 1024), 40);
        assert_eq!(sequence_bits_for(0), 63);
    }

    #[test]
    fn the_circular_area_wraps() {
        let layout = layout(43);
        assert_eq!(layout.next_page(50), (51, false));
        assert_eq!(layout.next_page(99), (34, true));
        assert_eq!(layout.next_page(u64::MAX), (34, true));
        assert!(layout.is_buffer_page(2) && layout.is_buffer_page(33));
        assert!(!layout.is_buffer_page(34) && layout.is_circular(34));
    }

    #[test]
    fn a_short_log_wraps_at_its_declared_size() {
        assert_eq!(page_count(9_043_968, 212_992, 4096), 2208);
        assert_eq!(page_count(0, 212_992, 4096), 52);
    }
}
