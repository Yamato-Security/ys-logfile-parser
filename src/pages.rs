//! Log record pages (`RCRD`): the circular area, and the buffer pages that
//! hold copies of the last pages written.
//!
//! A page in the circular area can have more than one version: its own,
//! and copies in buffer pages. A copy can be newer (the last page written,
//! not yet written in place, or written in place before a crash) or older
//! (a copy from an earlier pass, its target since overwritten). Every
//! version is kept: each can hold records the others don't.

use std::collections::BTreeMap;

use crate::bytes::Reader;

use crate::fixup::unprotect;
use crate::layout::Layout;
use crate::{Problem, ProblemKind};

/// A log record page's signature; `CHKD` once chkdsk has modified it,
/// `BAAD` when Windows found its update sequence array wrong (the page is
/// still read when the array now checks out).
const SIGNATURES: [&[u8; 4]; 3] = [b"RCRD", b"CHKD", b"BAAD"];
/// Where a version 2.0 fast page keeps its target's offset.
const FAST_TARGET_AT: usize = 60;

/// One version of a page of the circular area, its update sequence array
/// applied.
#[derive(Debug, Clone)]
pub(crate) struct Page {
    /// Which page of the circular area it is a version of.
    pub(crate) location: u64,
    /// Byte offset in the log where this version was read.
    pub(crate) offset: u64,
    /// The page.
    pub(crate) bytes: Vec<u8>,
    /// The highest LSN the page's header records: when it was written.
    pub(crate) newest_lsn: u64,
}

/// Every version of every page of the circular area that can be read.
#[derive(Debug, Default)]
pub(crate) struct Pages {
    /// By location; the page's own version first, then buffer copies.
    versions: BTreeMap<u64, Vec<Page>>,
}

impl Pages {
    /// Read every log record page after the restart pages.
    pub(crate) fn read(data: &[u8], layout: &Layout, problems: &mut Vec<Problem>) -> Self {
        let mut pages = Self::default();
        let mut buffers = Vec::new();
        let chunks = data.chunks(layout.page_size).enumerate().skip(2);
        for (index, raw) in chunks {
            let index = index as u64;
            let offset = layout.page_offset(index);
            let Some(page) = read_page(raw, offset, layout, problems) else {
                continue;
            };
            if layout.is_buffer_page(index) {
                buffers.push(page);
            } else if layout.is_circular(index) {
                let newest_lsn = page.newest_lsn(false);
                pages.add(index, page, newest_lsn);
            }
        }
        for page in buffers {
            let newest_lsn = page.newest_lsn(layout.tail_buffers);
            if let Some(location) = page.target(layout) {
                pages.add(location, page, newest_lsn);
            }
        }
        pages
    }

    fn add(&mut self, location: u64, page: Raw, newest_lsn: u64) {
        self.versions.entry(location).or_default().push(Page {
            location,
            offset: page.offset,
            bytes: page.bytes,
            newest_lsn,
        });
    }

    /// Every version of every page, in page order.
    pub(crate) fn all(&self) -> impl Iterator<Item = &Page> {
        self.versions.values().flatten()
    }

    /// The versions of the page at `location`.
    pub(crate) fn at(&self, location: u64) -> &[Page] {
        self.versions.get(&location).map_or(&[], Vec::as_slice)
    }
}

/// A log record page as read, before it is placed.
struct Raw {
    offset: u64,
    bytes: Vec<u8>,
    /// The highest LSN in the page; for a version 1.x tail page, its
    /// target's offset instead.
    last_lsn: u64,
    /// The LSN of the last record ending in the page.
    last_end_lsn: u64,
    /// Where its update sequence array ends.
    array_end: usize,
}

impl Raw {
    /// The highest LSN the header records. A tail page's last LSN field
    /// holds its target's offset, so only its last end LSN counts.
    fn newest_lsn(&self, tail_page: bool) -> u64 {
        if tail_page {
            self.last_end_lsn
        } else {
            self.last_lsn.max(self.last_end_lsn)
        }
    }

    /// Where a buffer page's copy belongs: the offset it records, or else
    /// where its last record is.
    fn target(&self, layout: &Layout) -> Option<u64> {
        let recorded = if layout.tail_buffers {
            Some(self.last_lsn)
        } else if self.array_end <= FAST_TARGET_AT {
            let mut r = Reader::new(&self.bytes);
            r.seek(FAST_TARGET_AT).ok()?;
            r.u32_le().ok().map(u64::from)
        } else {
            None
        };
        let page_size = layout.page_size as u64;
        recorded
            .filter(|offset| offset % page_size == 0)
            .map(|offset| offset / page_size)
            .filter(|&location| layout.is_circular(location))
            .or_else(|| {
                let location = layout.offset_of(self.last_end_lsn) / page_size;
                layout.is_circular(location).then_some(location)
            })
    }
}

/// Read the log record page `raw`, at `offset`. `None` for a page never
/// written, and for one that can't be read (a problem).
fn read_page(raw: &[u8], offset: u64, layout: &Layout, problems: &mut Vec<Problem>) -> Option<Raw> {
    if raw.iter().all(|&b| b == 0xFF) || raw.iter().all(|&b| b == 0) {
        return None;
    }
    let mut problem = |kind| {
        problems.push(Problem { offset, kind });
        None
    };
    if raw.len() < layout.page_size {
        return problem(ProblemKind::PartialPage);
    }
    if !SIGNATURES
        .iter()
        .any(|signature| raw.get(..4) == Some(&signature[..]))
    {
        return problem(ProblemKind::UnknownPage);
    }
    let mut bytes = raw.to_vec();
    let array_end = match unprotect(&mut bytes) {
        Ok(end) => end,
        Err(fixup) => {
            problems.push(Problem::page(offset, fixup));
            return None;
        }
    };
    let mut r = Reader::new(&bytes);
    r.seek(8).ok()?;
    let last_lsn = r.u64_le().ok()?;
    r.seek(32).ok()?;
    let last_end_lsn = r.u64_le().ok()?;
    Some(Raw {
        offset,
        bytes,
        last_lsn,
        last_end_lsn,
        array_end,
    })
}
