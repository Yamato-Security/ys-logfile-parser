//! Finding records: every header whose LSN names its own position, and its
//! client data, following the pages.
//!
//! An LSN is its record's offset in the log, with the pass over the
//! circular area in its high bits. Eight bytes that, read as an LSN, name
//! the very place they are read from are a record header: nothing else in
//! a log does that by chance. So every page is searched, 8 bytes at a time,
//! from its data offset; each record found is stepped over whole. This
//! reads records whatever page versions survive, without relying on one
//! record leading to the next.
//!
//! A record's client data continues, when longer than the rest of its
//! page, in the following pages from their data offset, wrapping from the
//! end of the circular area to its start. A continuation must come from a
//! page version written after the record, in the same pass (the next one
//! across the wrap); the record is cut short where none is.

use std::collections::BTreeMap;

use crate::bytes::Reader;

use crate::layout::Layout;
use crate::pages::{Page, Pages};
use crate::record::ClientId;
use crate::{Problem, ProblemKind};

/// A record's header and client data, as found.
#[derive(Debug, Clone)]
pub(crate) struct Found {
    /// Byte offset of its header in the log.
    pub(crate) offset: u64,
    pub(crate) header: Header,
    /// Its client data, short when it is cut short.
    pub(crate) data: Vec<u8>,
}

/// A log record header.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Header {
    pub(crate) lsn: u64,
    pub(crate) previous_lsn: u64,
    pub(crate) undo_next_lsn: u64,
    pub(crate) data_length: u32,
    pub(crate) client: ClientId,
    pub(crate) record_type: u32,
    pub(crate) transaction_id: u32,
    pub(crate) flags: u16,
}

/// Every record in `pages`, in LSN order. A record found in more than one
/// version of a page is taken from the first.
pub(crate) fn find(pages: &Pages, layout: &Layout, problems: &mut Vec<Problem>) -> Vec<Found> {
    let mut found = BTreeMap::new();
    for page in pages.all() {
        let mut at = layout.data_offset;
        while at + layout.header_length <= layout.page_size {
            let Some(header) = header_at(page, at, layout) else {
                at += 8;
                continue;
            };
            let start = at + layout.header_length;
            let end = start.saturating_add(header.data_length as usize);
            found.entry(header.lsn).or_insert_with(|| {
                let offset = page.offset + at as u64;
                let data = client_data(pages, page, start, &header, layout);
                let missing = u64::from(header.data_length) - data.len() as u64;
                if missing > 0 {
                    let lsn = header.lsn;
                    let kind = ProblemKind::RecordCutShort { lsn, missing };
                    problems.push(Problem { offset, kind });
                }
                Found {
                    offset,
                    header,
                    data,
                }
            });
            if end > layout.page_size {
                break;
            }
            at = end.next_multiple_of(8);
        }
    }
    found.into_values().collect()
}

/// The record header at `at` in `page`, if there is one: its LSN names
/// this position, and its client data could fit in the log.
fn header_at(page: &Page, at: usize, layout: &Layout) -> Option<Header> {
    let mut r = Reader::new(page.bytes.get(at..at + layout.header_length)?);
    let lsn = r.u64_le().ok()?;
    let position = layout.page_offset(page.location) + at as u64;
    if lsn == 0 || layout.offset_of(lsn) != position {
        return None;
    }
    let header = Header {
        lsn,
        previous_lsn: r.u64_le().ok()?,
        undo_next_lsn: r.u64_le().ok()?,
        data_length: r.u32_le().ok()?,
        client: ClientId {
            sequence: r.u16_le().ok()?,
            index: r.u16_le().ok()?,
        },
        record_type: r.u32_le().ok()?,
        transaction_id: r.u32_le().ok()?,
        flags: r.u16_le().ok()?,
    };
    (u64::from(header.data_length) <= layout.max_client_data()).then_some(header)
}

/// The client data of the record whose header is in `first`, starting at
/// `start`: there, then in the following pages.
fn client_data(
    pages: &Pages,
    first: &Page,
    start: usize,
    header: &Header,
    layout: &Layout,
) -> Vec<u8> {
    let length = header.data_length as usize;
    let here = (layout.page_size - start).min(length);
    let mut data = first.bytes[start..start + here].to_vec();
    let mut location = first.location;
    let mut pass = layout.sequence_of(header.lsn);
    while data.len() < length {
        let (next, wrapped) = layout.next_page(location);
        pass = pass.saturating_add(u64::from(wrapped));
        let Some(page) = continuation(pages.at(next), header.lsn, pass, layout) else {
            break;
        };
        let take = (length - data.len()).min(layout.page_size - layout.data_offset);
        data.extend_from_slice(&page.bytes[layout.data_offset..layout.data_offset + take]);
        location = next;
    }
    data
}

/// The version of a page that continues the record `lsn`, written in
/// `pass`: one written after it, and in that pass (the latest such).
fn continuation<'a>(
    versions: &'a [Page],
    lsn: u64,
    pass: u64,
    layout: &Layout,
) -> Option<&'a Page> {
    versions
        .iter()
        .filter(|page| page.newest_lsn >= lsn && layout.sequence_of(page.newest_lsn) <= pass)
        .max_by_key(|page| page.newest_lsn)
}
