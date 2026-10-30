//! Log records: the header every client's record has, and what the NTFS
//! client puts after it.

use common::bytes::Reader;

use crate::attributes::OpenAttribute;
use crate::content::{FileName, StandardTimes};
use crate::walk::Found;
use crate::Operation;

/// Record types: an update, or a client's restart area (a checkpoint).
const CLIENT_RECORD: u32 = 1;
const CLIENT_RESTART: u32 = 2;
/// The NTFS update header, before its LCNs.
const UPDATE_HEADER: usize = 32;
/// The NTFS restart area's fixed part, and where it records the cluster
/// size, when long enough to.
const CHECKPOINT_HEADER: usize = 64;
const BYTES_PER_CLUSTER_AT: usize = 80;
/// Header flag: the record continues on the next page.
const MULTI_PAGE: u16 = 0x0001;

/// A log record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRecord {
    /// Its log sequence number: where it is in the log, and in which pass
    /// over the circular area it was written.
    pub lsn: u64,
    /// The LSN of the client's previous record in the same transaction; 0
    /// for none.
    pub previous_lsn: u64,
    /// The LSN of the client's next record to undo when rolling back; 0 for
    /// none.
    pub undo_next_lsn: u64,
    /// Byte offset in the log where its header was read: in the circular
    /// area, or in a buffer page holding a copy of the page.
    pub offset: u64,
    /// The client that wrote it.
    pub client: ClientId,
    /// Its transaction: an offset in the transaction table.
    pub transaction_id: u32,
    /// Header flags: see [`LogRecord::spans_pages`]. Other bits are kept as
    /// found.
    pub flags: u16,
    /// What it says.
    pub body: Body,
}

impl LogRecord {
    /// Whether its client data continues in the following pages.
    #[must_use]
    pub fn spans_pages(&self) -> bool {
        self.flags & MULTI_PAGE != 0
    }

    /// The update it records, if it is one.
    #[must_use]
    pub fn update(&self) -> Option<&Update> {
        match &self.body {
            Body::Update(update) => Some(update),
            _ => None,
        }
    }
}

/// Which client wrote a record: an index in the restart area's client
/// records, and that record's sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientId {
    /// The client record's sequence number when the record was written.
    pub sequence: u16,
    /// The client record's index (0 for `NTFS`).
    pub index: u16,
}

/// What a log record says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// A change to the volume, with how to redo and undo it.
    Update(Box<Update>),
    /// The client's restart area: a checkpoint.
    Checkpoint(Checkpoint),
    /// A record of a type NTFS doesn't write, or too short for its type:
    /// its client data as found.
    Other {
        /// The record type.
        record_type: u32,
        /// Its client data.
        data: Vec<u8>,
    },
}

/// An NTFS update record: one change to the volume, with how to redo and
/// undo it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    /// The operation that redoes the change.
    pub redo: Operation,
    /// The operation that undoes it.
    pub undo: Operation,
    /// What the redo operation writes, as far as the record carries it.
    pub redo_data: Vec<u8>,
    /// What the undo operation writes, as far as the record carries it.
    pub undo_data: Vec<u8>,
    /// The redo data's length as the record gives it. Some operations give
    /// a length and no data: `ZeroEndOfFileRecord`'s is how many bytes it
    /// zeroes.
    pub redo_length: u16,
    /// The undo data's length as the record gives it.
    pub undo_length: u16,
    /// The attribute changed: an offset in the open attribute table.
    pub target_attribute: u16,
    /// Offset of the attribute in its file record (or of the entry in its
    /// index buffer).
    pub record_offset: u16,
    /// Offset of the change in the attribute (or entry).
    pub attribute_offset: u16,
    /// Offset of the change in its cluster, in 512-byte blocks.
    pub cluster_block_offset: u16,
    /// Size of the file record or index buffer changed, in 512-byte blocks
    /// (0 for other targets).
    pub target_block_size: u16,
    /// The virtual cluster changed, in the target attribute.
    pub target_vcn: i64,
    /// The logical clusters (on the volume) of the page changed.
    pub lcns: Vec<i64>,
    /// The number of the MFT file record changed, for operations on file
    /// records: the VCN and block offset over the record size.
    pub mft_record: Option<u64>,
    /// Byte offset of the change in its target: in the file record for
    /// operations on file records; in the attribute for the others.
    pub offset_in_target: Option<u64>,
    /// The open attribute changed, for operations on non-resident
    /// attributes, when the log says which it is.
    pub target: Option<OpenAttribute>,
    /// The `$FILE_NAME`s the redo data carries: names a file is given (a
    /// new file record, attribute or directory entry).
    pub redo_names: Vec<FileName>,
    /// The `$FILE_NAME`s the undo data carries: names taken away (a
    /// directory entry or attribute deleted).
    pub undo_names: Vec<FileName>,
    /// The `$STANDARD_INFORMATION` timestamps the redo data writes.
    pub redo_times: Option<StandardTimes>,
    /// The `$STANDARD_INFORMATION` timestamps the undo data writes back:
    /// what they were.
    pub undo_times: Option<StandardTimes>,
}

/// The NTFS client's restart area, written to the log at each checkpoint:
/// where recovery starts, and copies of its tables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// Its major version: 0 up to Windows 7, 1 from Windows 8.
    pub major_version: u32,
    /// Its minor version.
    pub minor_version: u32,
    /// The LSN where the checkpoint starts: where recovery would begin.
    pub start_lsn: u64,
    /// The record holding a copy of the open attribute table.
    pub open_attribute_table: TableDump,
    /// The record holding a copy of the open attributes' names.
    pub attribute_names: TableDump,
    /// The record holding a copy of the dirty page table.
    pub dirty_page_table: TableDump,
    /// The record holding a copy of the transaction table.
    pub transaction_table: TableDump,
    /// The volume's cluster size, when the area is long enough to say.
    pub bytes_per_cluster: Option<u32>,
}

/// Where a checkpoint's copy of a table is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TableDump {
    /// The LSN of the record holding it; 0 for none.
    pub lsn: u64,
    /// Its length in bytes.
    pub length: u32,
}

/// The record `found` is, before its targets and content are worked out.
pub(crate) fn decode(found: Found) -> LogRecord {
    let header = found.header;
    let body = match header.record_type {
        CLIENT_RECORD => update(&found.data).map(|update| Body::Update(Box::new(update))),
        CLIENT_RESTART => checkpoint(&found.data).map(Body::Checkpoint),
        _ => None,
    };
    LogRecord {
        lsn: header.lsn,
        previous_lsn: header.previous_lsn,
        undo_next_lsn: header.undo_next_lsn,
        offset: found.offset,
        client: header.client,
        transaction_id: header.transaction_id,
        flags: header.flags,
        body: body.unwrap_or(Body::Other {
            record_type: header.record_type,
            data: found.data,
        }),
    }
}

/// An update record's client data.
fn update(data: &[u8]) -> Option<Update> {
    if data.len() < UPDATE_HEADER {
        return None;
    }
    let mut r = Reader::new(data);
    let redo = Operation::from_code(r.u16_le().ok()?);
    let undo = Operation::from_code(r.u16_le().ok()?);
    let (redo_offset, redo_length) = (r.u16_le().ok()?, r.u16_le().ok()?);
    let (undo_offset, undo_length) = (r.u16_le().ok()?, r.u16_le().ok()?);
    let target_attribute = r.u16_le().ok()?;
    let lcn_count = usize::from(r.u16_le().ok()?);
    let record_offset = r.u16_le().ok()?;
    let attribute_offset = r.u16_le().ok()?;
    let cluster_block_offset = r.u16_le().ok()?;
    let target_block_size = r.u16_le().ok()?;
    let target_vcn = r.i64_le().ok()?;
    let lcns = (0..lcn_count).map_while(|_| r.i64_le().ok()).collect();
    Some(Update {
        redo,
        undo,
        redo_data: side(data, redo_offset, redo_length),
        undo_data: side(data, undo_offset, undo_length),
        redo_length,
        undo_length,
        target_attribute,
        record_offset,
        attribute_offset,
        cluster_block_offset,
        target_block_size,
        target_vcn,
        lcns,
        mft_record: None,
        offset_in_target: None,
        target: None,
        redo_names: Vec::new(),
        undo_names: Vec::new(),
        redo_times: None,
        undo_times: None,
    })
}

/// Redo or undo data: `length` bytes at `offset` in the client data, as
/// far as they are in it.
fn side(data: &[u8], offset: u16, length: u16) -> Vec<u8> {
    let start = usize::from(offset).min(data.len());
    let end = (usize::from(offset) + usize::from(length)).min(data.len());
    data[start..end].to_vec()
}

/// A checkpoint's client data.
fn checkpoint(data: &[u8]) -> Option<Checkpoint> {
    if data.len() < CHECKPOINT_HEADER {
        return None;
    }
    let mut r = Reader::new(data);
    let major_version = r.u32_le().ok()?;
    let minor_version = r.u32_le().ok()?;
    let start_lsn = r.u64_le().ok()?;
    let mut lsns = [0; 4];
    for lsn in &mut lsns {
        *lsn = r.u64_le().ok()?;
    }
    let mut tables = [TableDump::default(); 4];
    for (table, lsn) in tables.iter_mut().zip(lsns) {
        *table = TableDump {
            lsn,
            length: r.u32_le().ok()?,
        };
    }
    let bytes_per_cluster = r
        .seek(BYTES_PER_CLUSTER_AT)
        .ok()
        .and_then(|()| r.u32_le().ok());
    let [open_attribute_table, attribute_names, dirty_page_table, transaction_table] = tables;
    Some(Checkpoint {
        major_version,
        minor_version,
        start_lsn,
        open_attribute_table,
        attribute_names,
        dirty_page_table,
        transaction_table,
        bytes_per_cluster,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_is_kept_as_far_as_the_record_carries_it() {
        let data = [7_u8; 40];
        assert_eq!(side(&data, 32, 8), [7; 8]);
        assert_eq!(side(&data, 36, 8), [7; 4]);
        assert_eq!(side(&data, 60, 8), []);
        assert_eq!(side(&data, 0, 0), []);
    }
}
