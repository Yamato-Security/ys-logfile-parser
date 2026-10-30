//! Working out, in LSN order, what each update changes (which file record,
//! where, which open attribute) and what its data says about files.

use crate::attributes;
use crate::content::{self, Content, first_attribute_offsets};
use crate::{Body, LogRecord, Operation, Options, SizeSource, Update};

/// The size of a sector, the unit of block offsets and sizes.
const BLOCK: u64 = 512;
/// The cluster size assumed when nothing says otherwise.
const DEFAULT_CLUSTER_SIZE: u32 = 4096;
/// The record size assumed when nothing says otherwise.
const DEFAULT_RECORD_SIZE: u32 = 1024;
/// The largest cluster size NTFS allows.
const MAX_CLUSTER_SIZE: u32 = 2 * 1024 * 1024;

/// The cluster size the updates are read with, and where it came from: the
/// caller, else the latest checkpoint that records it, else the smallest
/// size (4 KiB at least) that holds every file record block offset seen.
pub(crate) fn cluster_size(records: &[LogRecord], options: &Options) -> (u32, SizeSource) {
    if let Some(size) = options.cluster_size.filter(|&size| is_cluster_size(size)) {
        return (size, SizeSource::Caller);
    }
    let recorded = records.iter().rev().find_map(|record| match &record.body {
        Body::Checkpoint(checkpoint) => {
            checkpoint.bytes_per_cluster.filter(|&s| is_cluster_size(s))
        }
        _ => None,
    });
    if let Some(size) = recorded {
        return (size, SizeSource::Checkpoint);
    }
    let reach = records
        .iter()
        .filter_map(LogRecord::update)
        .filter(|update| targets_file_record(update))
        .map(|update| u64::from(update.cluster_block_offset) * BLOCK + record_size(update, options))
        .max()
        .unwrap_or(0);
    let size = reach
        .next_power_of_two()
        .clamp(u64::from(DEFAULT_CLUSTER_SIZE), u64::from(MAX_CLUSTER_SIZE));
    (size as u32, SizeSource::Inferred)
}

fn is_cluster_size(size: u32) -> bool {
    size.is_power_of_two() && (BLOCK as u32..=MAX_CLUSTER_SIZE).contains(&size)
}

/// Fill in every update's targets and content.
pub(crate) fn complete(
    records: &mut [LogRecord],
    cluster_size: u32,
    page_size: u64,
    options: &Options,
) {
    for record in records.iter_mut() {
        let Body::Update(update) = &mut record.body else {
            continue;
        };
        let record_size = record_size(update, options);
        locate(update, u64::from(cluster_size), record_size);
        let redo = decode(update.redo, &update.redo_data, update, record_size);
        let undo = decode(update.undo, &update.undo_data, update, record_size);
        (update.redo_names, update.redo_times) = (redo.names, redo.times);
        (update.undo_names, update.undo_times) = (undo.names, undo.times);
    }
    attributes::resolve(records, page_size);
}

/// The size of the file record (or index buffer) an update changes: what
/// it records, else what the caller says, else 1 KiB.
fn record_size(update: &Update, options: &Options) -> u64 {
    match update.target_block_size {
        0 => u64::from(options.record_size.unwrap_or(DEFAULT_RECORD_SIZE).max(1)),
        blocks => u64::from(blocks) * BLOCK,
    }
}

fn targets_file_record(update: &Update) -> bool {
    update.redo.targets_file_record() || update.undo.targets_file_record()
}

fn targets_nonresident(update: &Update) -> bool {
    update.redo.targets_nonresident() || update.undo.targets_nonresident()
}

/// Which file record an update changes, and where in its target.
fn locate(update: &mut Update, cluster_size: u64, record_size: u64) {
    let within = u64::from(update.attribute_offset) + u64::from(update.record_offset);
    let start = u64::try_from(update.target_vcn)
        .ok()
        .and_then(|vcn| vcn.checked_mul(cluster_size))
        .and_then(|bytes| bytes.checked_add(u64::from(update.cluster_block_offset) * BLOCK));
    if targets_file_record(update) {
        update.mft_record = start.map(|bytes| bytes / record_size);
        update.offset_in_target = Some(within);
    } else if targets_nonresident(update) {
        update.offset_in_target = start.and_then(|bytes| bytes.checked_add(within));
    }
}

/// What data written by `operation` says about files: it has the layout of
/// what that operation writes.
fn decode(operation: Operation, data: &[u8], update: &Update, record_size: u64) -> Content {
    match operation {
        Operation::InitializeFileRecordSegment => content::file_record(data),
        Operation::CreateAttribute => content::attribute(data),
        Operation::AddIndexEntryRoot | Operation::AddIndexEntryAllocation => {
            content::index_entry(data)
        }
        Operation::UpdateResidentValue
            if first_attribute_offsets(record_size).contains(&u64::from(update.record_offset)) =>
        {
            Content {
                names: Vec::new(),
                times: content::resident_times(data, usize::from(update.attribute_offset)),
            }
        }
        _ => Content::default(),
    }
}
