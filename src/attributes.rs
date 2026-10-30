//! The open attribute table: which file and attribute each update changes.
//!
//! Updates name their target by an offset in this table. The log rebuilds
//! it: an `OpenNonresidentAttribute` record adds an entry (its redo data)
//! with its attribute's name (its undo data, from Windows 8), and each
//! checkpoint writes a copy of the whole table (`OpenAttributeTableDump`)
//! and of the names (`AttributeNamesDump`).
//!
//! An entry has one of two layouts, told apart by their sizes: 44 bytes
//! (checkpoint version 0, up to Windows 7) or 40 bytes (version 1).
//!
//! An update uses the newest definition of its table offset at or before
//! its LSN, else the oldest one after it: an attribute opened before the
//! oldest record that survives. Both only within a stretch of the log in
//! which the table carries over: a checkpoint without tables (a mount or a
//! clean dismount) starts a new table, and so does a gap of more than
//! [`GAP_PAGES`] pages between records (records left from an earlier pass,
//! or lost pages), across which it may have changed unseen. An update with
//! no definition in its stretch takes the nearest one elsewhere, marked as
//! inferred.

use std::collections::BTreeMap;

use crate::bytes::Reader;
use crate::content::Reference;
use crate::text::utf16le_until_nul;
use crate::{Body, LogRecord, Operation, Update};

/// A table copy's header: entry size, counts, free list.
const TABLE_HEADER: usize = 24;
/// The entry sizes of the two layouts.
const ENTRY_V0: usize = 44;
const ENTRY_V1: usize = 40;
/// What an entry in use has in its first four bytes.
const ALLOCATED: u32 = 0xFFFF_FFFF;
/// Records further apart than this many log pages start a new stretch.
/// Gaps of a few pages are normal (up to about 25 in real logs).
pub(crate) const GAP_PAGES: u64 = 64;

/// An attribute of a file, opened for updates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAttribute {
    /// The file whose attribute it is.
    pub file: Reference,
    /// The attribute's type code (`0x80` for `$DATA`, `0xA0` for
    /// `$INDEX_ALLOCATION`, `0xB0` for `$BITMAP`, …).
    pub attribute_type: u32,
    /// The attribute's name (`$I30` for a directory's index, `$J` for the
    /// USN journal's records), empty for an unnamed attribute; `None` when
    /// the log doesn't say (Windows 7 opens attributes without their names,
    /// and a table copy without a names copy has none).
    pub name: Option<String>,
}

/// An entry of the table, and where it was defined.
#[derive(Debug, Clone)]
struct Definition {
    lsn: u64,
    attribute: OpenAttribute,
    from_checkpoint: bool,
}

/// Fill in the open attribute of every update that has one.
pub(crate) fn resolve(records: &mut [LogRecord], page_size: u64) {
    let stretches = Stretches::new(records, page_size);
    let mut definitions: BTreeMap<(usize, u16), Vec<Definition>> = BTreeMap::new();
    let mut by_index: BTreeMap<u16, Vec<Definition>> = BTreeMap::new();
    for (index, definition) in definitions_in(records, &stretches) {
        definitions
            .entry((stretches.of(definition.lsn), index))
            .or_default()
            .push(definition.clone());
        by_index.entry(index).or_default().push(definition);
    }
    // Windows 7 opens attributes without their names: a later copy of the
    // table, in the same stretch, has the same attribute's.
    for list in definitions.values_mut() {
        for at in 0..list.len() {
            if list[at].attribute.name.is_some() {
                continue;
            }
            let (file, kind) = (list[at].attribute.file, list[at].attribute.attribute_type);
            let named = list[at + 1..].iter().find_map(|later| {
                (later.from_checkpoint
                    && later.attribute.file == file
                    && later.attribute.attribute_type == kind)
                    .then(|| later.attribute.name.clone())
                    .flatten()
            });
            list[at].attribute.name = named;
        }
    }
    for record in records {
        let lsn = record.lsn;
        let Body::Update(update) = &mut record.body else {
            continue;
        };
        if update.target_attribute == 0 || !has_target(update) {
            continue;
        }
        if let Some(list) = definitions.get(&(stretches.of(lsn), update.target_attribute)) {
            update.target = Some(at_or_before(list, lsn).attribute.clone());
        } else if let Some(list) = by_index.get(&update.target_attribute) {
            update.target = Some(at_or_before(list, lsn).attribute.clone());
            update.target_inferred = true;
        }
    }
}

/// Whether an update's target attribute is an entry of the table: every
/// operation's but those of transactions, checkpoints and no-ops.
fn has_target(update: &Update) -> bool {
    !matches!(
        update.redo,
        Operation::Noop
            | Operation::CompensationLogRecord
            | Operation::EndTopLevelAction
            | Operation::PrepareTransaction
            | Operation::CommitTransaction
            | Operation::ForgetTransaction
            | Operation::OpenAttributeTableDump
            | Operation::AttributeNamesDump
            | Operation::DirtyPageTableDump
            | Operation::TransactionTableDump
    )
}

/// The newest definition at or before `lsn`, else the oldest. `list` is in
/// LSN order and not empty.
fn at_or_before(list: &[Definition], lsn: u64) -> &Definition {
    let after = list.partition_point(|definition| definition.lsn <= lsn);
    &list[after.saturating_sub(1)]
}

/// The stretches of the log in which the table carries over.
struct Stretches(Vec<u64>);

impl Stretches {
    fn new(records: &[LogRecord], page_size: u64) -> Self {
        let mut boundaries: Vec<u64> = records
            .iter()
            .filter(|record| match &record.body {
                Body::Checkpoint(checkpoint) => checkpoint.open_attribute_table.lsn == 0,
                Body::Other { record_type, .. } => *record_type == crate::record::CLIENT_RESTART,
                Body::Update(_) => false,
            })
            .map(|record| record.lsn)
            .collect();
        let gap = page_size.saturating_mul(GAP_PAGES) / 8;
        boundaries.extend(
            records
                .windows(2)
                .filter(|pair| pair[1].lsn - pair[0].lsn > gap)
                .map(|pair| pair[1].lsn),
        );
        boundaries.sort_unstable();
        Self(boundaries)
    }

    /// The stretch `lsn` is in: how many boundaries are at or before it.
    fn of(&self, lsn: u64) -> usize {
        self.0.partition_point(|&boundary| boundary <= lsn)
    }
}

/// Every definition the records make, in LSN order, with its table offset.
fn definitions_in(records: &[LogRecord], stretches: &Stretches) -> Vec<(u16, Definition)> {
    let names_dumps: BTreeMap<u64, BTreeMap<u16, String>> = records
        .iter()
        .filter_map(|record| {
            let update = record.update()?;
            (update.redo == Operation::AttributeNamesDump)
                .then(|| (record.lsn, names(&update.redo_data)))
        })
        .collect();
    // Each checkpoint names the copies of its tables.
    let names_of_table: BTreeMap<u64, u64> = records
        .iter()
        .filter_map(|record| match &record.body {
            Body::Checkpoint(checkpoint) if checkpoint.open_attribute_table.lsn != 0 => Some((
                checkpoint.open_attribute_table.lsn,
                checkpoint.attribute_names.lsn,
            )),
            _ => None,
        })
        .collect();
    let mut found = Vec::new();
    for record in records {
        let Some(update) = record.update() else {
            continue;
        };
        match update.redo {
            Operation::OpenAttributeTableDump => {
                let names = match names_of_table.get(&record.lsn) {
                    Some(&names_lsn) if names_lsn != 0 => names_dumps.get(&names_lsn),
                    Some(_) => None,
                    None => names_dumps
                        .range(record.lsn + 1..)
                        .next()
                        .filter(|(lsn, _)| stretches.of(**lsn) == stretches.of(record.lsn))
                        .map(|(_, names)| names),
                };
                for (index, mut attribute) in table(&update.redo_data) {
                    // A names copy has every named attribute: one it lacks is
                    // unnamed. Without a copy, the names aren't known.
                    attribute.name =
                        names.map(|names| names.get(&index).cloned().unwrap_or_default());
                    found.push((
                        index,
                        Definition {
                            lsn: record.lsn,
                            attribute,
                            from_checkpoint: true,
                        },
                    ));
                }
            }
            Operation::OpenNonresidentAttribute => {
                if let Some(mut attribute) = entry(&update.redo_data, update.redo_data.len()) {
                    // From Windows 8 the undo data is the name (none for an
                    // unnamed attribute); Windows 7's entries carry none.
                    attribute.name = (update.redo_data.len() != ENTRY_V0
                        || !update.undo_data.is_empty())
                    .then(|| utf16le_until_nul(&update.undo_data).text);
                    found.push((
                        update.target_attribute,
                        Definition {
                            lsn: record.lsn,
                            attribute,
                            from_checkpoint: false,
                        },
                    ));
                }
            }
            _ => {}
        }
    }
    found
}

/// The entries in use of a copy of the table, by table offset.
fn table(table: &[u8]) -> Vec<(u16, OpenAttribute)> {
    let Some(size) = table
        .get(..2)
        .map(|b| usize::from(u16::from_le_bytes([b[0], b[1]])))
    else {
        return Vec::new();
    };
    if size < ENTRY_V1 {
        return Vec::new();
    }
    let mut entries = Vec::new();
    for offset in (TABLE_HEADER..table.len()).step_by(size) {
        let (Ok(index), Some(bytes)) = (u16::try_from(offset), table.get(offset..offset + size))
        else {
            break;
        };
        if bytes.get(..4) == Some(&ALLOCATED.to_le_bytes()[..])
            && let Some(entry) = entry(bytes, size)
        {
            entries.push((index, entry));
        }
    }
    entries
}

/// An entry in the layout its `size` says, without its name.
fn entry(bytes: &[u8], size: usize) -> Option<OpenAttribute> {
    if size < ENTRY_V1 {
        return None;
    }
    let (file_at, type_at) = if size == ENTRY_V0 { (8, 28) } else { (16, 8) };
    let mut r = Reader::new(bytes);
    r.seek(file_at).ok()?;
    let file = Reference::new(r.u64_le().ok()?);
    r.seek(type_at).ok()?;
    let attribute_type = r.u32_le().ok()?;
    Some(OpenAttribute {
        file,
        attribute_type,
        name: None,
    })
}

/// A copy of the names: table offset, length in bytes, the name and a NUL,
/// until an empty entry.
fn names(dump: &[u8]) -> BTreeMap<u16, String> {
    let mut names = BTreeMap::new();
    let mut r = Reader::new(dump);
    while let (Ok(index), Ok(length)) = (r.u16_le(), r.u16_le()) {
        if index == 0 && length == 0 {
            break;
        }
        let Ok(name) = r.bytes(usize::from(length)) else {
            break;
        };
        names.insert(index, utf16le_until_nul(name).text);
        if r.skip(2).is_err() {
            break;
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn names_until_an_empty_entry() {
        let mut dump = Vec::new();
        for (index, name) in [(0x18_u16, "$I30"), (0x40, "$J")] {
            dump.extend(index.to_le_bytes());
            dump.extend((name.len() as u16 * 2).to_le_bytes());
            dump.extend(utf16(name));
            dump.extend([0, 0]);
        }
        dump.extend([0; 4]);
        dump.extend([1, 2, 3]);
        let names = names(&dump);
        assert_eq!(names.len(), 2);
        assert_eq!(names[&0x40], "$J");
    }

    #[test]
    fn table_copies_in_both_layouts() {
        for (size, file_at, type_at) in [(ENTRY_V1, 16, 8), (ENTRY_V0, 8, 28)] {
            let mut copy = vec![0; TABLE_HEADER + 2 * size];
            copy[..2].copy_from_slice(&(size as u16).to_le_bytes());
            let second = TABLE_HEADER + size;
            copy[second..second + 4].copy_from_slice(&ALLOCATED.to_le_bytes());
            copy[second + file_at..second + file_at + 8]
                .copy_from_slice(&0x0002_0000_0000_0009_u64.to_le_bytes());
            copy[second + type_at..second + type_at + 4].copy_from_slice(&0x80_u32.to_le_bytes());
            let entries = table(&copy);
            assert_eq!(entries.len(), 1);
            let (index, open) = &entries[0];
            assert_eq!(usize::from(*index), second);
            assert_eq!(
                (open.file.to_string(), open.attribute_type),
                ("9-2".to_owned(), 0x80)
            );
            assert_eq!(open.name, None);
        }
    }
}
