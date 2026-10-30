//! The open attribute table: which file and attribute each non-resident
//! update changes.
//!
//! Updates to non-resident attributes name their target by an offset in
//! this table. The log rebuilds it: an `OpenNonresidentAttribute` record
//! adds an entry (its redo data) with its attribute's name (its undo data),
//! and each checkpoint writes a copy of the whole table
//! (`OpenAttributeTableDump`) and of the names (`AttributeNamesDump`).
//!
//! An entry has one of two layouts, told apart by their sizes: 44 bytes
//! (checkpoint version 0, up to Windows 7) or 40 bytes (version 1).

use std::collections::BTreeMap;

use crate::bytes::Reader;
use crate::text::utf16le_until_nul;

use crate::content::Reference;
use crate::{Operation, Update};

/// A table copy's header: entry size, counts, free list.
const TABLE_HEADER: usize = 24;
/// The entry sizes of the two layouts.
const ENTRY_V0: usize = 44;
const ENTRY_V1: usize = 40;
/// What an entry in use has in its first four bytes.
const ALLOCATED: u32 = 0xFFFF_FFFF;

/// An attribute of a file, opened for non-resident updates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAttribute {
    /// The file whose attribute it is.
    pub file: Reference,
    /// The attribute's type code (`0x80` for `$DATA`, `0xA0` for
    /// `$INDEX_ALLOCATION`, `0xB0` for `$BITMAP`, …).
    pub attribute_type: u32,
    /// The attribute's name, empty for an unnamed attribute (`$I30` for a
    /// directory's index).
    pub name: String,
}

/// An entry: the attribute, and its name when its own record gave it.
#[derive(Debug, Clone)]
struct Entry {
    file: Reference,
    attribute_type: u32,
    name: Option<String>,
}

/// The table as of the record being read.
#[derive(Debug, Default)]
pub(crate) struct OpenAttributes {
    entries: BTreeMap<u16, Entry>,
    /// Names from the latest names copy, by table offset.
    names: BTreeMap<u16, String>,
}

impl OpenAttributes {
    /// The attribute at offset `index` of the table.
    pub(crate) fn get(&self, index: u16) -> Option<OpenAttribute> {
        let entry = self.entries.get(&index)?;
        let name = entry
            .name
            .as_ref()
            .or_else(|| self.names.get(&index))
            .cloned()
            .unwrap_or_default();
        Some(OpenAttribute {
            file: entry.file,
            attribute_type: entry.attribute_type,
            name,
        })
    }

    /// Take in what `update` does to the table, if anything.
    pub(crate) fn observe(&mut self, update: &Update) {
        match update.redo {
            Operation::OpenNonresidentAttribute => {
                if let Some(mut entry) = entry(&update.redo_data, update.redo_data.len()) {
                    let name = utf16le_until_nul(&update.undo_data).text;
                    entry.name = Some(name);
                    self.entries.insert(update.target_attribute, entry);
                }
            }
            Operation::OpenAttributeTableDump => self.add_table(&update.redo_data),
            Operation::AttributeNamesDump => self.names = names(&update.redo_data),
            _ => {}
        }
    }

    /// Add the entries in use of a copy of the table.
    fn add_table(&mut self, table: &[u8]) {
        let Some(size) = table
            .get(..2)
            .map(|b| usize::from(u16::from_le_bytes([b[0], b[1]])))
        else {
            return;
        };
        if size < ENTRY_V1 {
            return;
        }
        for offset in (TABLE_HEADER..table.len()).step_by(size) {
            let (Ok(index), Some(bytes)) =
                (u16::try_from(offset), table.get(offset..offset + size))
            else {
                break;
            };
            if bytes.get(..4) == Some(&ALLOCATED.to_le_bytes()[..])
                && let Some(entry) = entry(bytes, size) {
                    self.entries.insert(index, entry);
                }
        }
    }
}

/// An entry in the layout its `size` says.
fn entry(bytes: &[u8], size: usize) -> Option<Entry> {
    if size < ENTRY_V1 {
        return None;
    }
    let (file_at, type_at) = if size == ENTRY_V0 { (8, 28) } else { (16, 8) };
    let mut r = Reader::new(bytes);
    r.seek(file_at).ok()?;
    let file = Reference::new(r.u64_le().ok()?);
    r.seek(type_at).ok()?;
    let attribute_type = r.u32_le().ok()?;
    Some(Entry {
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
            let mut table = vec![0; TABLE_HEADER + 2 * size];
            table[..2].copy_from_slice(&(size as u16).to_le_bytes());
            let second = TABLE_HEADER + size;
            table[second..second + 4].copy_from_slice(&ALLOCATED.to_le_bytes());
            table[second + file_at..second + file_at + 8]
                .copy_from_slice(&0x0002_0000_0000_0009_u64.to_le_bytes());
            table[second + type_at..second + type_at + 4].copy_from_slice(&0x80_u32.to_le_bytes());
            let mut attributes = OpenAttributes::default();
            attributes.add_table(&table);
            assert!(attributes.get(TABLE_HEADER as u16).is_none());
            let open = attributes.get(second as u16).unwrap();
            assert_eq!(
                (open.file.to_string(), open.attribute_type),
                ("9-2".to_owned(), 0x80)
            );
            assert_eq!(open.name, "");
        }
    }
}
