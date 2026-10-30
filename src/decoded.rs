//! What redo and undo data hold, decoded in the layout of what their
//! operation writes:
//!
//! - `InitializeFileRecordSegment`: a file record, whole when a file or
//!   directory is created (redo), or only its header when one is deleted
//!   (the undo of `DeallocateFileRecordSegment`: its sequence number and
//!   flags before it was freed);
//! - `CreateAttribute`: an attribute record, added (redo) or deleted (the
//!   undo of `DeleteAttribute`);
//! - `AddIndexEntryRoot`/`Allocation`: an index entry, added (redo) or
//!   deleted (the undo of `DeleteIndexEntry*`);
//! - `UpdateFileNameRoot`/`Allocation`: the times, sizes and attributes a
//!   directory entry keeps for its file, new (redo) and old (undo).
//!
//! File records in the log were never written with an update sequence
//! array: the last bytes of each sector are the data itself.

use crate::Operation;
use crate::bytes::Reader;
use crate::content::{FileName, Reference, file_name};
use crate::text::utf16le;
use crate::time::Filetime;

/// Attribute type codes.
const STANDARD_INFORMATION: u32 = 0x10;
const FILE_NAME: u32 = 0x30;
const DATA: u32 = 0x80;
const END_OF_ATTRIBUTES: u32 = 0xFFFF_FFFF;
/// A file record's signature.
const FILE_RECORD: &[u8; 4] = b"FILE";
/// The file record header, as far as a freed record's undo data keeps it
/// (to its flags), and where NTFS 3.1's records keep their own number.
const HEADER_TO_FLAGS: usize = 0x18;
const RECORD_NUMBER_AT: usize = 0x2C;
const HEADER_31: usize = 0x30;
/// File record flags.
const IN_USE: u16 = 0x0001;
const DIRECTORY: u16 = 0x0002;
/// An attribute record's common header; a resident one's ends here too.
const ATTRIBUTE_HEADER: usize = 0x18;
/// A non-resident attribute record's sizes.
const NONRESIDENT_SIZES_AT: usize = 0x28;
/// An index entry's header: file reference (or data offset and length),
/// lengths, flags.
const INDEX_ENTRY_HEADER: usize = 0x10;
/// The fixed part of a `$FILE_NAME` value, before the name.
const FILE_NAME_HEADER: usize = 0x42;
/// `$STANDARD_INFORMATION`: the times and attributes every version has,
/// and the NTFS 3.0 fields after them.
const STANDARD_INFORMATION_V1: usize = 0x24;
const STANDARD_INFORMATION_V3: usize = 0x48;
/// The duplicated information a directory entry keeps.
const DUPLICATED_INFORMATION: usize = 0x38;

/// What one side of an update holds, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded {
    /// A file record (`InitializeFileRecordSegment`).
    FileRecord(FileRecord),
    /// An attribute record (`CreateAttribute`).
    Attribute(Attribute),
    /// An index entry (`AddIndexEntryRoot`, `AddIndexEntryAllocation`).
    IndexEntry(IndexEntry),
    /// What a directory entry keeps about its file (`UpdateFileNameRoot`,
    /// `UpdateFileNameAllocation`).
    DirectoryEntryInfo(DuplicatedInformation),
}

/// An MFT file record, as written to the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRecord {
    /// Its number, as NTFS 3.1 records keep it (none in NTFS 3.0's, or in a
    /// header alone).
    pub number: Option<u64>,
    /// Its sequence number.
    pub sequence: u16,
    /// Its hard link count.
    pub hard_links: u16,
    /// Its flags: in use (`0x1`), directory (`0x2`), in `$Extend` (`0x4`),
    /// view index (`0x8`).
    pub flags: u16,
    /// The base record, for an extension record (none for a base record,
    /// or when not logged).
    pub base: Option<Reference>,
    /// Its attributes, in the record's order.
    pub attributes: Vec<Attribute>,
    /// Whether only the header was logged (the undo of
    /// `DeallocateFileRecordSegment`): no attributes, no number.
    pub header_only: bool,
}

impl FileRecord {
    /// Whether the record is in use.
    #[must_use]
    pub fn in_use(&self) -> bool {
        self.flags & IN_USE != 0
    }

    /// Whether it is a directory's.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.flags & DIRECTORY != 0
    }

    /// Its reference: number and sequence number, when it has its number.
    #[must_use]
    pub fn reference(&self) -> Option<Reference> {
        self.number
            .map(|number| Reference::from_parts(number, self.sequence))
    }

    /// Its `$STANDARD_INFORMATION`.
    #[must_use]
    pub fn standard_information(&self) -> Option<&StandardInformation> {
        self.attributes
            .iter()
            .find_map(|attribute| attribute.standard_information.as_ref())
    }

    /// Its `$FILE_NAME`s.
    pub fn file_names(&self) -> impl Iterator<Item = &FileName> {
        self.attributes
            .iter()
            .filter_map(|attribute| attribute.file_name.as_ref())
    }

    /// The name to show: the first that isn't an 8.3 alias, else the first.
    #[must_use]
    pub fn name(&self) -> Option<&FileName> {
        self.file_names()
            .find(|name| name.namespace != crate::Namespace::Dos)
            .or_else(|| self.file_names().next())
    }

    /// The size of its unnamed `$DATA` stream: the file's size.
    #[must_use]
    pub fn data_size(&self) -> Option<u64> {
        self.attributes
            .iter()
            .find(|attribute| attribute.attribute_type == DATA && attribute.name.is_empty())
            .map(|attribute| attribute.size)
    }
}

/// An attribute record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// Its type code (`0x10` `$STANDARD_INFORMATION`, `0x30` `$FILE_NAME`,
    /// `0x80` `$DATA`, …).
    pub attribute_type: u32,
    /// Its name, empty for an unnamed attribute (an alternate data stream
    /// is a named `$DATA`).
    pub name: String,
    /// Whether its value is in the record.
    pub resident: bool,
    /// Its flags: compressed (`0x0001`), encrypted (`0x4000`), sparse
    /// (`0x8000`).
    pub flags: u16,
    /// Its identifier in the file record.
    pub id: u16,
    /// The value's size: its length when resident, its real size when not.
    pub size: u64,
    /// Space allocated on the volume, for a non-resident attribute.
    pub allocated_size: Option<u64>,
    /// The value, decoded, for `$STANDARD_INFORMATION`.
    pub standard_information: Option<StandardInformation>,
    /// The value, decoded, for `$FILE_NAME`.
    pub file_name: Option<FileName>,
}

/// A `$STANDARD_INFORMATION` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StandardInformation {
    /// Created.
    pub created: Filetime,
    /// Content last modified.
    pub modified: Filetime,
    /// File record last changed.
    pub changed: Filetime,
    /// Last accessed.
    pub accessed: Filetime,
    /// The file's attributes (`FILE_ATTRIBUTE_*`).
    pub attributes: u32,
    /// Owner id (NTFS 3.0 on).
    pub owner_id: Option<u32>,
    /// Security id: its descriptor in `$Secure` (NTFS 3.0 on).
    pub security_id: Option<u32>,
    /// Quota charged (NTFS 3.0 on).
    pub quota_charged: Option<u64>,
    /// The USN of the file's last change journal record (NTFS 3.0 on).
    pub usn: Option<u64>,
}

/// An index entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    /// Its flags: has a child node (`0x1`), last in its node (`0x2`).
    pub flags: u16,
    /// The length of its key.
    pub key_length: u16,
    /// Its key, decoded, in a directory's index (`$I30`): the `$FILE_NAME`
    /// of the file the entry points to, with that file's reference. None
    /// in other indexes (`$O`, `$Q`, `$R`, `$SDH`, `$SII`), whose keys are
    /// something else.
    pub file_name: Option<FileName>,
}

/// What a directory entry keeps about its file, besides its name: the
/// times, sizes and attributes as they were when it was last updated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplicatedInformation {
    /// Created.
    pub created: Filetime,
    /// Content last modified.
    pub modified: Filetime,
    /// File record last changed.
    pub changed: Filetime,
    /// Last accessed.
    pub accessed: Filetime,
    /// Allocated size, in bytes.
    pub allocated_size: u64,
    /// Real size, in bytes.
    pub size: u64,
    /// The file's attributes (`FILE_ATTRIBUTE_*`).
    pub attributes: u32,
    /// Its reparse tag, or the size of its extended attributes.
    pub reparse_value: u32,
}

/// `data`, written by `operation`, decoded: `None` for operations whose
/// data isn't decoded, or data too short or not in the layout expected.
pub(crate) fn decode(operation: Operation, data: &[u8]) -> Option<Decoded> {
    match operation {
        Operation::InitializeFileRecordSegment => file_record(data).map(Decoded::FileRecord),
        Operation::CreateAttribute => attribute(data).map(Decoded::Attribute),
        Operation::AddIndexEntryRoot | Operation::AddIndexEntryAllocation => {
            index_entry(data).map(Decoded::IndexEntry)
        }
        Operation::UpdateFileNameRoot | Operation::UpdateFileNameAllocation => {
            duplicated_information(data).map(Decoded::DirectoryEntryInfo)
        }
        _ => None,
    }
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    let mut r = Reader::new(bytes);
    r.seek(at).ok()?;
    r.u16_le().ok()
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let mut r = Reader::new(bytes);
    r.seek(at).ok()?;
    r.u32_le().ok()
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    let mut r = Reader::new(bytes);
    r.seek(at).ok()?;
    r.u64_le().ok()
}

/// A file record: the header, as far as it is there, and the attributes
/// that are whole in it.
fn file_record(image: &[u8]) -> Option<FileRecord> {
    if image.get(..4) != Some(&FILE_RECORD[..]) || image.len() < HEADER_TO_FLAGS {
        return None;
    }
    let sequence = u16_at(image, 0x10)?;
    let hard_links = u16_at(image, 0x12)?;
    let first = usize::from(u16_at(image, 0x14)?);
    let flags = u16_at(image, 0x16)?;
    let header_only = image.len() < first.max(HEADER_TO_FLAGS + 1);
    let base = u64_at(image, 0x20)
        .filter(|&raw| raw != 0)
        .map(Reference::new);
    let number = (first >= HEADER_31)
        .then(|| u32_at(image, RECORD_NUMBER_AT))
        .flatten()
        .map(u64::from);
    let mut attributes = Vec::new();
    // A header alone has no attributes to read.
    let mut at = if header_only { image.len() } else { first };
    while let (Some(kind), Some(length)) = (u32_at(image, at), u32_at(image, at + 4)) {
        let length = length as usize;
        if kind == END_OF_ATTRIBUTES || length < ATTRIBUTE_HEADER || !length.is_multiple_of(8) {
            break;
        }
        let Some(end) = at.checked_add(length) else {
            break;
        };
        let Some(record) = image.get(at..end) else {
            break;
        };
        attributes.extend(attribute(record));
        at = end;
    }
    let mut record = FileRecord {
        number,
        sequence,
        hard_links,
        flags,
        base,
        attributes,
        header_only,
    };
    // The names a record carries are its own.
    let reference = record.reference();
    for attribute in &mut record.attributes {
        if let Some(name) = &mut attribute.file_name {
            name.file = reference;
        }
    }
    Some(record)
}

/// An attribute record, as far as its declared length and the data go.
fn attribute(record: &[u8]) -> Option<Attribute> {
    let mut r = Reader::new(record);
    let attribute_type = r.u32_le().ok()?;
    let length = r.u32_le().ok()? as usize;
    let nonresident = r.u8().ok()? != 0;
    let name_length = usize::from(r.u8().ok()?);
    let name_offset = usize::from(r.u16_le().ok()?);
    let flags = r.u16_le().ok()?;
    let id = r.u16_le().ok()?;
    if attribute_type == END_OF_ATTRIBUTES || length < ATTRIBUTE_HEADER {
        return None;
    }
    let record = &record[..length.min(record.len())];
    let name = if name_length == 0 {
        String::new()
    } else {
        utf16le(record.get(name_offset..name_offset + 2 * name_length)?).text
    };
    let mut attribute = Attribute {
        attribute_type,
        name,
        resident: !nonresident,
        flags,
        id,
        size: 0,
        allocated_size: None,
        standard_information: None,
        file_name: None,
    };
    if nonresident {
        attribute.allocated_size = Some(u64_at(record, NONRESIDENT_SIZES_AT)?);
        attribute.size = u64_at(record, NONRESIDENT_SIZES_AT + 8)?;
        return Some(attribute);
    }
    let value_length = u32_at(record, 0x10)? as usize;
    let value_offset = usize::from(u16_at(record, 0x14)?);
    attribute.size = value_length as u64;
    let value = record
        .get(value_offset..value_offset.saturating_add(value_length).min(record.len()))
        .unwrap_or_default();
    match attribute_type {
        STANDARD_INFORMATION => attribute.standard_information = standard_information(value),
        FILE_NAME => attribute.file_name = file_name(value, None),
        _ => {}
    }
    Some(attribute)
}

/// A `$STANDARD_INFORMATION` value, as far as it goes.
pub(crate) fn standard_information(value: &[u8]) -> Option<StandardInformation> {
    if value.len() < STANDARD_INFORMATION_V1 {
        return None;
    }
    let time = |at| u64_at(value, at).map(Filetime::new);
    let v3 = value.len() >= STANDARD_INFORMATION_V3;
    Some(StandardInformation {
        created: time(0)?,
        modified: time(8)?,
        changed: time(16)?,
        accessed: time(24)?,
        attributes: u32_at(value, 32)?,
        owner_id: v3.then(|| u32_at(value, 0x30)).flatten(),
        security_id: v3.then(|| u32_at(value, 0x34)).flatten(),
        quota_charged: v3.then(|| u64_at(value, 0x38)).flatten(),
        usn: v3.then(|| u64_at(value, 0x40)).flatten(),
    })
}

/// An index entry, with its key decoded as a `$FILE_NAME` when it is one.
fn index_entry(entry: &[u8]) -> Option<IndexEntry> {
    let reference = Reference::new(u64_at(entry, 0)?);
    let length = usize::from(u16_at(entry, 0x08)?);
    let key_length = u16_at(entry, 0x0A)?;
    let flags = u16_at(entry, 0x0C)?;
    if length < INDEX_ENTRY_HEADER || !length.is_multiple_of(8) {
        return None;
    }
    // A child VCN is the final eight bytes, outside the key. A final sentinel entry has no
    // filename key. Do not consume padding or bytes from the next entry, even if available.
    let key_end = INDEX_ENTRY_HEADER + usize::from(key_length);
    let key_limit = length.checked_sub(if flags & 1 != 0 { 8 } else { 0 })?;
    let file_name =
        (flags & 2 == 0 && usize::from(key_length) >= FILE_NAME_HEADER && key_end <= key_limit)
            .then(|| {
                let key = entry.get(INDEX_ENTRY_HEADER..key_end)?;
                file_name(key, Some(reference))
            })
            .flatten();
    Some(IndexEntry {
        flags,
        key_length,
        file_name,
    })
}

/// The duplicated information of a directory entry.
fn duplicated_information(data: &[u8]) -> Option<DuplicatedInformation> {
    if data.len() < DUPLICATED_INFORMATION {
        return None;
    }
    let time = |at| u64_at(data, at).map(Filetime::new);
    Some(DuplicatedInformation {
        created: time(0)?,
        modified: time(8)?,
        changed: time(16)?,
        accessed: time(24)?,
        allocated_size: u64_at(data, 0x20)?,
        size: u64_at(data, 0x28)?,
        attributes: u32_at(data, 0x30)?,
        reparse_value: u32_at(data, 0x34)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_freed_records_header() {
        // The undo data of a real DeallocateFileRecordSegment: 24 bytes.
        let undo = [
            0x46, 0x49, 0x4C, 0x45, 0x30, 0x00, 0x03, 0x00, 0x57, 0xD5, 0x20, 0x14, 0x00, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x38, 0x00, 0x01, 0x00,
        ];
        let Some(Decoded::FileRecord(record)) =
            decode(Operation::InitializeFileRecordSegment, &undo)
        else {
            panic!("not a file record");
        };
        assert!(record.header_only && record.in_use() && !record.is_directory());
        assert_eq!((record.sequence, record.hard_links), (2, 2));
        assert_eq!((record.number, record.base), (None, None));
        assert_eq!(record.attributes, []);
    }

    #[test]
    fn directory_entry_information() {
        let mut data = Vec::new();
        for time in [1_u64, 2, 3, 4] {
            data.extend(time.to_le_bytes());
        }
        data.extend(8192_u64.to_le_bytes());
        data.extend(5000_u64.to_le_bytes());
        data.extend(0x20_u32.to_le_bytes());
        data.extend(0xA000_000C_u32.to_le_bytes());
        let Some(Decoded::DirectoryEntryInfo(info)) =
            decode(Operation::UpdateFileNameAllocation, &data)
        else {
            panic!("not decoded");
        };
        assert_eq!((info.created.raw(), info.accessed.raw()), (1, 4));
        assert_eq!((info.allocated_size, info.size), (8192, 5000));
        assert_eq!((info.attributes, info.reparse_value), (0x20, 0xA000_000C));
        assert_eq!(decode(Operation::UpdateFileNameRoot, &data[..55]), None);
    }

    #[test]
    fn non_resident_attributes_have_their_real_size() {
        let mut record = vec![0; 0x48];
        record[..4].copy_from_slice(&DATA.to_le_bytes());
        record[4..8].copy_from_slice(&0x48_u32.to_le_bytes());
        record[8] = 1;
        record[0x28..0x30].copy_from_slice(&8192_u64.to_le_bytes());
        record[0x30..0x38].copy_from_slice(&5000_u64.to_le_bytes());
        let attribute = attribute(&record).unwrap();
        assert!(!attribute.resident);
        assert_eq!(
            (attribute.size, attribute.allocated_size),
            (5000, Some(8192))
        );
        assert_eq!(attribute.name, "");
    }

    proptest::proptest! {
        /// Any bytes, in any of the layouts decoded: never a panic.
        #[test]
        fn arbitrary_data(
            data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2048),
            code in 0x02_u16..0x15,
        ) {
            let _ = decode(Operation::from_code(code), &data);
            let mut record = b"FILE".to_vec();
            record.extend(&data);
            let _ = decode(Operation::InitializeFileRecordSegment, &record);
        }
    }

    #[test]
    fn view_index_keys_are_not_file_names() {
        // A $SII entry: data offset and length, then a 4-byte key.
        let mut entry = vec![0; 0x28];
        entry[..2].copy_from_slice(&0x14_u16.to_le_bytes());
        entry[2..4].copy_from_slice(&0x14_u16.to_le_bytes());
        entry[8..10].copy_from_slice(&0x28_u16.to_le_bytes());
        entry[10..12].copy_from_slice(&4_u16.to_le_bytes());
        let Some(Decoded::IndexEntry(entry)) = decode(Operation::AddIndexEntryAllocation, &entry)
        else {
            panic!("not decoded");
        };
        assert_eq!((entry.key_length, entry.file_name), (4, None));
    }

    #[test]
    fn index_entries_respect_child_pointer_and_sentinel_boundaries() {
        let mut entry = vec![0; 0x70];
        entry[8..10].copy_from_slice(&0x60_u16.to_le_bytes());
        entry[10..12].copy_from_slice(&0x48_u16.to_le_bytes());
        // A complete one-character FILE_NAME key, ending at 0x58.
        entry[0x50] = 1;
        entry[0x52..0x54].copy_from_slice(&u16::from(b'a').to_le_bytes());
        assert!(index_entry(&entry).unwrap().file_name.is_some());
        // Reserving the final child VCN at 0x50 puts part of the key outside the entry.
        entry[8..10].copy_from_slice(&0x58_u16.to_le_bytes());
        entry[12..14].copy_from_slice(&1_u16.to_le_bytes());
        assert!(index_entry(&entry).unwrap().file_name.is_none());
        entry[12..14].copy_from_slice(&2_u16.to_le_bytes());
        assert!(index_entry(&entry).unwrap().file_name.is_none());
        entry[8..10].copy_from_slice(&0x08_u16.to_le_bytes());
        assert!(index_entry(&entry).is_none());
    }
}
