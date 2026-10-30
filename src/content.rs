//! What redo and undo data say about files: names and timestamps.
//!
//! Records carry pieces of MFT file records and of directory indexes, in
//! the layouts those have on disk:
//!
//! - a whole file record (`InitializeFileRecordSegment` redo data);
//! - an attribute record (`CreateAttribute` redo data, `DeleteAttribute`
//!   undo data);
//! - a directory index entry, whose key is the `$FILE_NAME` of the file it
//!   points to (`AddIndexEntry*` redo data, `DeleteIndexEntry*` undo data);
//! - a few bytes of a resident value (`UpdateResidentValue`), which are
//!   `$STANDARD_INFORMATION` timestamps when they land on them.

use core::fmt;

use common::bytes::Reader;
use common::text::utf16le;
use common::time::Ts;

/// Attribute type codes.
const STANDARD_INFORMATION: u32 = 0x10;
const FILE_NAME: u32 = 0x30;
const END_OF_ATTRIBUTES: u32 = 0xFFFF_FFFF;
/// A file record's signature.
const FILE_RECORD: &[u8; 4] = b"FILE";
/// Where a file record keeps its sequence number, first attribute and (from
/// NTFS 3.1) its own number.
const SEQUENCE_AT: usize = 0x10;
const FIRST_ATTRIBUTE_AT: usize = 0x14;
const RECORD_NUMBER_AT: usize = 0x2C;
/// The NTFS 3.1 file record header, which has the record number, ends here;
/// NTFS 3.0's ends at `0x2A`.
const HEADER_31: usize = 0x30;
const HEADER_30: usize = 0x2A;
/// A resident attribute record's header: type, length, form, name, flags,
/// identifier, then the value's length and offset.
const RESIDENT_HEADER: usize = 0x18;
const VALUE_LENGTH_AT: usize = 0x10;
const VALUE_OFFSET_AT: usize = 0x14;
/// An index entry's header: file reference, lengths, flags.
const INDEX_ENTRY_HEADER: usize = 0x10;
const LAST_INDEX_ENTRY: u16 = 0x02;
/// The fixed part of a `$FILE_NAME` value, before the name.
const FILE_NAME_HEADER: usize = 0x42;
/// `$STANDARD_INFORMATION` starts with four timestamps.
const TIMES_LENGTH: usize = 32;
/// Timestamps outside these years are not `$STANDARD_INFORMATION`'s.
const PLAUSIBLE_YEARS: (i64, i64) = (1980, 2200);
/// Record numbers are 48 bits of a reference.
const ENTRY_BITS: u32 = 48;

/// An NTFS file reference: an MFT record number and the sequence number
/// that record had, which tells reuses of the record apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Reference(u64);

impl Reference {
    /// A reference from its recorded value.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// A reference from a record number and sequence number.
    #[must_use]
    pub const fn from_parts(entry: u64, sequence: u16) -> Self {
        Self(entry & ((1 << ENTRY_BITS) - 1) | (sequence as u64) << ENTRY_BITS)
    }

    /// The value as recorded.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// The MFT record number: the low 48 bits.
    #[must_use]
    pub const fn entry(self) -> u64 {
        self.0 & ((1 << ENTRY_BITS) - 1)
    }

    /// The sequence number: the high 16 bits.
    #[must_use]
    pub const fn sequence(self) -> u16 {
        (self.0 >> ENTRY_BITS) as u16
    }
}

/// `entry-sequence` (`30-1`), as The Sleuth Kit writes it.
impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.entry(), self.sequence())
    }
}

/// A `$FILE_NAME` attribute value: a name of a file, the directory it is
/// in, and the times and sizes recorded with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileName {
    /// The file named, when the data says: the index entry's reference, or
    /// the number and sequence number of the file record carrying it.
    pub file: Option<Reference>,
    /// The directory the name is in.
    pub parent: Reference,
    /// The name. Invalid UTF-16 is escaped, never replaced (`\u{d800}`).
    pub name: String,
    /// Whether the name held invalid UTF-16, now escaped.
    pub name_escaped: bool,
    /// Which naming rules the name follows.
    pub namespace: Namespace,
    /// Created (FILETIME, UTC), as recorded with the name.
    pub created: Ts,
    /// Content last modified.
    pub modified: Ts,
    /// File record last changed.
    pub changed: Ts,
    /// Last accessed.
    pub accessed: Ts,
    /// Allocated size, in bytes.
    pub allocated_size: u64,
    /// Real size, in bytes.
    pub size: u64,
    /// The file's attributes (`FILE_ATTRIBUTE_*`).
    pub attributes: u32,
}

/// The namespace of a [`FileName`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Namespace {
    /// Case-sensitive, any character but `/` and NUL.
    Posix,
    /// A Windows long name, with an 8.3 alias in another `$FILE_NAME`.
    Win32,
    /// An 8.3 alias of a Windows long name.
    Dos,
    /// Valid both as a Windows long name and as an 8.3 name.
    Win32AndDos,
    /// A code NTFS doesn't define.
    Other(u8),
}

impl Namespace {
    const fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Posix,
            1 => Self::Win32,
            2 => Self::Dos,
            3 => Self::Win32AndDos,
            other => Self::Other(other),
        }
    }
}

/// `$STANDARD_INFORMATION` timestamps: the times Windows shows, and those
/// timestomping rewrites. A field is `None` when the data doesn't cover it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StandardTimes {
    /// Created (FILETIME, UTC).
    pub created: Option<Ts>,
    /// Content last modified.
    pub modified: Option<Ts>,
    /// File record last changed.
    pub changed: Option<Ts>,
    /// Last accessed.
    pub accessed: Option<Ts>,
}

/// What one side (redo or undo) of a record says about files.
#[derive(Debug, Default)]
pub(crate) struct Content {
    pub(crate) names: Vec<FileName>,
    pub(crate) times: Option<StandardTimes>,
}

impl Content {
    fn add_attribute(&mut self, kind: u32, value: &[u8], file: Option<Reference>) {
        match kind {
            STANDARD_INFORMATION => self.times = standard_times(value, 0),
            FILE_NAME => self.names.extend(file_name(value, file)),
            _ => {}
        }
    }
}

/// The names and times in a whole file record.
pub(crate) fn file_record(image: &[u8]) -> Content {
    let mut content = Content::default();
    if image.get(..4) != Some(&FILE_RECORD[..]) {
        return content;
    }
    let (Some(sequence), Some(first)) = (
        u16_at(image, SEQUENCE_AT),
        u16_at(image, FIRST_ATTRIBUTE_AT),
    ) else {
        return content;
    };
    let mut at = usize::from(first);
    let file = if at >= HEADER_31 {
        u32_at(image, RECORD_NUMBER_AT).map(|number| Reference::from_parts(number.into(), sequence))
    } else {
        None
    };
    while let (Some(kind), Some(length)) = (u32_at(image, at), u32_at(image, at + 4)) {
        let length = length as usize;
        let Some(attribute) = image.get(at..at.saturating_add(length)) else {
            break;
        };
        if kind == END_OF_ATTRIBUTES || length < RESIDENT_HEADER {
            break;
        }
        if let Some(value) = resident_value(attribute) {
            content.add_attribute(kind, value, file);
        }
        at += length;
    }
    content
}

/// The names and times in one attribute record.
pub(crate) fn attribute(record: &[u8]) -> Content {
    let mut content = Content::default();
    if let (Some(kind), Some(value)) = (u32_at(record, 0), resident_value(record)) {
        content.add_attribute(kind, value, None);
    }
    content
}

/// The name in a directory index entry: its key, a `$FILE_NAME`.
pub(crate) fn index_entry(entry: &[u8]) -> Content {
    let mut r = Reader::new(entry);
    let parsed = (|| {
        let file = Reference::new(r.u64_le().ok()?);
        let _length = r.u16_le().ok()?;
        let key_length = usize::from(r.u16_le().ok()?);
        let flags = r.u16_le().ok()?;
        if flags & LAST_INDEX_ENTRY != 0 || key_length < FILE_NAME_HEADER {
            return None;
        }
        let key = entry.get(INDEX_ENTRY_HEADER..INDEX_ENTRY_HEADER + key_length)?;
        file_name(key, Some(file))
    })();
    Content {
        names: parsed.into_iter().collect(),
        times: None,
    }
}

/// `$STANDARD_INFORMATION` timestamps in bytes written at
/// `attribute_offset` of a resident attribute, when they land on them.
/// Whether the attribute is `$STANDARD_INFORMATION` is the caller's to say;
/// timestamps that aren't plausible say it isn't.
pub(crate) fn resident_times(data: &[u8], attribute_offset: usize) -> Option<StandardTimes> {
    let value_offset = attribute_offset.checked_sub(RESIDENT_HEADER)?;
    standard_times(data, value_offset)
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    let bytes = bytes.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let bytes = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// The value of a resident attribute record.
fn resident_value(record: &[u8]) -> Option<&[u8]> {
    let mut r = Reader::new(record);
    r.seek(8).ok()?;
    if r.u8().ok()? != 0 {
        return None;
    }
    r.seek(VALUE_LENGTH_AT).ok()?;
    let length = usize::try_from(r.u32_le().ok()?).ok()?;
    r.seek(VALUE_OFFSET_AT).ok()?;
    let offset = usize::from(r.u16_le().ok()?);
    record.get(offset..offset.checked_add(length)?)
}

/// A `$FILE_NAME` value.
fn file_name(value: &[u8], file: Option<Reference>) -> Option<FileName> {
    let mut r = Reader::new(value);
    let parent = Reference::new(r.u64_le().ok()?);
    let mut time = || r.u64_le().ok().map(Ts::from_filetime);
    let (created, modified, changed, accessed) = (time()?, time()?, time()?, time()?);
    let allocated_size = r.u64_le().ok()?;
    let size = r.u64_le().ok()?;
    let attributes = r.u32_le().ok()?;
    r.skip(4).ok()?; // extended attributes or reparse tag
    let length = usize::from(r.u8().ok()?);
    let namespace = Namespace::from_code(r.u8().ok()?);
    if length == 0 {
        return None;
    }
    let name = utf16le(r.bytes(length * 2).ok()?);
    Some(FileName {
        file,
        parent,
        name: name.text,
        name_escaped: name.escaped,
        namespace,
        created,
        modified,
        changed,
        accessed,
        allocated_size,
        size,
        attributes,
    })
}

/// The timestamps among `data`, written at `value_offset` of a
/// `$STANDARD_INFORMATION` value: each one it covers whole, when every one
/// it covers is plausible.
fn standard_times(data: &[u8], value_offset: usize) -> Option<StandardTimes> {
    if value_offset >= TIMES_LENGTH || value_offset % 8 != 0 {
        return None;
    }
    let mut times = StandardTimes::default();
    let fields = [
        &mut times.created,
        &mut times.modified,
        &mut times.changed,
        &mut times.accessed,
    ];
    let mut any = false;
    for (index, field) in fields.into_iter().enumerate() {
        let Some(at) = (index * 8).checked_sub(value_offset) else {
            continue;
        };
        let Some(bytes) = data.get(at..at + 8) else {
            break;
        };
        let time = Ts::from_filetime(u64::from_le_bytes(bytes.try_into().ok()?));
        if !time.year_within(PLAUSIBLE_YEARS.0, PLAUSIBLE_YEARS.1) {
            return None;
        }
        *field = Some(time);
        any = true;
    }
    any.then_some(times)
}

/// Where the first attribute of a file record of `record_size` bytes is,
/// for NTFS 3.1 (Windows XP on) and NTFS 3.0 layouts: after the header and
/// its update sequence array, 8-byte aligned. `$STANDARD_INFORMATION`, the
/// attribute with the lowest type, is there in every base record.
pub(crate) fn first_attribute_offsets(record_size: u64) -> [u64; 2] {
    let array = 2 * (record_size / 512 + 1);
    [HEADER_31 as u64, HEADER_30 as u64].map(|header| (header + array).next_multiple_of(8))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references() {
        let reference = Reference::new(0x0005_0000_0000_0005);
        assert_eq!((reference.entry(), reference.sequence()), (5, 5));
        assert_eq!(Reference::from_parts(30, 1).to_string(), "30-1");
    }

    #[test]
    fn first_attributes() {
        assert_eq!(first_attribute_offsets(1024), [0x38, 0x30]);
        assert_eq!(first_attribute_offsets(4096), [0x48, 0x40]);
    }

    #[test]
    fn partial_timestamp_updates() {
        // 2024-03-01T12:00:00Z, written over modified and changed.
        let time = 133_537_680_000_000_000_u64.to_le_bytes();
        let data = [time, time].concat();
        let times = resident_times(&data, 0x20).unwrap();
        assert_eq!(times.created, None);
        assert!(times.modified.is_some() && times.changed.is_some());
        assert_eq!(times.accessed, None);
        // Past the timestamps, or not timestamps at all.
        assert_eq!(resident_times(&data, 0x38), None);
        assert_eq!(resident_times(&[0x41; 16], 0x18), None);
        assert_eq!(resident_times(&data, 0x10), None);
    }
}
