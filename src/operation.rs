//! The redo and undo operations of NTFS log records.

use core::fmt;

/// An enum over a `u16` operation code, with each operation's name and an
/// `Unknown` variant keeping any other code.
macro_rules! operations {
    ($($(#[$doc:meta])* $name:ident = $code:literal,)+) => {
        /// An operation a log record redoes or undoes. Codes NTFS doesn't
        /// define are kept as [`Operation::Unknown`].
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Operation {
            $($(#[$doc])* $name,)+
            /// A code with no name here.
            Unknown(u16),
        }

        impl Operation {
            /// The operation with this code.
            #[must_use]
            pub const fn from_code(code: u16) -> Self {
                match code {
                    $($code => Self::$name,)+
                    other => Self::Unknown(other),
                }
            }

            /// Its code.
            #[must_use]
            pub const fn code(self) -> u16 {
                match self {
                    $(Self::$name => $code,)+
                    Self::Unknown(code) => code,
                }
            }

            /// Its name, as in Windows' own tools and the NTFS literature;
            /// `None` for an unknown code.
            #[must_use]
            pub const fn name(self) -> Option<&'static str> {
                match self {
                    $(Self::$name => Some(stringify!($name)),)+
                    Self::Unknown(_) => None,
                }
            }
        }
    };
}

operations! {
    /// Does nothing (a record with only a redo or only an undo side).
    Noop = 0x00,
    /// Records that an undo was done, during rollback.
    CompensationLogRecord = 0x01,
    /// Writes a whole file record: a file or directory is created (or a
    /// record reused). The redo data is the new record.
    InitializeFileRecordSegment = 0x02,
    /// Frees a file record: a file or directory is deleted.
    DeallocateFileRecordSegment = 0x03,
    /// Writes the end of a file record.
    WriteEndOfFileRecordSegment = 0x04,
    /// Adds an attribute to a file record. The redo data is the attribute.
    CreateAttribute = 0x05,
    /// Removes an attribute from a file record. The undo data is the
    /// attribute.
    DeleteAttribute = 0x06,
    /// Overwrites part of a resident attribute's value (such as the
    /// timestamps of `$STANDARD_INFORMATION`).
    UpdateResidentValue = 0x07,
    /// Overwrites part of a non-resident attribute's value.
    UpdateNonresidentValue = 0x08,
    /// Changes a non-resident attribute's run list.
    UpdateMappingPairs = 0x09,
    /// Clears clusters marked dirty.
    DeleteDirtyClusters = 0x0A,
    /// Changes an attribute's sizes.
    SetNewAttributeSizes = 0x0B,
    /// Adds an index entry to an index root (a small directory's entry).
    AddIndexEntryRoot = 0x0C,
    /// Removes an index entry from an index root.
    DeleteIndexEntryRoot = 0x0D,
    /// Adds an index entry to an index buffer (a large directory's entry).
    AddIndexEntryAllocation = 0x0E,
    /// Removes an index entry from an index buffer.
    DeleteIndexEntryAllocation = 0x0F,
    /// Writes the end of an index buffer.
    WriteEndOfIndexBuffer = 0x10,
    /// Sets the child VCN of an index root entry.
    SetIndexEntryVcnRoot = 0x11,
    /// Sets the child VCN of an index buffer entry.
    SetIndexEntryVcnAllocation = 0x12,
    /// Updates the times and sizes kept in an index root entry.
    UpdateFileNameRoot = 0x13,
    /// Updates the times and sizes kept in an index buffer entry.
    UpdateFileNameAllocation = 0x14,
    /// Sets bits of a non-resident bitmap (clusters or records allocated).
    SetBitsInNonresidentBitMap = 0x15,
    /// Clears bits of a non-resident bitmap (clusters or records freed).
    ClearBitsInNonresidentBitMap = 0x16,
    /// Relocates a bad cluster.
    HotFix = 0x17,
    /// Ends a top-level action.
    EndTopLevelAction = 0x18,
    /// Prepares a transaction.
    PrepareTransaction = 0x19,
    /// Commits a transaction.
    CommitTransaction = 0x1A,
    /// Forgets a transaction: it is done.
    ForgetTransaction = 0x1B,
    /// Opens a non-resident attribute: adds it to the open attribute
    /// table, which later records name by index.
    OpenNonresidentAttribute = 0x1C,
    /// A checkpoint's copy of the open attribute table.
    OpenAttributeTableDump = 0x1D,
    /// A checkpoint's copy of the open attributes' names.
    AttributeNamesDump = 0x1E,
    /// A checkpoint's copy of the dirty page table.
    DirtyPageTableDump = 0x1F,
    /// A checkpoint's copy of the transaction table.
    TransactionTableDump = 0x20,
    /// Updates data in an index root entry (such as `$O` or `$Q`).
    UpdateRecordDataRoot = 0x21,
    /// Updates data in an index buffer entry.
    UpdateRecordDataAllocation = 0x22,
    /// Updates data at an offset in an index root entry.
    UpdateRelativeDataInIndex = 0x23,
    /// Updates data at an offset in an index buffer entry.
    UpdateRelativeDataInIndex2 = 0x24,
    /// Zeroes the end of a file record.
    ZeroEndOfFileRecord = 0x25,
}

impl Operation {
    /// Whether it changes a file record of the MFT, in place: its target is
    /// then a file record segment, found from the record's VCN.
    #[must_use]
    pub const fn targets_file_record(self) -> bool {
        matches!(
            self,
            Self::InitializeFileRecordSegment
                | Self::DeallocateFileRecordSegment
                | Self::WriteEndOfFileRecordSegment
                | Self::CreateAttribute
                | Self::DeleteAttribute
                | Self::UpdateResidentValue
                | Self::UpdateMappingPairs
                | Self::SetNewAttributeSizes
                | Self::AddIndexEntryRoot
                | Self::DeleteIndexEntryRoot
                | Self::SetIndexEntryVcnRoot
                | Self::UpdateFileNameRoot
                | Self::UpdateRecordDataRoot
                | Self::UpdateRelativeDataInIndex
                | Self::ZeroEndOfFileRecord
        )
    }

    /// Whether it changes a non-resident attribute: its target is then an
    /// entry of the open attribute table.
    #[must_use]
    pub const fn targets_nonresident(self) -> bool {
        matches!(
            self,
            Self::UpdateNonresidentValue
                | Self::AddIndexEntryAllocation
                | Self::DeleteIndexEntryAllocation
                | Self::WriteEndOfIndexBuffer
                | Self::SetIndexEntryVcnAllocation
                | Self::UpdateFileNameAllocation
                | Self::SetBitsInNonresidentBitMap
                | Self::ClearBitsInNonresidentBitMap
                | Self::UpdateRecordDataAllocation
                | Self::UpdateRelativeDataInIndex2
        )
    }
}

/// The name, or the code in hex for an unknown operation.
impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "0x{:02x}", self.code()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip() {
        for code in 0..=0x30 {
            assert_eq!(Operation::from_code(code).code(), code);
        }
        assert_eq!(
            Operation::from_code(0x1C),
            Operation::OpenNonresidentAttribute
        );
        assert_eq!(Operation::from_code(0x26), Operation::Unknown(0x26));
    }

    #[test]
    fn names_and_unknown_codes() {
        assert_eq!(
            Operation::UpdateRelativeDataInIndex2.to_string(),
            "UpdateRelativeDataInIndex2"
        );
        assert_eq!(Operation::Unknown(0x41).to_string(), "0x41");
        assert_eq!(Operation::Unknown(0x41).name(), None);
    }

    #[test]
    fn targets() {
        assert!(Operation::UpdateResidentValue.targets_file_record());
        assert!(!Operation::UpdateResidentValue.targets_nonresident());
        assert!(Operation::AddIndexEntryAllocation.targets_nonresident());
        assert!(!Operation::CommitTransaction.targets_file_record());
        assert!(!Operation::CommitTransaction.targets_nonresident());
    }
}
