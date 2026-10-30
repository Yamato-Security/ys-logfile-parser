//! What couldn't be read, and where.

use core::fmt;

use crate::fixup::Fixup;

/// Something in the log that couldn't be read, or only partly. None stops
/// the reading: what can be read around it still is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Problem {
    /// Byte offset in the log of the page or record concerned.
    pub offset: u64,
    /// What is wrong.
    pub kind: ProblemKind,
}

/// What a [`Problem`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProblemKind {
    /// A restart page that can't be read. The other one is used.
    BadRestartPage,
    /// No restart page can be read or used: records are looked for with the
    /// usual layout (4 KiB pages, version 2.0).
    NoRestartPage,
    /// A page that is neither a log page nor unused.
    UnknownPage,
    /// A page whose update sequence array doesn't fit it.
    DamagedPage,
    /// A page only partly written: this sector (from 0) doesn't end with
    /// the page's update sequence number. The page is skipped.
    TornPage {
        /// The first sector found torn.
        sector: u32,
    },
    /// The log ends partway through a page.
    PartialPage,
    /// A record whose client data runs into a page that is missing,
    /// unreadable or from another pass over the log: its data is cut
    /// short.
    RecordCutShort {
        /// The record's LSN.
        lsn: u64,
        /// How many bytes of its client data are missing.
        missing: u64,
    },
}

impl Problem {
    /// A page that couldn't be unprotected.
    pub(crate) fn page(offset: u64, fixup: Fixup) -> Self {
        let kind = match fixup {
            Fixup::Malformed => ProblemKind::DamagedPage,
            Fixup::Torn(sector) => ProblemKind::TornPage {
                sector: sector as u32,
            },
        };
        Self { offset, kind }
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "at byte {}: ", self.offset)?;
        match self.kind {
            ProblemKind::BadRestartPage => f.write_str("a restart page that can't be read"),
            ProblemKind::NoRestartPage => f.write_str(
                "no readable restart page: records looked for with the usual layout (4 KiB pages)",
            ),
            ProblemKind::UnknownPage => f.write_str("neither a log page nor an unused one"),
            ProblemKind::DamagedPage => {
                f.write_str("a page whose update sequence array doesn't fit it")
            }
            ProblemKind::TornPage { sector } => write!(
                f,
                "a page only partly written (sector {sector} torn), skipped"
            ),
            ProblemKind::PartialPage => f.write_str("the log ends partway through a page"),
            ProblemKind::RecordCutShort { lsn, missing } => write!(
                f,
                "record {lsn} cut short: {missing} bytes of it are in no page of its pass"
            ),
        }
    }
}
