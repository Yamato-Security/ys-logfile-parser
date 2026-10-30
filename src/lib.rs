//! The NTFS transaction journal, `$LogFile`: what NTFS was about to change
//! on a volume, and how to undo it, for the last few minutes or hours of
//! activity. File creations, deletions, renames and timestamp changes all
//! pass through it, often long after the USN journal and the MFT have
//! moved on.
//!
//! [`parse`] reads a whole `$LogFile` held in memory and never fails: what
//! can't be read is in [`LogFile::problems`], and everything around it is
//! still read.
//!
//! # The format
//!
//! The log is written by NTFS's log file service in pages, protected like
//! MFT records by an **update sequence array**: the last two bytes of each
//! 512-byte sector are saved in the array and replaced by a number that
//! changes on every write, so a page only partly written (torn) shows.
//!
//! **Restart pages** (`RSTR`, or `CHKD` after chkdsk) are the first two
//! pages, two copies written in turn; the one with the higher current LSN
//! is the latest. Each holds a header (the page sizes and the log's
//! version: 1.1 up to Windows 7, 2.0 from Windows 8) and a **restart
//! area**: the current LSN, whether the volume was cleanly dismounted, the
//! file size, the number of sequence number bits, the record header length
//! and the offset of record data in a page, then the **client records**.
//! NTFS is the log's only client (`NTFS`); its record holds the oldest LSN
//! it still needs and the LSN of its latest restart record.
//!
//! **Log record pages** (`RCRD`) follow. The rest of the file is a
//! **circular buffer**, written page after page and wrapping back to its
//! start. Before it come buffer pages that keep copies of the last pages
//! written: two tail pages in version 1.1, 32 fast pages from version 2.0.
//! A page's header records the highest LSN in it, the LSN of the last
//! record ending in it and where its free space starts; its update
//! sequence array follows, then records from the log page data offset.
//!
//! A **log sequence number** (LSN) is a record's address. Its low bits are
//! its byte offset in the file in 8-byte units; its high bits, as many as
//! the restart area's *sequence number bits* (sized so that the offset
//! bits cover the file size), count the passes over the circular buffer.
//! So `offset = (lsn << bits) >> (bits - 3)`, and LSNs keep growing as the
//! buffer wraps. A record header starts with its own LSN, which therefore
//! names the place it is read from: that is how every record is found here,
//! in every version of every page, whether or not the records before it
//! survive.
//!
//! A **log record** has a 48-byte header: its LSN, the client's previous
//! LSN (the record before it in the same transaction) and undo-next LSN
//! (the next one to undo when rolling back), the length of its client
//! data, the client, the record type, the transaction id and flags. Client
//! data longer than the rest of its page continues in the next pages, from
//! their data offset.
//!
//! NTFS writes two record types. A **checkpoint** (a client restart area)
//! records where recovery would start and the LSNs of its copies of the
//! open attribute, attribute name, dirty page and transaction tables, and
//! the cluster size. An **update** starts with a 32-byte header: the redo
//! and undo operations ([`Operation`]), the offset and length of the redo
//! and undo data, the target attribute (an offset in the open attribute
//! table), the record and attribute offsets of the change, the target's VCN
//! and block offset and size, then the LCNs of the clusters changed.
//!
//! Operations on MFT file records name their record by its place in
//! `$MFT`: record number = (VCN × cluster size + block offset × 512) /
//! record size. Operations on non-resident attributes name an entry of the
//! open attribute table, which the log rebuilds from its
//! `OpenNonresidentAttribute` records and its checkpoints' table copies.
//!
//! # What is decoded
//!
//! Each [`Update`] has its operations, data, target and the MFT record
//! number where it can be worked out, and what its data says about files:
//! [`FileName`]s from new file records, new attributes and directory index
//! entries added (its redo data), or deleted (its undo data); and
//! [`StandardTimes`] written over `$STANDARD_INFORMATION`, new (redo) and
//! old (undo).

mod attributes;
mod bytes;
mod content;
mod fixup;
mod layout;
mod operation;
mod pages;
mod problem;
mod record;
mod restart;
mod targets;
mod text;
mod time;
mod walk;

pub use attributes::OpenAttribute;
pub use content::{FileName, Namespace, Reference, StandardTimes};
pub use operation::Operation;
pub use problem::{Problem, ProblemKind};
pub use record::{Body, Checkpoint, ClientId, LogRecord, TableDump, Update};
pub use restart::{Client, RestartArea, RestartPage, Version};
pub use time::Filetime;

use layout::Layout;
use pages::Pages;

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// What the caller knows about the volume, when the log doesn't say.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Options {
    /// The volume's cluster size, from its boot sector: used instead of the
    /// one the log's checkpoints record, when a power of two from 512 bytes
    /// to 2 MiB.
    pub cluster_size: Option<u32>,
    /// The size of the volume's MFT file records, for updates that don't
    /// record it (1 KiB by default).
    pub record_size: Option<u32>,
}

/// Where the cluster size used came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeSource {
    /// [`Options::cluster_size`].
    Caller,
    /// A checkpoint record (the latest that records it).
    Checkpoint,
    /// Nothing recorded it: the smallest size, 4 KiB at least, that holds
    /// every file record the updates place in a cluster.
    Inferred,
}

/// A `$LogFile`'s contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogFile {
    /// The restart pages that could be read, in file order: the first copy
    /// and the second. See [`LogFile::restart`] for the latest.
    pub restart_pages: Vec<RestartPage>,
    /// Every record that could be read, in LSN order.
    pub records: Vec<LogRecord>,
    /// The cluster size updates were placed with.
    pub cluster_size: u32,
    /// Where it came from.
    pub cluster_size_source: SizeSource,
    /// What couldn't be read, in file order.
    pub problems: Vec<Problem>,
}

impl LogFile {
    /// The latest restart page: the one with the higher current LSN.
    #[must_use]
    pub fn restart(&self) -> Option<&RestartPage> {
        latest(self.restart_pages.iter(), |page| page.area.current_lsn)
    }

    /// Whether the log has never been written (all `0xFF`, as a newly
    /// formatted volume's is): no restart page, no record and no problem.
    #[must_use]
    pub fn is_unused(&self) -> bool {
        self.restart_pages.is_empty() && self.records.is_empty() && self.problems.is_empty()
    }
}

/// Read a `$LogFile` held in memory, with what the log itself says about
/// the volume.
///
/// ```
/// let log = ntfslog::parse(&[0xFF; 65536]);
/// assert!(log.is_unused());
/// ```
#[must_use]
pub fn parse(data: &[u8]) -> LogFile {
    parse_with(data, &Options::default())
}

/// Read a `$LogFile` held in memory, with what the caller knows about the
/// volume.
///
/// ```
/// let options = ntfslog::Options { cluster_size: Some(4096), record_size: Some(1024) };
/// let log = ntfslog::parse_with(&[0xFF; 65536], &options);
/// assert_eq!(log.cluster_size_source, ntfslog::SizeSource::Caller);
/// ```
#[must_use]
pub fn parse_with(data: &[u8], options: &Options) -> LogFile {
    let mut problems = Vec::new();
    let restart_pages = restart::read(data, &mut problems);
    let usable = restart_pages
        .iter()
        .filter_map(|page| Some((page, Layout::from_restart(page, data.len())?)));
    let latest = latest(usable, |(page, _)| page.area.current_lsn).map(|(_, layout)| layout);
    let layout = latest.unwrap_or_else(|| {
        if !restart_pages.is_empty() || !problems.is_empty() {
            problems.push(Problem {
                offset: 0,
                kind: ProblemKind::NoRestartPage,
            });
        }
        Layout::assumed(data.len())
    });
    let pages = Pages::read(data, &layout, &mut problems);
    let mut records: Vec<LogRecord> = walk::find(&pages, &layout, &mut problems)
        .into_iter()
        .map(record::decode)
        .collect();
    let (cluster_size, cluster_size_source) = targets::cluster_size(&records, options);
    targets::complete(&mut records, cluster_size, options);
    problems.sort_by_key(|problem| problem.offset);
    LogFile {
        restart_pages,
        records,
        cluster_size,
        cluster_size_source,
        problems,
    }
}

/// The item with the highest `lsn`; the first on a tie.
fn latest<T>(items: impl Iterator<Item = T>, lsn: impl Fn(&T) -> u64) -> Option<T> {
    items.reduce(|latest, item| {
        if lsn(&item) > lsn(&latest) {
            item
        } else {
            latest
        }
    })
}
