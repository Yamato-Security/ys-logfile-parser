# ys-logfile-parser

Yamato Security's maintained fork of [sootmark-ntfslog](https://github.com/Sootmark/ntfslog), the
NTFS transaction journal (`$LogFile`) parser for [Juntei](https://github.com/Yamato-Security/juntei).
The upstream history and the MIT OR Apache-2.0 license are kept.

`$LogFile` holds what NTFS was about to change on a volume, and how to undo it, for the last minutes
or hours of activity: files and directories created, renamed and deleted, attributes added and
removed, timestamps rewritten, directory entries updated, and the USN journal records written, often
after the `$MFT` and the USN journal have moved on. Its undo data is the earlier state: the names
before a rename, the timestamps before timestomping.

```rust
let log = ntfslog::parse(&std::fs::read("$LogFile")?);
for record in &log.records {
    let Some(update) = record.update() else { continue };
    for name in &update.redo_names {
        println!("{} {}: {} added in {}", record.lsn, update.redo, name.name, name.parent);
    }
    for name in &update.undo_names {
        println!("{} {}: {} removed from {}", record.lsn, update.redo, name.name, name.parent);
    }
    if let Some(write) = update.journal_write() {
        println!("{} USN records at {} in $J", record.lsn, write.offset);
    }
}
for problem in &log.problems {
    eprintln!("{problem}");
}
```

Use it from Cargo by commit. The crate is `ys-logfile-parser`, named after the repository, and its
library keeps the name `ntfslog`. It is not published, and its versions are the fork's own: 1.0.0
since the fork.

```toml
[dependencies]
ntfslog = { package = "ys-logfile-parser", git = "https://github.com/Yamato-Security/ys-logfile-parser" }
```

## Why sootmark-ntfslog

The `$LogFile` readers were run on the six real logs of the
[DFIR Artifact Museum](https://github.com/AndrewRathbun/DFIRArtifactMuseum) (Windows Server 2012 R2
and 2022, Windows 10 and 11: 2,120,167 records), against dfir_ntfs and a second, independent parser,
which agree with each other on the records both read:

| Reader | Records the oracles read | Notes |
| --- | --- | --- |
| **sootmark-ntfslog 0.1.0** (Rust) | every one, field for field, and 1,637 older ones | records across pages and round the circular area, every page version, buffer pages; 0.1 s per 64 MiB log |
| ntfs-core 0.9.8 (Rust) | 2,054,419 (65,748 missed: records continued on the next page) | one page at a time, no client data; its USN extractor finds 54,992 USN records where 129,987 are found here |
| dfir_ntfs (Python, GPL-3.0) | oracle | run as a black box only: none of its code is here |
| a second, independent parser | oracle | its open attribute resolution by stretch of the log is the model for this fork's |

Other `$LogFile` tools informed the work as references: Joakim Schicht's
[LogFileParser](https://github.com/jschicht/LogFileParser) (MIT, AutoIt: transactions decoded in
detail, and the `$UsnJrnl` records written in `$LogFile`), Stroz Friedberg's
[ntfs-linker](https://github.com/strozfriedberg/ntfs-linker) (LGPL-3.0, C++: `$LogFile`, `$UsnJrnl` and
`$MFT` linked into one history), and ANJP (Advanced NTFS Journal Parser, `$LogFile` and `$UsnJrnl`;
a Windows GUI, not run). None of their code is here.

## What the fork adds and fixes

| Change | Source |
| --- | --- |
| No dependencies: sootmark-common's byte reader and UTF-16 decoding are part of the crate; times are `Filetime`s (the raw FILETIME), as in ys-usn-journal-parser | fork |
| Open attributes resolved by stretch of the log: a mount starts a new table, records written before the one that opened their attribute survives take it, `target_inferred` marks a target from another stretch; every update with a target gets it (`$MFT`'s `$DATA` for file record operations) | fork; the second parser's approach |
| A mount no longer leaves updates with a stale target (another file's attribute, or one entry's file with another's name: 24,511 records of one Museum log) | fork (found in review) |
| `Update::redo_decoded` / `undo_decoded`: file records (a new record whole; a freed record's header), attribute records, index entries (`$FILE_NAME` keys, view indexes told apart) and the times, sizes and attributes directory entries keep (`UpdateFileName*`) | fork |
| `StandardInformation` with attributes, owner and security ids, quota and USN; `FileName::reparse_value` | fork |
| `$STANDARD_INFORMATION` timestamps written from the middle of one (NTFS logs only the bytes that change) are decoded | fork (found in review) |
| `Update::journal_write`: the USN records written to `$UsnJrnl:$J`, with their offset, including those the journal no longer has | idea of LogFileParser and ntfs-core; written afresh |
| `LogRecord::transaction_first_lsn` | fork |
| Tests on a real Windows 11 log (a 1 MiB excerpt), and damaged real logs | fork |

## What you get

- `parse(bytes)` reads a whole `$LogFile` in memory and never fails: what can't be read is a
  `Problem` with its offset, and everything around it is still read. `parse_with` takes the volume's
  cluster and file record sizes when the caller knows them. No file I/O: it builds for `wasm32`.
- **Restart pages** (`RSTR`, `CHKD`): both copies, and the latest. The log's version (1.1 up to
  Windows 7, 2.0 from Windows 8), page sizes, current LSN, whether the volume was cleanly dismounted,
  the file size, sequence number bits, and the client records (`NTFS`: its oldest and restart LSNs).
- **Every log record that can be read**, in LSN order: LSN, previous LSN, undo-next LSN, client,
  transaction id and the LSN of its transaction's first record, flags, with its client data
  assembled across pages and round the circular buffer. A record header's LSN names its own place in
  the file, so every page is searched for headers rather than following one record to the next:
  records are read from whatever survives, including the copies of the last pages written (tail
  pages in 1.1, fast pages in 2.0), copies left over from earlier passes, and in-place pages a newer
  copy replaces. A record continued in a page from another pass is cut short and reported, never
  filled with someone else's bytes.
- **Updates**: redo and undo operations with their names (`InitializeFileRecordSegment`,
  `DeleteIndexEntryAllocation`, `UpdateResidentValue`, … and the code of any other), redo and undo
  data with their declared lengths, target attribute, record and attribute offsets, target VCN,
  block offset and size, LCNs; the **MFT record number** of operations on file records (VCN ×
  cluster size + block offset × 512, over the record size), the offset in the target, and the **open
  attribute** (file reference, attribute type, name) from the log's `OpenNonresidentAttribute`
  records and its checkpoints' table copies. The cluster size comes from the caller, else the latest
  checkpoint, else is inferred.
- **What the data is** (`Decoded`): a `FileRecord` (number, sequence number, flags, base record,
  attributes), an `Attribute` (type, name, form, flags, size, decoded `$STANDARD_INFORMATION` and
  `$FILE_NAME`), an `IndexEntry` (the `$FILE_NAME` key of a directory entry and the file it points
  to), or `DuplicatedInformation` (a directory entry's times, sizes and attributes), for the redo
  side (what is written) and the undo side (what was there).
- **What updates say about files**, in short: `$FILE_NAME`s given (`redo_names`: new file records,
  new name attributes, directory entries added) and taken away (`undo_names`: directory entries
  deleted, renames); `$STANDARD_INFORMATION` timestamps written, new (`redo_times`) and old
  (`undo_times`), including timestamp changes by `UpdateResidentValue`. Invalid UTF-16 in a name is
  escaped, never replaced.
- **USN journal writes** (`Update::journal_write`): the bytes written to `$UsnJrnl:$J` and their
  offset. They are whole USN records in the journal's layout, to parse with a USN record parser such
  as ys-usn-journal-parser.
- **Checkpoints** (the NTFS client's restart area): version, start LSN, where the copies of the open
  attribute, attribute name, dirty page and transaction tables are, and the cluster size.

## How it's checked

- **The six Museum logs** (2,120,167 records the second parser reads, 2,119,728 dfir_ntfs reads):
  every record either oracle reads is read here, with the same LSNs, client, transaction,
  operations, offsets, lengths, VCN, LCNs and data, and 1,637 more from older passes. Where they
  differ, the oracle is wrong:
  - four records in pages from another pass: both oracles fill them with other records' bytes (an
    undo operation `3411`, a target attribute of 0); here they are cut short or read from their own
    pass's copy;
  - targets: the open attributes and the `target_inferred` flags equal the second parser's, except
    two directory index attributes it leaves unnamed (`$I30` here); dfir_ntfs keeps a table across a
    mount (24,511 records) and names no target for records before their attribute is opened.
- **Decoded data**, against the second parser on the same logs (the four records above aside):
  every file record, attribute, directory entry and timestamp update gives the same record and
  sequence numbers, name, parent, four timestamps, size, file attributes and attribute type.
- **USN journal writes**, against the `$J` collected with the same logs: every one of the 129,987
  USN records written carries the USN of its offset; the 113,113 that `$J` still has are
  byte-identical, and 16,874 newer ones are only in `$LogFile`.
- **In the repository**: dfir_ntfs's reading of go-ntfs's test volume (Apache-2.0, a version 1.1
  log, field for field), of dfVFS's unused log, and of the first 1 MiB of the Museum's Windows 11 log
  (MIT, a version 2.0 log); go-ntfs's `$MFT` against the names and timestamps its log writes; logs
  built byte by byte (records spanning pages and wrapping round the circular area, fast and tail
  pages, torn pages, mounts, open attribute tables, file records, attributes, index entries,
  timestamp updates, USN journal writes); property tests on arbitrary bytes and damaged real logs.
  `tests/oracle/` has the script and commands that rebuild the oracle files.
- dfir_ntfs's own test logs (GPL, compared locally, never committed) read as upstream documented:
  none missed, two records cut at those excerpts' ends read from their buffer page copy.
- 600 damaged copies of the Museum logs (bytes and ranges overwritten, cut short): no panic, LSNs
  always in order.

## Not done

- No replay: records aren't applied to rebuild MFT records, and names come with their parent's
  reference, not a path (join with the `$MFT` for that).
- Non-resident data is decoded only for the USN journal: other `UpdateNonresidentValue` data (such
  as index buffers), the dirty page and transaction table copies, and `UpdateMappingPairs` and
  `SetNewAttributeSizes` data are kept as bytes.
- Known non-directory index targets suppress filename decoding. When the target cannot be
  resolved, an index key is interpreted from its layout alone; corroborate those names with the
  target, raw bytes, and other artifacts.
- `$STANDARD_INFORMATION` updates are recognised by place (the first attribute of a file record,
  the timestamps' offsets) and by plausible times (1980 to 2200), not by an attribute type, which
  `UpdateResidentValue` doesn't carry.
- A torn page is skipped whole; the sectors before the tear aren't salvaged. Pages protected by a
  CRC instead of an update sequence array (DAX volumes) aren't read.
- Only 4 KiB log pages have been checked against real logs; other sizes are read the same way.
- Header flags other than "continues on the next page" (`0x2`, `0x4`) are kept as found: their
  meaning isn't settled.

## License

MIT or Apache-2.0, at your option (`LICENSE-MIT`, `LICENSE-APACHE`). The test files are go-ntfs's and
dfVFS's, under the Apache License 2.0, and the DFIR Artifact Museum's, under the MIT License: see
the `LICENSE` and `NOTICE` beside each.
