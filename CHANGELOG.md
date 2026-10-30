# Changelog

## 1.0.0 (Unreleased)

First version of Yamato Security's fork, based on sootmark-ntfslog 0.1.0 (Sootmark/ntfslog b885856).

### Added
- `Update::target` for every update that has one: `$MFT`'s `$DATA` for operations on file records,
  the attribute itself for `OpenNonresidentAttribute` records, and updates written before the record
  that opened their attribute survives (the oldest definition in their stretch of the log).
  `Update::target_inferred` marks a target taken from another stretch. (@YamatoSecurity)
- `Update::redo_decoded` and `Update::undo_decoded`: what each side of an update holds, decoded
  (`Decoded`): a `FileRecord` (`InitializeFileRecordSegment`: a new record whole, with its number,
  sequence number, flags, base record and attributes; or a freed record's header, its sequence
  number and flags before `DeallocateFileRecordSegment`), an `Attribute` record
  (`CreateAttribute`, and the undo of `DeleteAttribute`: type, name, form, flags, id, size,
  `$STANDARD_INFORMATION` and `$FILE_NAME` values), an `IndexEntry` (its `$FILE_NAME` key in a
  directory index; none in `$O`, `$Q`, `$R`, `$SDH` and `$SII`) and `DuplicatedInformation` (the
  times, sizes and attributes a directory entry keeps, new and old, from
  `UpdateFileNameRoot`/`Allocation`). `StandardInformation` has the attributes, owner id, security
  id, quota and USN too. `FileName::reparse_value`. (@YamatoSecurity)
- `Update::journal_write`: the bytes an update writes to the USN change journal (`$UsnJrnl:$J`) and
  their offset in it, for recovering records the journal no longer has. (@YamatoSecurity)
- `LogRecord::transaction_first_lsn`: the first record of each record's transaction, by following
  previous LSNs. (@YamatoSecurity)
- Tests on a real Windows 11 log (the first 1 MiB of the DFIR Artifact Museum's RathbunVM
  `$LogFile`, MIT) against dfir_ntfs's reading of it, and damage property tests on it.
  (@YamatoSecurity)

### Changed
- The crate is named after its repository, `ys-logfile-parser` (its library is still `ntfslog`:
  depend on it as `ntfslog = { package = "ys-logfile-parser", … }`), version 1.0.0, by Florian
  Amette and Zach Mathis (@yamatosecurity), on Rust's 2024 edition, and requires Rust 1.99.
  (@YamatoSecurity)
- No dependencies: the byte reader, UTF-16 decoding and times from `sootmark-common` are part of
  the crate. Times are `Filetime`s (the raw FILETIME, formatted as ISO 8601 with 100 ns), as in
  ys-usn-journal-parser. (@YamatoSecurity)
- `OpenAttribute::name` is an `Option`: `None` when the log doesn't say (Windows 7 opens attributes
  without their names), empty for an unnamed attribute. (@YamatoSecurity)

### Fixed
- Known non-directory index targets no longer emit file names when their long keys resemble a
  `$FILE_NAME` value; the generic index header is retained for redo and undo. (@YamatoSecurity)
- Index keys are bounded by the declared entry length and cannot consume a child VCN or the
  following entry; sentinel entries do not emit file names. (@YamatoSecurity)
- A crafted file-record attribute length no longer overflows on 32-bit targets such as wasm32.
  The damaged attribute is skipped while retaining the file-record header. (@YamatoSecurity)
- `$STANDARD_INFORMATION` timestamps written from the middle of one (NTFS logs only the bytes that
  change, so an update can start at byte 1 of a timestamp) were not decoded; the timestamps the
  update covers whole now are. (@YamatoSecurity)
- `$STANDARD_INFORMATION` timestamps outside 1980–2200 in a whole attribute (a new file record or
  attribute) were dropped; only the bytes of an `UpdateResidentValue`, whose attribute isn't
  recorded, are checked for plausibility now. (@YamatoSecurity)
- After a mount, updates took the open attribute table left from before it: a stale attribute, or
  one entry's file with another's name. The table now carries over only within a stretch of the log
  (from one checkpoint without tables to the next, and not across gaps of more than 64 pages).
  (@YamatoSecurity)
