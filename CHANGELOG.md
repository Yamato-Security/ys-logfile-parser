# Changelog

## 1.0.0 (Unreleased)

First version of Yamato Security's fork, based on sootmark-ntfslog 0.1.0 (Sootmark/ntfslog b885856).

### Added
- `Update::target` for every update that has one: `$MFT`'s `$DATA` for operations on file records,
  the attribute itself for `OpenNonresidentAttribute` records, and updates written before the record
  that opened their attribute survives (the oldest definition in their stretch of the log).
  `Update::target_inferred` marks a target taken from another stretch. (@YamatoSecurity)
- `LogRecord::transaction_first_lsn`: the first record of each record's transaction, by following
  previous LSNs. (@YamatoSecurity)

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
- After a mount, updates took the open attribute table left from before it: a stale attribute, or
  one entry's file with another's name. The table now carries over only within a stretch of the log
  (from one checkpoint without tables to the next, and not across gaps of more than 64 pages).
  (@YamatoSecurity)
