# Changelog

## 1.0.0 (Unreleased)

First version of Yamato Security's fork, based on sootmark-ntfslog 0.1.0 (Sootmark/ntfslog b885856).

### Changed
- The crate is named after its repository, `ys-logfile-parser` (its library is still `ntfslog`:
  depend on it as `ntfslog = { package = "ys-logfile-parser", … }`), version 1.0.0, by Florian
  Amette and Zach Mathis (@yamatosecurity), on Rust's 2024 edition, and requires Rust 1.99.
  (@YamatoSecurity)
- No dependencies: the byte reader, UTF-16 decoding and times from `sootmark-common` are part of
  the crate. Times are `Filetime`s (the raw FILETIME, formatted as ISO 8601 with 100 ns), as in
  ys-usn-journal-parser. (@YamatoSecurity)
