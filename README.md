# ntfslog

The NTFS transaction journal (`$LogFile`) as KAPE, Velociraptor and forensic images give it: every change NTFS was about to make to the volume, with how to redo and undo it, for the last minutes or hours of activity. Files created, renamed and deleted, and timestamps rewritten, are all in it, often after the MFT and the USN journal have moved on. One dependency, its sibling `sootmark-common` (times, UTF-16).

```toml
[dependencies]
sootmark-ntfslog = "0.1"
```

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
}
for problem in &log.problems {
    eprintln!("{problem}");
}
```

## What you get

- `parse(bytes)` reads a whole `$LogFile` in memory and never fails: what can't be read is a `Problem` with its offset, and everything around it is still read. `parse_with` takes the volume's cluster and file record sizes when the caller knows them. No file I/O: it builds for `wasm32`.
- **Restart pages** (`RSTR`, `CHKD`): both copies, and the latest. The log's version (1.1 up to Windows 7, 2.0 from Windows 8), page sizes, current LSN, whether the volume was cleanly dismounted, the file size, sequence number bits, and the client records (`NTFS`: its oldest and restart LSNs).
- **Every log record that can be read**, in LSN order: LSN, previous LSN, undo-next LSN, client, transaction id and flags, with its client data assembled across pages and round the circular buffer. A record header's LSN names its own place in the file, so every page is searched for headers rather than following one record to the next: records are read from whatever survives, including the copies of the last pages written (tail pages in 1.1, fast pages in 2.0), copies left over from earlier passes, and in-place pages a newer copy replaces. A record continued in a page from another pass is cut short and reported, never filled with someone else's bytes.
- **Updates**: redo and undo operations with their names (`InitializeFileRecordSegment`, `DeleteIndexEntryAllocation`, `UpdateResidentValue`, … and the code of any other), redo and undo data with their declared lengths, target attribute, record and attribute offsets, target VCN, block offset and size, LCNs; the **MFT record number** of operations on file records (VCN × cluster size + block offset × 512, over the record size), the offset in the target, and for operations on non-resident attributes the **open attribute** (file reference, attribute type, name), from the log's `OpenNonresidentAttribute` records and its checkpoints' table copies. The cluster size comes from the caller, else the latest checkpoint, else is inferred.
- **Checkpoints** (the NTFS client's restart area): version, start LSN, where the copies of the open attribute, attribute name, dirty page and transaction tables are, and the cluster size.
- **What updates say about files.** `$FILE_NAME`s (name, namespace, parent reference, the file's reference when the data has it, times, sizes, attributes) from new file records (`InitializeFileRecordSegment`), new attributes (`CreateAttribute`) and directory entries added (`AddIndexEntry*`), as `redo_names`; and the same taken away, as `undo_names`: deleted directory entries (`DeleteIndexEntry*`), deleted name attributes (renames) and freed file records (`DeallocateFileRecordSegment`, whose undo is the whole old record). `$STANDARD_INFORMATION` timestamps, new (`redo_times`) and old (`undo_times`), from `UpdateResidentValue` updates that land on them and from new file records. Invalid UTF-16 in a name is escaped, never replaced.

## How it's checked

Against [dfir_ntfs](https://github.com/msuhanov/dfir_ntfs) (commit `ec3ae08`), run as an oracle only (it is GPL-3.0; nothing of it is in this crate). `tests/oracle/` has the script that dumps its reading and the commands that rebuild everything. For every record it reads, every field is compared: LSNs, client, transaction, operations, target attribute, VCN, MFT record number, offset in target, LCNs, open attribute, and the length and SHA-1 of the redo and undo data; for checkpoints, version, start LSN, the tables' LSNs and lengths, and the cluster size.

- go-ntfs's test volume (Apache-2.0, `tests/fixtures/go-ntfs/`, a version 1.1 log): all 2127 records dfir_ntfs reads (2111 updates, 16 checkpoints) match, field for field. Two more are read here: the first records of a page whose tail copy holds the next pass's first records; dfir_ntfs reads the page from the copy only.
- The same volume's `$MFT`: the 26 names its new file records carry are in the MFT records they name, every `$STANDARD_INFORMATION` update decoded lands on that attribute, and the last timestamps the log writes for each of the 31 records it touches are the ones the MFT holds. The renames and the deletion the volume's history went through are read back.
- dfVFS's NTFS test volume (Apache-2.0, `tests/fixtures/dfvfs/`): a log never written, all `0xFF`.
- dfir_ntfs's own test logs (GPL, compared locally, never committed):

  | log | dfir_ntfs reads | same here | differ | extra here |
  |---|---|---|---|---|
  | `LogFile_7.bin` (1.1) | 778 | 777 | 1 | 1 |
  | `LogFile_10.bin` (2.0) | 280 | 280 | 0 | 255 |
  | `LogFile_10_large.bin` (2.0) | 404 | 403 | 1 | 1 |
  | `LogFile_10_downgraded.bin` (1.1) | 271 | 271 | 0 | 12 |
  | `LogFile_empty.bin` | 0 | 0 | 0 | 0 |

  None is missed. The two that differ are records continued past the end of these excerpts (cut from larger logs), in a page whose only copy is a buffer page: dfir_ntfs wraps at the excerpt's end and appends an unrelated page; here the copy is used (in `LogFile_7.bin` it completes `$STANDARD_INFORMATION` times that sit next to the old ones they replace). The extras are records no chain of LSNs leads dfir_ntfs to (the oldest of the circular area, and those earlier on a page than any it starts from) and records in page versions it doesn't read: copies of pages from earlier passes left in the fast pages, and in-place pages it replaces with a newer copy.
- Logs built byte by byte: restart areas, records spanning pages and wrapping round the circular buffer, fast and tail pages, a continuation overwritten by a later pass, a torn page, no restart page, checkpoints, file records, attributes, index entries, timestamp updates and the open attribute table.
- Property tests: arbitrary bytes, a restart page followed by arbitrary bytes, and real and built logs damaged and cut anywhere never panic, and records stay in strict LSN order.

## Not done

- No replay: records aren't applied to rebuild MFT records, and names come with their parent's reference, not a path (join with the MFT for that).
- Data decoded for names and timestamps only. `UpdateFileNameRoot`/`Allocation` (times and sizes in directory entries), non-resident data (`UpdateNonresidentValue`, such as index buffers and `$UsnJrnl` pages), the dirty page and transaction table copies, and the rest of `$STANDARD_INFORMATION` (attributes, owner, security id, USN) are kept as bytes.
- `$STANDARD_INFORMATION` updates are recognised by place (the first attribute of a file record, the timestamps' offsets) and by plausible times (1980 to 2200), not by an attribute type, which `UpdateResidentValue` doesn't carry.
- A torn page is skipped whole; the sectors before the tear aren't salvaged. Pages protected by a CRC instead of an update sequence array (DAX volumes) aren't read.
- Only 4 KiB log pages have been checked against real logs; other sizes are read the same way.
- Header flags other than "continues on the next page" (`0x2`, `0x4`) are kept as found: their meaning isn't settled.

## Licence

MIT or Apache-2.0, at your option. The test volumes' files are go-ntfs's and dfVFS's, under the Apache licence 2.0.
