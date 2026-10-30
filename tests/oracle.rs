//! The `$LogFile`s of go-ntfs's and dfVFS's test volumes (Apache-2.0,
//! `tests/fixtures/`, stored gzip-compressed), against `dfir_ntfs`: every
//! record it reads, every field it gives (`tests/oracle/`, written by
//! `tests/oracle/regenerate.sh`). `dfir_ntfs` is GPL-3.0 and only ever run,
//! as an oracle, to write those files.
//!
//! The ignored test compares any other logs the same way, with their
//! oracle files beside them: `NTFSLOG_ORACLE_DIR=dir cargo test --
//! --ignored --nocapture` reads each `dir/NAME.bin` with `dir/NAME.tsv` and
//! prints how they compare.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::Path;

use ntfslog::{Body, LogFile, Update, parse};
use sha1_smol::Sha1;

fn manifest(path: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn gunzip(path: &str) -> Vec<u8> {
    let compressed = fs::read(manifest(path)).unwrap();
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(compressed.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}

/// The columns dump.py writes for each record, by LSN.
type Lines = BTreeMap<u64, Vec<String>>;

fn oracle(tsv: &str) -> Lines {
    tsv.lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            // dfir_ntfs writes an unnamed attribute's name as "" or "None"
            // (when from a table copy): both are an empty name here.
            let columns: Vec<String> = line
                .split('\t')
                .map(|column| if column == "None" { "" } else { column }.to_owned())
                .collect();
            (columns[1].parse().unwrap(), columns)
        })
        .collect()
}

fn dash(value: Option<impl ToString>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| value.to_string())
}

fn digest(data: &[u8]) -> [String; 2] {
    [
        data.len().to_string(),
        Sha1::from(data).digest().to_string(),
    ]
}

fn update_columns(update: &Update) -> Vec<String> {
    let lcns: Vec<String> = update.lcns.iter().map(ToString::to_string).collect();
    // dfir_ntfs names the open attribute of operations on non-resident
    // attributes only.
    let target = update
        .target
        .as_ref()
        .filter(|_| update.redo.targets_nonresident() || update.undo.targets_nonresident());
    let mut columns = vec![
        update.redo.code().to_string(),
        update.undo.code().to_string(),
        update.target_attribute.to_string(),
        update.target_vcn.to_string(),
        dash(update.mft_record),
        dash(update.offset_in_target),
        if lcns.is_empty() {
            "-".to_owned()
        } else {
            lcns.join(",")
        },
        dash(target.map(|t| t.file.raw())),
        dash(target.map(|t| t.name.clone().unwrap_or_default())),
    ];
    columns.extend(digest(&update.redo_data));
    columns.extend(digest(&update.undo_data));
    columns
}

/// The same columns, from this crate.
fn ours(log: &LogFile) -> Lines {
    log.records
        .iter()
        .filter_map(|record| {
            let columns = match &record.body {
                Body::Update(update) => {
                    let client =
                        u32::from(record.client.sequence) | u32::from(record.client.index) << 16;
                    let mut columns = vec![
                        "U".to_owned(),
                        record.lsn.to_string(),
                        record.previous_lsn.to_string(),
                        record.undo_next_lsn.to_string(),
                        client.to_string(),
                        record.transaction_id.to_string(),
                    ];
                    columns.extend(update_columns(update));
                    columns
                }
                Body::Checkpoint(checkpoint) => {
                    let mut columns = vec![
                        "C".to_owned(),
                        record.lsn.to_string(),
                        format!("{}.{}", checkpoint.major_version, checkpoint.minor_version),
                        checkpoint.start_lsn.to_string(),
                    ];
                    for table in [
                        checkpoint.open_attribute_table,
                        checkpoint.attribute_names,
                        checkpoint.dirty_page_table,
                        checkpoint.transaction_table,
                    ] {
                        columns.extend([table.lsn.to_string(), table.length.to_string()]);
                    }
                    columns.push(dash(checkpoint.bytes_per_cluster));
                    columns
                }
                Body::Other { .. } => return None,
            };
            Some((record.lsn, columns))
        })
        .collect()
}

/// A column that differs: its index, ours, then the oracle's.
type Difference = (usize, String, String);

/// How this crate's records compare with the oracle's.
#[derive(Debug, Default)]
struct Comparison {
    /// Records the oracle reads, as it reads them.
    same: usize,
    /// Records the oracle reads differently, by LSN.
    differ: Vec<(u64, Vec<Difference>)>,
    /// Records only the oracle reads.
    missing: Vec<u64>,
    /// Records only this crate reads.
    extra: Vec<u64>,
}

fn compare(log: &LogFile, tsv: &str) -> Comparison {
    let (ours, theirs) = (ours(log), oracle(tsv));
    let mut comparison = Comparison::default();
    for (lsn, expected) in &theirs {
        let Some(found) = ours.get(lsn) else {
            comparison.missing.push(*lsn);
            continue;
        };
        let differ: Vec<_> = found
            .iter()
            .zip(expected)
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(column, (a, b))| (column, a.clone(), b.clone()))
            .collect();
        if differ.is_empty() && found.len() == expected.len() {
            comparison.same += 1;
        } else {
            comparison.differ.push((*lsn, differ));
        }
    }
    comparison.extra = ours
        .keys()
        .filter(|lsn| !theirs.contains_key(lsn))
        .copied()
        .collect();
    comparison
}

#[test]
fn every_record_as_dfir_ntfs_reads_it() {
    let log = parse(&gunzip("tests/fixtures/go-ntfs/LogFile.gz"));
    let tsv = fs::read_to_string(manifest("tests/oracle/go-ntfs.tsv")).unwrap();
    let comparison = compare(&log, &tsv);
    // 2111 updates and 16 checkpoints.
    assert_eq!(comparison.same, 2127);
    assert!(comparison.differ.is_empty() && comparison.missing.is_empty());
    // Two more: the first records of page 4 in pass 2, where the page's
    // tail copy has pass 3's first records. dfir_ntfs reads the page from
    // that copy only; both versions are read here.
    assert_eq!(comparison.extra, [1_050_632, 1_050_652]);
    let first = log.records.iter().find(|r| r.lsn == 1_050_632).unwrap();
    assert_eq!(first.offset, 4 * 4096 + 64);
}

#[test]
fn a_windows_11_log_as_dfir_ntfs_reads_it() {
    // The first 1 MiB of a 64 MiB log: records cut by the excerpt's end.
    let log = parse(&gunzip("tests/fixtures/museum-win11/LogFile.gz"));
    let tsv = fs::read_to_string(manifest("tests/oracle/museum-win11.tsv")).unwrap();
    let comparison = compare(&log, &tsv);
    assert_eq!(comparison.same, 4409);
    // Open attributes dfir_ntfs doesn't name, for records written before
    // the one that opened theirs survives; and twelve records continued
    // in pages the excerpt has only as fast page copies, where dfir_ntfs
    // wraps at the excerpt's end instead: what is read here for them is
    // what dfir_ntfs reads from the whole 64 MiB log.
    let wrapped = [
        354_268_665,
        354_271_731,
        354_290_672,
        354_301_431,
        354_301_891,
        354_302_457,
        354_302_960,
        354_303_481,
        354_323_307,
        354_323_951,
        354_324_468,
        354_464_240,
    ];
    assert_eq!(comparison.differ.len(), 543);
    for (lsn, columns) in &comparison.differ {
        for (column, _, theirs) in columns {
            assert!(
                wrapped.contains(lsn) || (matches!(column, 13 | 14) && theirs == "-"),
                "{lsn}: column {column} differs"
            );
        }
    }
    // Two records continue past the excerpt's end: dfir_ntfs fills them
    // from another pass; here they are cut short and reported.
    assert_eq!(comparison.missing, [352_452_602, 354_269_687]);
    for lsn in &comparison.missing {
        let record = log.records.iter().find(|r| r.lsn == *lsn).unwrap();
        assert!(matches!(record.body, Body::Other { .. }));
        assert!(log.problems.iter().any(|problem| {
            problem
                .to_string()
                .contains(&format!("record {lsn} cut short"))
        }));
    }
    // Older records, from pages dfir_ntfs doesn't start from.
    assert_eq!(comparison.extra.len(), 690);
    // Every USN record written to the journal carries its own offset.
    let mut journal_records = 0;
    for write in log
        .records
        .iter()
        .filter_map(|r| r.update()?.journal_write())
    {
        let mut at = 0;
        while let Some(header) = write.data.get(at..at + 8) {
            let length = u32::from_le_bytes(header[..4].try_into().unwrap()) as usize;
            let usn = write.data.get(at + 0x18..at + 0x20).unwrap();
            assert_eq!(header[4..6], [2, 0], "version 2 records");
            assert_eq!(
                u64::from_le_bytes(usn.try_into().unwrap()),
                write.offset + at as u64
            );
            journal_records += 1;
            at += length;
        }
    }
    assert_eq!(journal_records, 503);
}

#[test]
fn an_unused_log_as_dfir_ntfs_reads_it() {
    let log = parse(&gunzip("tests/fixtures/dfvfs/LogFile.gz"));
    let tsv = fs::read_to_string(manifest("tests/oracle/dfvfs.tsv")).unwrap();
    let comparison = compare(&log, &tsv);
    assert_eq!(comparison.same, 0);
    assert!(comparison.missing.is_empty() && comparison.extra.is_empty());
    assert!(log.is_unused());
}

#[test]
#[ignore = "needs NTFSLOG_ORACLE_DIR: logs that can't be committed, with their oracle files"]
fn other_logs_as_dfir_ntfs_reads_them() {
    let dir = std::env::var("NTFSLOG_ORACLE_DIR").expect("NTFSLOG_ORACLE_DIR");
    let mut logs: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "bin"))
        .collect();
    logs.sort();
    for path in logs {
        let log = parse(&fs::read(&path).unwrap());
        let tsv = fs::read_to_string(path.with_extension("tsv")).unwrap();
        let c = compare(&log, &tsv);
        let total = c.same + c.differ.len() + c.missing.len();
        println!(
            "{}: dfir_ntfs {total}, ours {}, same {}, differ {}, missing {}, extra {}, problems {}",
            path.file_name().unwrap().to_string_lossy(),
            log.records.len(),
            c.same,
            c.differ.len(),
            c.missing.len(),
            c.extra.len(),
            log.problems.len(),
        );
        // Targets dfir_ntfs leaves unnamed: records before the one that
        // opened their attribute, or in a stretch without one.
        let (unnamed, other): (Vec<_>, Vec<_>) = c.differ.iter().partition(|(_, columns)| {
            columns
                .iter()
                .all(|(column, _, theirs)| matches!(column, 13 | 14) && theirs == "-")
        });
        println!(
            "  differ: {} targets dfir_ntfs doesn't name, {} otherwise",
            unnamed.len(),
            other.len()
        );
        for (lsn, columns) in other.iter().take(10) {
            println!("  differs {lsn}: {columns:?}");
        }
        println!("  missing {:?}", &c.missing[..c.missing.len().min(10)]);
        let mut pages: BTreeMap<u64, usize> = BTreeMap::new();
        for record in log.records.iter().filter(|r| c.extra.contains(&r.lsn)) {
            *pages.entry(record.offset / 4096).or_default() += 1;
        }
        println!("  extra, by page read from: {pages:?}");
        for problem in log.problems.iter().take(10) {
            println!("  {problem}");
        }
    }
}
