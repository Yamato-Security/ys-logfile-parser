# Oracle

`dump.py` writes, as TSV, every record [dfir_ntfs](https://github.com/msuhanov/dfir_ntfs)
reads from a `$LogFile`: LSNs, transaction, operations, target, MFT record
number, offset in target, LCNs, open attribute, and the length and SHA-1 of
the redo and undo data. dfir_ntfs is GPL-3.0: it is only run, as an oracle,
never copied into the crate, and its own test data is never committed here.

`tests/oracle.rs` reads the same columns from this crate and compares every
record.

## The committed fixtures

`go-ntfs.tsv` and `dfvfs.tsv` are dfir_ntfs's reading of
`../fixtures/go-ntfs/LogFile.gz` and `../fixtures/dfvfs/LogFile.gz`. To
rebuild them and check the fixtures against the upstream images, on Debian:

```sh
apt-get install sleuthkit curl python3-venv git
python3 -m venv venv
venv/bin/pip install git+https://github.com/msuhanov/dfir_ntfs@ec3ae0884048ade106c91a68dab7c9fb3af393bf
PYTHON=venv/bin/python tests/oracle/regenerate.sh
cargo test --test oracle
```

## dfir_ntfs's own test logs

dfir_ntfs's repository has five `$LogFile`s in `test_data/` (`LogFile_7.bin`,
`LogFile_10.bin`, `LogFile_10_large.bin`, `LogFile_10_downgraded.bin`,
`LogFile_empty.bin`), under the GPL. They are compared locally, never
committed:

```sh
git clone https://github.com/msuhanov/dfir_ntfs dfir_ntfs_src
git -C dfir_ntfs_src checkout ec3ae0884048ade106c91a68dab7c9fb3af393bf
mkdir logs
for log in dfir_ntfs_src/test_data/LogFile_*.bin; do
    name=$(basename "$log" .bin)
    cp "$log" "logs/$name.bin"
    venv/bin/python -I tests/oracle/dump.py "$log" > "logs/$name.tsv"
done
NTFSLOG_ORACLE_DIR=$PWD/logs cargo test --test oracle -- --ignored --nocapture
```
