#!/bin/sh
# Rebuilds the oracle files in this directory, and checks the fixtures, from
# the upstream test images (Apache-2.0). Runs on Debian with
#   apt-get install sleuthkit curl python3-venv git
# and dfir_ntfs (GPL-3.0, run as an oracle only) in a virtual environment:
#   python3 -m venv venv
#   venv/bin/pip install git+https://github.com/msuhanov/dfir_ntfs@ec3ae0884048ade106c91a68dab7c9fb3af393bf
# Usage: PYTHON=venv/bin/python tests/oracle/regenerate.sh
# The Sleuth Kit 4.12.1 (`icat`) and Python 3.13 wrote the committed files.
set -eu

GO_NTFS_COMMIT=20cc4d33923d64fcb39c03438568ddfa26bf416b
DFVFS_COMMIT=917cefc9426d6ded2687d2b55164ded25b44fcb7
PYTHON=${PYTHON:-python3}
here=$(cd "$(dirname "$0")" && pwd)
fixtures="$here/../fixtures"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

curl -fsSL -o "$work/go-ntfs.dd" \
    "https://raw.githubusercontent.com/Velocidex/go-ntfs/$GO_NTFS_COMMIT/parser/test_data/test.ntfs.dd"
curl -fsSL -o "$work/dfvfs.raw" \
    "https://raw.githubusercontent.com/log2timeline/dfvfs/$DFVFS_COMMIT/test_data/ntfs.raw"

# Both images are bare NTFS volumes: $MFT is MFT entry 0, $LogFile entry 2.
for source in go-ntfs dfvfs; do
    image=$(ls "$work/$source".*)
    icat "$image" 2 > "$work/$source.LogFile"
    icat "$image" 0 > "$work/$source.MFT"
    gzip -dc "$fixtures/$source/LogFile.gz" | cmp - "$work/$source.LogFile"
    gzip -dc "$fixtures/$source/MFT.gz" | cmp - "$work/$source.MFT"
    "$PYTHON" -I "$here/dump.py" "$work/$source.LogFile" > "$here/$source.tsv"
done
