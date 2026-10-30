#!/usr/bin/env python3
"""Dump every item dfir_ntfs reads from a $LogFile as TSV, for diffing.

Usage: dump.py <$LogFile>  (writes TSV to standard output)

dfir_ntfs (GPL-3.0) is used as an oracle only: imported here, never copied
into the crate. One line per item, in the order dfir_ntfs yields them
(grouped by client, then by LSN). Columns are described by the header line;
"-" stands for a value dfir_ntfs does not compute for the item.

Update records (kind U): LSN, client previous LSN, client undo-next LSN,
client ID, transaction ID, redo and undo operation codes, target attribute,
target VCN, MFT record number, offset in target, LCNs, the open attribute
table's file reference and attribute name for the target, and the length
and SHA-1 of the redo and undo data.

Checkpoints (kind C, an NTFS restart area written to the log): LSN, version,
start-of-checkpoint LSN, the four tables' LSNs and lengths, and bytes per
cluster.
"""

import hashlib
import sys

from dfir_ntfs import LogFile


def dash(value):
    return '-' if value is None else str(value)


def header_of(parser, lsn):
    page_number, offset = parser.lsn_to_offset(lsn)
    page = parser.get_log_record_page_by_number(page_number)
    return page.get_log_record_at_offset(offset, parser.record_header_length)


def data_columns(data):
    return [str(len(data)), hashlib.sha1(data).hexdigest()]


def update_line(parser, record):
    header = header_of(parser, record.lsn)
    try:
        lcns = ','.join(str(lcn) for lcn in record.get_lcns_for_page()) or '-'
    except LogFile.ClientException:
        lcns = 'truncated'
    reference = record.calculate_mft_target_reference_and_name()
    if reference is None:
        reference = (None, None)
    columns = [
        'U', record.lsn, header.get_client_previous_lsn(),
        header.get_client_undo_next_lsn(), header.get_client_id(),
        record.transaction_id, record.get_redo_operation(),
        record.get_undo_operation(), record.get_target_attribute(),
        record.get_target_vcn(), dash(record.calculate_mft_target_number()),
        dash(record.calculate_offset_in_target()), lcns,
        dash(reference[0]), dash(reference[1]),
    ]
    columns += data_columns(record.get_redo_data())
    columns += data_columns(record.get_undo_data())
    return columns


def checkpoint_line(area):
    return [
        'C', area.lsn,
        '{}.{}'.format(area.get_major_version(), area.get_minor_version()),
        area.get_start_of_checkpoint_lsn(),
        area.get_open_attribute_table_lsn(), area.get_open_attribute_table_length(),
        area.get_attribute_names_lsn(), area.get_attribute_names_length(),
        area.get_dirty_page_table_lsn(), area.get_dirty_page_table_length(),
        area.get_transaction_table_lsn(), area.get_transaction_table_length(),
        dash(area.get_bytes_per_cluster()),
    ]


def main(path):
    out = sys.stdout
    out.write('# U lsn previous undo_next client transaction redo undo '
              'target_attribute vcn mft_record offset_in_target lcns '
              'target_reference target_name redo_length redo_sha1 '
              'undo_length undo_sha1\n')
    out.write('# C lsn version checkpoint oat_lsn oat_length names_lsn '
              'names_length dirty_lsn dirty_length transactions_lsn '
              'transactions_length cluster_size\n')
    with open(path, 'rb') as f:
        try:
            parser = LogFile.LogFileParser(f)
        except LogFile.LogFileException as error:
            out.write('# not read: {}\n'.format(type(error).__name__))
            return
        for item in parser.parse_ntfs_records():
            if isinstance(item, LogFile.NTFSLogRecord):
                columns = update_line(parser, item)
            else:
                columns = checkpoint_line(item)
            out.write('\t'.join(str(c) for c in columns) + '\n')


if __name__ == '__main__':
    main(sys.argv[1])
