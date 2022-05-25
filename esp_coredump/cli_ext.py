#
# SPDX-FileCopyrightText: 2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#

import argparse
import os

from pygdbmi.gdbcontroller import DEFAULT_GDB_TIMEOUT_SEC

from esp_coredump import __version__

from .corefile import SUPPORTED_TARGETS

try:
    # esptool>=4.0
    from esptool.loader import ESPLoader
except (AttributeError, ModuleNotFoundError):
    # esptool<4.0
    from esptool import ESPLoader

parser = argparse.ArgumentParser(description='espcoredump.py v%s - ESP32 Core Dump Utility' % __version__)
parser.add_argument('--chip', default=os.environ.get('ESPTOOL_CHIP', 'auto'),
                    choices=['auto'] + SUPPORTED_TARGETS,
                    help='Target chip type')
parser.add_argument('--port', '-p', default=os.environ.get('ESPTOOL_PORT', ESPLoader.DEFAULT_PORT),
                    help='Serial port device')
parser.add_argument('--baud', '-b', type=int,
                    default=os.environ.get('ESPTOOL_BAUD', ESPLoader.ESP_ROM_BAUD),
                    help='Serial port baud rate used when flashing/reading')
parser.add_argument('--gdb-timeout-sec', type=int, default=DEFAULT_GDB_TIMEOUT_SEC,
                    help='Overwrite the default internal delay for gdb responses')

common_args = argparse.ArgumentParser(add_help=False)
common_args.add_argument('--debug', '-d', type=int, default=3,
                         help='Log level (0..3)')
common_args.add_argument('--gdb', '-g',
                         help='Path to gdb')
common_args.add_argument('--extra-gdbinit-file', '-ex',
                         help='Path to additional gdbinit file')
common_args.add_argument('--core', '-c',
                         help='Path to core dump file (if skipped core dump will be read from flash)')
common_args.add_argument('--core-format', '-t', choices=['b64', 'elf', 'raw'], default='elf',
                         help='File specified with "-c" is an ELF ("elf"), '
                              'raw (raw) or base64-encoded (b64) binary')
common_args.add_argument('--off', '-o', type=int,
                         help='Offset of coredump partition in flash (type "make partition_table" to see).')
common_args.add_argument('--save-core', '-s',
                         help='Save core to file. Otherwise temporary core file will be deleted. '
                              'Does not work with "-c"', )
common_args.add_argument('--rom-elf', '-r',
                         help='Path to ROM ELF file. Will use "<target>_rom.elf" if not specified')
common_args.add_argument('prog', help='Path to program\'s ELF binary')

operations = parser.add_subparsers(dest='operation')

operations.add_parser('dbg_corefile', parents=[common_args],
                      help='Starts GDB debugging session with specified corefile')

info_coredump = operations.add_parser('info_corefile', parents=[common_args],
                                      help='Print core dump info from file')
info_coredump.add_argument('--print-mem', '-m', action='store_true',
                           help='Print memory dump')
