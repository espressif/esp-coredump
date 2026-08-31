#
# SPDX-FileCopyrightText: 2022-2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#

import os
import sys
from types import SimpleNamespace

import rich_click as click
from esp_pylib.cli_types import AnyIntType, BaudRateType, SerialPortType
from esp_pylib.constants import ESP_ROM_BAUD

from esp_coredump import CoreDump, __version__
from esp_coredump.log import log

from .corefile import SUPPORTED_TARGETS
from .corefile.gdb import DEFAULT_GDB_TIMEOUT_SEC

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


def common_options(func):
    """Options shared by every ``espcoredump`` subcommand (mirrors the old argparse parent parser)."""
    options = [
        # TODO: move the --debug option to global args and change to verbose/silent/normal in next major release.
        click.option('--debug', '-d', type=int, default=3, help='Log level (0..4)'),
        click.option('--gdb', '-g', help='Path to gdb'),
        click.option('--extra-gdbinit-file', '-ex', help='Path to additional gdbinit file'),
        click.option('--core', '-c', help='Path to core dump file (if skipped core dump will be read from flash)'),
        click.option(
            '--core-format',
            '-t',
            type=click.Choice(['auto', 'b64', 'elf', 'raw']),
            default='auto',
            help=('File specified with "-c" is an ELF (elf), raw (raw) or base64-encoded (b64) binary. For autodetection based on file header use "auto".'),
        ),
        click.option(
            '--off',
            '-o',
            type=AnyIntType(),
            help='Offset of coredump partition in flash (type "idf.py partition-table" to see).',
        ),
        click.option('--parttable-off', type=AnyIntType(), help='Offset of the partition table in flash.'),
        click.option(
            '--save-core',
            '-s',
            help='Save core to file. Otherwise temporary core file will be deleted. Does not work with "-c"',
        ),
        click.option('--rom-elf', '-r', help='Path to ROM ELF file. Will use "<target>_rom.elf" if not specified'),
        click.argument('prog'),
    ]
    for option in reversed(options):
        func = option(func)
    return func


def _run(ctx, operation, **opts):
    """Build a `CoreDump` from the merged CLI options and run *operation*."""
    debug = opts.pop('debug', 3)
    log.set_log_level(debug)
    # Keep stdout reserved for the core dump report; route diagnostics to stderr.
    log.set_info_stream(sys.stderr)

    kwargs = dict(ctx.obj)
    kwargs.update(opts)
    kwargs = {k: v for k, v in kwargs.items() if v is not None}

    espcoredump = CoreDump(**kwargs)
    temp_core_files = None
    try:
        temp_core_files = getattr(espcoredump, operation)()
    finally:
        if temp_core_files:
            for f in temp_core_files:
                try:
                    os.remove(f)
                except OSError:
                    pass


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(__version__, '--version', message='espcoredump.py v%(version)s')
@click.option(
    '--chip',
    type=click.Choice(['auto'] + SUPPORTED_TARGETS),
    default=os.environ.get('ESPTOOL_CHIP', 'auto'),
    help='Target chip type',
)
@click.option('--chip-rev', type=int, help='Target chip revision')
@click.option('--port', '-p', type=SerialPortType(), default=os.environ.get('ESPTOOL_PORT'), help='Serial port device')
@click.option(
    '--baud',
    '-b',
    type=BaudRateType(),
    default=os.environ.get('ESPTOOL_BAUD', ESP_ROM_BAUD),
    help='Serial port baud rate used when flashing/reading',
)
@click.option(
    '--gdb-timeout-sec',
    type=int,
    default=DEFAULT_GDB_TIMEOUT_SEC,
    help='Overwrite the default internal delay for gdb responses',
)
@click.pass_context
def cli(ctx, chip, chip_rev, port, baud, gdb_timeout_sec):
    """espcoredump.py - ESP32 Core Dump Utility"""
    log.print(f'espcoredump.py v{__version__}')
    ctx.ensure_object(dict)
    ctx.obj.update(
        chip=chip,
        chip_rev=chip_rev,
        port=port,
        baud=baud,
        gdb_timeout_sec=gdb_timeout_sec,
    )


@cli.command('dbg_corefile')
@common_options
@click.pass_context
def dbg_corefile(ctx, **opts):
    """Starts GDB debugging session with specified corefile"""
    _run(ctx, 'dbg_corefile', **opts)


@cli.command('info_corefile')
@common_options
@click.option('--print-mem', '-m', is_flag=True, default=False, help='Print memory dump')
@click.pass_context
def info_corefile(ctx, **opts):
    """Print core dump info from file"""
    _run(ctx, 'info_corefile', **opts)


class _ArgparseCompatParser:
    """argparse-compatible facade over the Click CLI. Backward compatibility with ESP-IDF.

    ESP-IDF's ``components/espcoredump/espcoredump.py`` does::

        from esp_coredump.cli_ext import parser

        args = parser.parse_args()
    """

    def parse_args(self, args=None):
        argv = list(sys.argv[1:] if args is None else args)
        with cli.make_context(cli.name or 'espcoredump', argv) as ctx:
            if not ctx.protected_args:
                raise SystemExit('Error: Missing command.')
            operation = ctx.protected_args[0]
            cmd = cli.get_command(ctx, operation)
            if cmd is None:
                raise SystemExit(f'Error: Unknown command {operation}')
            with cmd.make_context(operation, ctx.args, parent=ctx) as sub_ctx:
                values = {**ctx.params, **sub_ctx.params, 'operation': operation}
        return SimpleNamespace(**values)


parser = _ArgparseCompatParser()
