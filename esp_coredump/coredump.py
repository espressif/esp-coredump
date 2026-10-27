#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2022-2023 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#
# ESP-IDF Core Dump Utility
#
from __future__ import annotations

import os
import re
import subprocess
import sys
import textwrap
from contextlib import contextmanager
from shutil import copyfile, which
from typing import Optional, Tuple  # noqa: F401

import serial

try:
    # esptool>=4.0
    from esptool.cmds import detect_chip
except (AttributeError, ModuleNotFoundError):
    # esptool<4.0
    from esptool import ESPLoader

    detect_chip = ESPLoader.detect_chip

from construct import Container, GreedyRange, Int32ul, Int64sl, ListContainer, Struct  # noqa: F401
from esp_pylib.constants import ESP_ROM_BAUD
from esp_pylib.rom import get_idf_path, get_rom_elf_dir
from esp_pylib.rom import get_rom_elf_path as _pylib_get_rom_elf_path

from esp_coredump.log import log

from .corefile import RISCV_TARGETS, SUPPORTED_TARGETS, XTENSA_TARGETS, riscv, xtensa
from .corefile.elf import (
    TASK_STATUS_CORRECT,
    ElfFile,
    ElfSegment,
    ElfSymbol,
    ESPCoreDumpElfFile,
    EspTaskStatus,
)
from .corefile.gdb import DEFAULT_GDB_TIMEOUT_SEC, EspGDB
from .corefile.loader import (
    ESPCoreDumpFileLoader,
    ESPCoreDumpFlashLoader,
    ESPCoreDumpLoaderError,
    EspCoreDumpVersion,
    get_core_file_format,
)
from .corefile.riscv_trace import parse_riscv_trace_note

MORE_INFO_MSG = 'Read more: https://github.com/espressif/esp-coredump/blob/master/README.md#installation'
GDB_NOT_FOUND_ERROR = f'GDB executable not found. Please install GDB or set up ESP-IDF to complete the action. {MORE_INFO_MSG}'
IDF_SETUP_ERROR = f'Please set up ESP-IDF to complete the action. {MORE_INFO_MSG}'

RETRY_ATTEMPTS = 3

XTENSA_ISR_CTX_IDX = 37
RISCV_ISR_CTX_IDX = 1

PRINT_VAR_FORMATS = 'xduotacfsz'
NOT_IN_CORE_DUMP = '<not in core dump>'
NOT_IN_CORE_DUMP_HINT = 'Some values are not in the core dump. Tag them with COREDUMP_DRAM_ATTR or enable CONFIG_ESP_COREDUMP_CAPTURE_DRAM.'
# IDF places these sections in flash
FLASH_SECTION_PREFIXES = ('.flash.', '.eh_frame')
CANNOT_ACCESS_RE = re.compile(r'^Cannot access memory at address (0x[0-9a-fA-F]+)')
VALUE_CANNOT_ACCESS_RE = re.compile(r'<error: Cannot access memory at address (0x[0-9a-fA-F]+)>')
# COREDUMP_*_ATTR variables are placed between these linker symbols
TAGGED_REGION_RE = re.compile(r'_coredump_(\w+)_(start|end)$')
C_IDENTIFIER_RE = re.compile(r'[A-Za-z_]\w*$')

if os.name == 'nt':
    CLOSE_FDS = False
else:
    CLOSE_FDS = True


class CoreDump:
    def __init__(
        self,
        baud: int | None = int(os.environ.get('ESPTOOL_BAUD', ESP_ROM_BAUD)),
        chip: str = os.environ.get('ESPTOOL_CHIP', 'auto'),
        core_format: str = 'auto',
        port: str | None = os.environ.get('ESPTOOL_PORT'),
        gdb_timeout_sec: int = DEFAULT_GDB_TIMEOUT_SEC,
        core: str | None = None,
        chip_rev: int | None = None,
        gdb: str | None = None,
        extra_gdbinit_file: str | None = None,
        off: int | None = None,
        parttable_off: int | None = None,
        prog: str | None = None,
        print_mem: str | None = None,
        rom_elf: str | None = None,
        save_core: str | None = None,
        print_vars: list[str] | None = None,
        print_all_vars: bool = False,
    ):
        if prog is None:
            raise ValueError("Path to program's ELF binary is not provided")

        self.baud = baud
        self.chip = chip
        self.core = core
        self.chip_rev = chip_rev
        self.core_format = get_core_file_format(core) if core and core_format == 'auto' else core_format
        self.gdb = gdb
        self.gdb_timeout_sec = gdb_timeout_sec
        self.extra_gdbinit_file = extra_gdbinit_file
        self.coredump_off = off
        self.parttable_off = parttable_off
        self.prog = prog
        self.port = port
        self.print_mem = print_mem
        self.print_vars = print_vars
        self.print_all_vars = print_all_vars
        self.rom_elf = rom_elf
        self.save_core = save_core

    @staticmethod
    def load_aux_elf(elf_path):  # type: (str) -> str
        """
        Loads auxiliary ELF file and composes GDB command to read its symbols.
        """
        sym_cmd = ''
        if os.path.exists(elf_path):
            elf = ElfFile(elf_path)
            if os.name == 'nt':
                elf_path = elf_path.replace('\\', '/')
            for s in elf.sections:
                if s.name == '.text':
                    sym_cmd = f'add-symbol-file {elf_path} {s.addr:#x}'
                    break
        return sym_cmd

    def extract_chip_rev_from_elf(self):
        if not os.path.exists(self.core):
            raise FileNotFoundError(f"Provided ELF file {self.core} is not found or doesn't exist")
        elf = ElfFile(elf_path=self.core)
        chip_rev = None
        for s in elf.note_segments:
            for n in s.note_secs:
                if b'ESP_CHIP_REV' in n.name:
                    chip_rev = int.from_bytes(n.desc, 'little')
                    break

        return chip_rev

    def get_core_header_info_dict(self, e_machine=ESPCoreDumpElfFile.EM_XTENSA):
        loader = None  # type: Union[ESPCoreDumpFlashLoader, ESPCoreDumpFileLoader, None]
        core_dump_info_map = {
            'core_elf_path': None,
            'target': None,
            'temp_files': None,
            'chip_rev': None,
        }

        if not self.core:
            # Core file not specified, try to read core dump from flash.
            if not get_idf_path():
                log.die(IDF_SETUP_ERROR)
            loader = ESPCoreDumpFlashLoader(
                self.coredump_off,
                port=self.port,
                baud=self.baud,
                part_table_offset=self.parttable_off,
            )
        elif self.core_format != 'elf':
            # Core file specified, but not yet in ELF format. Convert it from raw or
            # base64 into ELF.
            loader = ESPCoreDumpFileLoader(self.core, self.core_format == 'b64')
        else:
            # Core file is already in the ELF format
            core_dump_info_map['core_elf_path'] = self.core
            chip_rev = self.extract_chip_rev_from_elf()

            if self.chip_rev is not None and chip_rev != self.chip_rev:
                log.die('Provided chip revision does not match the one extracted from the provided coredump elf file.')

            core_dump_info_map['chip_rev'] = chip_rev

        # Load/convert the core file
        if loader:
            loader.create_corefile(exe_name=self.prog, e_machine=e_machine)
            core_dump_info_map['core_elf_path'] = loader.core_elf_file
            if self.save_core:
                # We got asked to save the core file, make a copy
                copyfile(loader.core_elf_file, self.save_core)
            core_dump_info_map['target'] = loader.target
            core_dump_info_map['chip_rev'] = loader.chip_rev
            core_dump_info_map['temp_files'] = loader.temp_files

        return core_dump_info_map

    def get_chip_version(self):  # type: () -> Optional[int]
        for segment in self.core_elf.note_segments:
            for sec in segment.note_secs:
                if sec.type == ESPCoreDumpElfFile.PT_ESP_INFO:
                    ver_bytes = sec.desc[:4]
                    return int((ver_bytes[3] << 8) | ver_bytes[2])
        return None

    def get_target(self):  # type: () -> str
        if self.chip != 'auto':
            return self.chip  # type: ignore

        chip_version = self.get_chip_version()
        if chip_version is not None:
            if chip_version == EspCoreDumpVersion.ESP32:
                return 'esp32'

            if chip_version == EspCoreDumpVersion.ESP32S2:
                return 'esp32s2'

            if chip_version == EspCoreDumpVersion.ESP32S3:
                return 'esp32s3'

            if chip_version == EspCoreDumpVersion.ESP32C3:
                return 'esp32c3'

            if chip_version == EspCoreDumpVersion.ESP32C2:
                return 'esp32c2'

            if chip_version == EspCoreDumpVersion.ESP32C6:
                return 'esp32c6'

            if chip_version == EspCoreDumpVersion.ESP32H2:
                return 'esp32h2'

            if chip_version == EspCoreDumpVersion.ESP32P4:
                return 'esp32p4'

            if chip_version == EspCoreDumpVersion.ESP32C5:
                return 'esp32c5'

            if chip_version == EspCoreDumpVersion.ESP32C61:
                return 'esp32c61'

            if chip_version == EspCoreDumpVersion.ESP32H21:
                return 'esp32h21'

            if chip_version == EspCoreDumpVersion.ESP32H4:
                return 'esp32h4'

            if chip_version == EspCoreDumpVersion.ESP32S31:
                return 'esp32s31'

        target = None
        try:
            inst = detect_chip(self.port, self.baud)
        except serial.serialutil.SerialException:
            log.die(
                'Unable to identify the chip type. '
                'Please use the --chip option to specify the chip type or '
                'connect the board and provide the --port option to have '
                'the chip type determined automatically.'
            )
        else:
            target = inst.CHIP_NAME.lower().replace('-', '')

        return target  # type: ignore

    def get_gdb_path(self, target):  # type: (str) -> Optional[str]
        if self.gdb:
            return self.gdb  # type: ignore

        if target in XTENSA_TARGETS:
            gdb_path = f'xtensa-{target}-elf-gdb'
        elif target in RISCV_TARGETS:
            gdb_path = 'riscv32-esp-elf-gdb'
        else:
            raise ValueError(f'Invalid value: {target}. For now we only support {SUPPORTED_TARGETS}')
        if which(gdb_path) is None:
            return None

        return gdb_path

    def get_gdb_args(self, target, core_elf_path, chip_rev, is_dbg_mode=False):
        gdb_tool = self.get_gdb_path(target)
        if not gdb_tool:
            log.die(GDB_NOT_FOUND_ERROR)

        rom_elf_path = self.get_rom_elf_path(target=target, chip_rev=chip_rev)
        rom_sym_cmd = self.load_aux_elf(rom_elf_path)

        gdb_args = [gdb_tool]

        if self.extra_gdbinit_file:
            if not os.path.isfile(self.extra_gdbinit_file):
                raise ValueError(f'{self.extra_gdbinit_file} does not exist')
            gdb_args.append('-x={}'.format(self.extra_gdbinit_file))
        else:
            gdb_args.append('--nx')  # ignore .gdbinit

        if not is_dbg_mode:
            gdb_args.append('--nw')  # suppress the GUI interface
            gdb_args.append('--quiet')  # inhibit dumping info at start-up
            gdb_args.append('--interpreter=mi2')  # use GDB/MI v2

        gdb_args.append('--core={}'.format(core_elf_path))  # core file
        if rom_sym_cmd:
            gdb_args += ['-ex', rom_sym_cmd]
        gdb_args.append(self.prog)

        return gdb_args

    def get_rom_elf_path(self, chip_rev, target):  # type: (Optional[int], str) -> str
        if self.rom_elf:
            return self.rom_elf

        if chip_rev is None:
            return ''

        if not get_idf_path() or not get_rom_elf_dir():
            log.note("The ROM ELF file won't be loaded automatically since you are running the utility out of IDF.")
            return ''

        rom_file_path = _pylib_get_rom_elf_path(target, chip_rev)
        if not rom_file_path:
            log.note("The ROM ELF file won't load automatically since it was not found for the provided chip type.")
            return ''

        return str(rom_file_path)

    def get_task_info_extra_note_tuple(self):  # type: () -> Tuple[Optional[list[str]], Optional[Container]]
        extra_note = None
        task_info = []
        for note_seg in self.core_elf.note_segments:
            for note_sec in note_seg.note_secs:
                if note_sec.type == ESPCoreDumpElfFile.PT_ESP_EXTRA_INFO:
                    extra_note = note_sec
                if note_sec.type == ESPCoreDumpElfFile.PT_ESP_TASK_INFO:
                    task_info_struct = EspTaskStatus.parse(note_sec.desc)
                    task_info.append(task_info_struct)
        return task_info, extra_note

    def get_note(self, note_type):
        for note_seg in self.core_elf.note_segments:
            for note_sec in note_seg.note_secs:
                if note_sec.type == note_type:
                    return note_sec
        return None

    def get_panic_details(self):
        return self.get_note(ESPCoreDumpElfFile.PT_ESP_PANIC_DETAILS)

    def print_crashed_task_info(self, marker):  # type: (Optional[int]) -> None
        if marker == ESPCoreDumpElfFile.CURR_TASK_MARKER:
            print('\nCrashed task has been skipped.')
        else:
            task_name = self.gdb_esp.get_freertos_task_name(marker)
            print(f"\nCrashed task handle: 0x{marker:x}, name: '{task_name}', GDB name: 'process {marker}'")

    def print_threads_info(self, task_info):  # type: (Optional[list[Container]]) -> None
        print(self.gdb_esp.run_cmd('info threads'))
        # THREADS STACKS
        for attempt in range(1, RETRY_ATTEMPTS + 1):
            threads, current_thread_id = self.gdb_esp.get_thread_info(attempt * DEFAULT_GDB_TIMEOUT_SEC)
            if threads is not None:
                break

            if attempt < RETRY_ATTEMPTS:
                log.warn('Failed to read threads information. Retrying...')

        if threads is None:
            log.print()  # newline
            log.warn(
                'The threads information for the current task could not be '
                'retrieved. Please try running this command again with '
                '--gdb-timeout-sec option to increase '
                'the default value of internal delay for gdb responses '
                f'(Default: {DEFAULT_GDB_TIMEOUT_SEC})'
            )
            return
        if not threads:
            # GDB has already printed "No threads." for "info threads"
            return

        print('\n')
        print('       TCB             NAME PRIO C/B  STACK USED/FREE')
        print('---------- ---------------- -------- ----------------')

        thread_dict = {}
        for thr in threads:
            thr_id = int(thr['id'])
            tcb_addr = self.gdb_esp.gdb2freertos_thread_id(thr['target-id'])
            task_name = self.gdb_esp.get_freertos_task_name(tcb_addr)
            try:
                pxEndOfStack = int(self.gdb_esp.parse_tcb_variable(tcb_addr, 'pxEndOfStack'), 16)
                pxTopOfStack = int(self.gdb_esp.parse_tcb_variable(tcb_addr, 'pxTopOfStack'), 16)
                pxStack = int(self.gdb_esp.parse_tcb_variable(tcb_addr, 'pxStack'), 16)
                uxPriority = int(self.gdb_esp.parse_tcb_variable(tcb_addr, 'uxPriority'), 16)
                uxBasePriority = int(self.gdb_esp.parse_tcb_variable(tcb_addr, 'uxBasePriority'), 16)
            except ValueError:
                pxEndOfStack = pxTopOfStack = pxStack = uxPriority = uxBasePriority = 0

            thread_dict[thr_id] = {'tcb_addr': tcb_addr, 'task_name': task_name}
            ftcb_addr = '0x{:x}'.format(tcb_addr)
            if pxStack == 0:
                print(f'{ftcb_addr:>10} Corrupted TCB data')
            else:
                fpriority = '{}/{}'.format(uxPriority, uxBasePriority)
                fstack_usage = '{}/{}'.format(abs(pxEndOfStack - pxTopOfStack), abs(pxStack - pxTopOfStack))
                print(f'{ftcb_addr:>10}{task_name:>17}{fpriority:>9}{fstack_usage:>17}')

        for thr_id, value in thread_dict.items():
            tcb_addr = value['tcb_addr']
            task_index = thr_id - 1
            task_name = value['task_name']
            self.gdb_esp.switch_thread(thr_id)
            print(f"\n==================== THREAD {thr_id} (TCB: 0x{tcb_addr:x}, name: '{task_name}') =====================")

            print(self.gdb_esp.run_cmd('bt'))
            if task_info and task_info[task_index].task_flags != TASK_STATUS_CORRECT:
                print(
                    f"The task '{thr_id}' is corrupted."
                    f'Task #{task_info[task_index].task_index} info: flags, tcb, stack '
                    f'({task_info[task_index].task_flags:x}, '
                    f'{task_info[task_index].task_tcb_addr:x}, '
                    f'{task_info[task_index].task_stack_start:x}).'
                )

        if current_thread_id:
            self.gdb_esp.switch_thread(current_thread_id)

    @staticmethod
    def parse_print_var(line):  # type: (str) -> Tuple[Optional[str], str]
        """Split '[/fmt] EXPR' into (fmt, expr). Raise ValueError if the line is not valid."""
        if '\n' in line or '\r' in line:
            raise ValueError('Line breaks are not allowed')
        fmt = None
        expr = line.strip()
        if expr.startswith('/'):
            fmt, _, expr = expr[1:].partition(' ')
            if len(fmt) != 1 or fmt not in PRINT_VAR_FORMATS:
                raise ValueError(f'Unknown format "/{fmt}". Use one of: {" ".join(PRINT_VAR_FORMATS)}')
            expr = expr.strip()
        if not expr:
            raise ValueError('Empty expression')
        return fmt, expr

    def _in_flash(self, addr):  # type: (int) -> bool
        return any(s.name.startswith(FLASH_SECTION_PREFIXES) and s.addr <= addr < s.addr + len(s.data) for s in self.exe_elf.sections)

    def _print_var_result(self, value, error):  # type: (Optional[str], Optional[str]) -> Tuple[str, Optional[int]]
        """Return the text to print and the address that could not be read, if any"""
        unread = CANNOT_ACCESS_RE.search(error) if error else VALUE_CANNOT_ACCESS_RE.search(value or '')
        if unread:
            return NOT_IN_CORE_DUMP, int(unread.group(1), 16)
        return (f'<error: {error}>' if error else value or ''), None

    def get_tagged_regions(self):  # type: () -> list[Tuple[str, int, int]]
        """Return (name, start, end) of each non-empty COREDUMP_*_ATTR region, sorted by address"""
        bounds = {}  # type: dict[str, dict[str, int]]
        for sym in self.exe_elf.symbols:
            match = TAGGED_REGION_RE.match(sym.name)
            if match:
                bounds.setdefault(match.group(1), {})[match.group(2)] = sym.value
        regions = [(name, b['start'], b['end']) for name, b in bounds.items() if b.get('start', 0) < b.get('end', 0)]
        return sorted(regions, key=lambda r: r[1])

    def get_tagged_vars(self):  # type: () -> list[Tuple[str, str]]
        """Return (label, "/x EXPR") for the variables in COREDUMP_*_ATTR regions, sorted by address"""
        regions = self.get_tagged_regions()
        symbols = [
            sym for sym in self.exe_elf.symbols if sym.type == ElfSymbol.STT_OBJECT and sym.size and any(start <= sym.value < end for _, start, end in regions)
        ]
        tagged_vars = []
        for sym in sorted(symbols, key=lambda sym: sym.value):
            if C_IDENTIFIER_RE.match(sym.name) and not sym.name.startswith('_ZZ'):
                # A file name keeps GDB from picking a static with the same name in another file
                name = f"'{sym.file}'::{sym.name}" if sym.file else sym.name
                tagged_vars.append((name, f'/x {name}'))
            else:
                # GDB cannot name statics inside a function (s.1 in C, _ZZ... in C++), so read the bytes at the address
                ctype = {1: 'unsigned char', 2: 'unsigned short', 4: 'unsigned int'}.get(sym.size)
                expr = f'*({ctype} *){sym.value:#x}' if ctype else f'*(unsigned char (*)[{sym.size}]){sym.value:#x}'
                tagged_vars.append((sym.name, f'/x {expr}'))
        return tagged_vars

    def print_user_vars(self, print_vars):  # type: (list[Tuple[str, str]]) -> None
        """Print each (label, '[/fmt] EXPR') pair as a 'label = value' line"""
        results = {}
        retry = []
        # Without the program ELF GDB reads only the core, so missing memory gives an error
        arch = self.gdb_esp.get_architecture()
        unloaded = False
        if arch:
            self.gdb_esp.run_cmd(f'set architecture {arch}')
            unloaded = self.gdb_esp.set_exec_file() is None
        if not unloaded:
            log.warn('Cannot unload the program ELF in GDB. Values below are not checked against the core dump.')
        try:
            for i, (_, line) in enumerate(print_vars):
                try:
                    fmt, expr = self.parse_print_var(line)
                except ValueError as e:
                    results[i] = f'<error: {e}>'
                    continue
                results[i], unread = self._print_var_result(*self.gdb_esp.evaluate(expr, fmt))
                # Flash content does not change at run time so the ELF value is correct
                if unread is not None and self._in_flash(unread):
                    retry.append((i, fmt, expr))
        finally:
            if unloaded:
                error = self.gdb_esp.set_exec_file(self.prog)
                if error:
                    log.warn(f'Cannot reload the program ELF in GDB. {error}')
            if arch:
                self.gdb_esp.run_cmd('set architecture auto')

        for i, fmt, expr in retry:
            results[i], _ = self._print_var_result(*self.gdb_esp.evaluate(expr, fmt))

        for i, (label, _) in enumerate(print_vars):
            print(f'{label} = {results[i]}')
        if NOT_IN_CORE_DUMP in results.values():
            log.warn(NOT_IN_CORE_DUMP_HINT)

    def print_current_thread_registers(self, extra_note, extra_info):
        # type: (Optional[Container], Optional[ListContainer]) -> None
        if self.exe_elf.e_machine == ESPCoreDumpElfFile.EM_XTENSA:
            if extra_note and extra_info:
                xtensa.print_exc_regs_info(extra_info)
            else:
                log.warn('Exception registers have not been found!')
        elif self.exe_elf.e_machine == ESPCoreDumpElfFile.EM_RISCV:
            riscv.print_exc_regs_info(self.core_elf, extra_info)
        print(self.gdb_esp.run_cmd('info registers'))

    def print_isr_context(self, extra_info):
        if self.exe_elf.e_machine == ESPCoreDumpElfFile.EM_XTENSA:
            isr_ctx_idx = XTENSA_ISR_CTX_IDX
        else:
            isr_ctx_idx = RISCV_ISR_CTX_IDX
        if len(extra_info) < isr_ctx_idx + 1:
            # no information
            return
        if extra_info[isr_ctx_idx]:
            print('Crash happened in the interrupt context')
        else:
            print('Crashed task is not in the interrupt context')

    def print_current_thread_stack(self, task_info):  # type: (Optional[list[Container]]) -> None
        print(self.gdb_esp.run_cmd('bt'))
        if task_info and task_info[0].task_flags != TASK_STATUS_CORRECT:
            print('The current crashed task is corrupted.')
            print(
                f'Task #{task_info[0].task_index} info: flags, tcb, stack '
                f'({task_info[0].task_flags:x}, {task_info[0].task_tcb_addr:x}, '
                f'{task_info[0].task_stack_start:x}).'
            )

    def print_all_memory_regions(self):  # type: () -> None
        print('Name   Address   Size   Attrs')
        core_segs = self.core_elf.load_segments
        tagged_segs = []
        for region, start, end in self.get_tagged_regions():
            # The writer rounds segment sizes up to 4 bytes
            end = start + ((end - start + 3) & ~3)
            for seg in core_segs:
                seg_end = seg.addr + len(seg.data)
                if seg.addr < end and start < seg_end:
                    tagged_segs.append((region, max(start, seg.addr), min(end, seg_end) - max(start, seg.addr), seg, start <= seg.addr and seg_end <= end))
        merged_segs = []
        for sec in self.exe_elf.sections:
            merged = False
            for seg in core_segs:
                if seg.addr <= sec.addr <= seg.addr + len(seg.data):
                    # sec:    |XXXXXXXXXX|
                    # seg: |...XXX.............|
                    seg_addr = seg.addr
                    if seg.addr + len(seg.data) <= sec.addr + len(sec.data):
                        # sec:        |XXXXXXXXXX|
                        # seg:    |XXXXXXXXXXX...|
                        # merged: |XXXXXXXXXXXXXX|
                        seg_len = len(sec.data) + (sec.addr - seg.addr)
                    else:
                        # sec:        |XXXXXXXXXX|
                        # seg:    |XXXXXXXXXXXXXXXXX|
                        # merged: |XXXXXXXXXXXXXXXXX|
                        seg_len = len(seg.data)
                    merged_segs.append((sec.name, seg_addr, seg_len, sec.attr_str(), True))
                    core_segs.remove(seg)
                    merged = True
                elif sec.addr <= seg.addr <= sec.addr + len(sec.data):
                    # sec:  |XXXXXXXXXX|
                    # seg:  |...XXX.............|
                    seg_addr = sec.addr
                    if (seg.addr + len(seg.data)) >= (sec.addr + len(sec.data)):
                        # sec:    |XXXXXXXXXX|
                        # seg:    |..XXXXXXXXXXX|
                        # merged: |XXXXXXXXXXXXX|
                        seg_len = len(sec.data) + (seg.addr + len(seg.data)) - (sec.addr + len(sec.data))
                    else:
                        # sec:    |XXXXXXXXXX|
                        # seg:      |XXXXXX|
                        # merged: |XXXXXXXXXX|
                        seg_len = len(sec.data)
                    merged_segs.append((sec.name, seg_addr, seg_len, sec.attr_str(), True))
                    core_segs.remove(seg)
                    merged = True

            if not merged:
                merged_segs.append((sec.name, sec.addr, len(sec.data), sec.attr_str(), False))

        for ms in merged_segs:
            print(f'{ms[0]} 0x{ms[1]:x} 0x{ms[2]:x} {ms[3]}')
        for region, addr, size, seg, _ in tagged_segs:
            print(f'.coredump.{region} 0x{addr:x} 0x{size:x} {seg.attr_str()}')

        trace_regions = self._riscv_trace_regions()
        for cs in core_segs:
            # A segment that holds only a tagged region is printed above
            if any(cs is seg and inside for _, _, _, seg, inside in tagged_segs):
                continue
            name = trace_regions.get(cs.addr)
            if name is not None:
                print(f'{name} 0x{cs.addr:x} 0x{len(cs.data):x} {cs.attr_str()}')
                continue
            # core dump exec segments are from ROM,
            # other are belong to tasks
            if cs.flags & ElfSegment.PF_X:
                seg_name = 'rom.text'
            else:
                seg_name = 'tasks.data'
            print(f'.coredump.{seg_name} 0x{cs.addr:x} 0x{len(cs.data):x} {cs.attr_str()}')

    def _riscv_trace_regions(self):  # type: () -> dict[int, str]
        # Map each stored trace buffer to a per-core region name via the ESP_RISCV_TRACE note.
        snapshot = parse_riscv_trace_note(self.core_elf)
        if snapshot is None:
            return {}
        return {core.buffer_addr: f'.trace.core{core.core_id}.data' for core in snapshot.cores if core.buffer_present}

    def print_riscv_trace_info(self):  # type: () -> None
        snapshot = parse_riscv_trace_note(self.core_elf)
        if snapshot is None:
            return
        print('\n===================== RISC-V TRACE SNAPSHOT =====================')
        print(f'ABI {snapshot.abi_major}.{snapshot.abi_minor}, reason {snapshot.capture_reason_name}, cores {snapshot.core_count}')
        print(f'Target 0x{snapshot.target_id:04x}, chip revision v{snapshot.chip_revision // 100}.{snapshot.chip_revision % 100}')
        if any(snapshot.app_elf_sha256):
            print(f'App ELF SHA256: {snapshot.app_elf_sha256.hex()}')
        for core in snapshot.cores:
            print(f'Core {core.core_id}: memory {core.memory_mode_name}, format {core.packet_format_name}, address {core.address_mode_name}')
            print(f'  resync {core.resync_mode_name}, threshold {core.resync_threshold}')
            if core.buffer_present:
                head = f'0x{core.head_offset:x}' if core.head_valid else 'invalid'
                print(f'  buffer 0x{core.buffer_addr:x}, capacity 0x{core.capacity:x}, head {head}, segment {core.segment_index}')
            else:
                print('  no buffer')
            print(
                f'  hw fifo 0x{core.fifo_status_raw:08x}, intr 0x{core.intr_status_raw:08x}, '
                f'empty {"yes" if core.fifo_empty else "no"}, '
                f'full {"yes" if core.memory_full else "no"}, '
                f'overflow {"yes" if core.fifo_overflow else "no"}'
            )
            if core.quality_flags:
                print(f'  quality: {", ".join(core.quality_flags)}')

    def print_core_dump_memory_contents(self):  # type: () -> None
        for cs in self.core_elf.load_segments:
            # core dump exec segments are from ROM,
            # other are belong to tasks (TCB or stack)
            if cs.flags & ElfSegment.PF_X:
                seg_name = 'rom.text'
            else:
                seg_name = 'tasks.data'
            print(f'.coredump.{seg_name} 0x{cs.addr:x} 0x{len(cs.data):x} {cs.attr_str()}')
            print(self.gdb_esp.run_cmd(f'x/{len(cs.data) // 4:d}x 0x{cs.addr:x}'))

    def verify_target(self, core_header_info_dict):
        target = core_header_info_dict.get('target')
        if target is None:
            target = self.get_target()
            core_header_info_dict['target'] = target
        return target

    @contextmanager
    def _handle_coredump_loader_error(self):
        try:
            yield
        except ESPCoreDumpLoaderError as e:
            log.err(f'Failed to load core dump: {e}')
            if e.extra_output:
                log.print('', file=sys.stderr)
                log.print('┌────── Additional information about the error: ', file=sys.stderr)
                log.print('│   ', file=sys.stderr)
                log.print(
                    textwrap.indent(e.extra_output.rstrip('\n'), '│   ', lambda line: True),
                    file=sys.stderr,
                    markup=False,
                    highlight=False,
                )
                log.print('│   ', file=sys.stderr)
                log.print('└────── end of additional information about the error.', file=sys.stderr)
            raise SystemExit(1)

    def dbg_corefile(self):  # type: () -> Optional[list[str]]
        """
        Command to load core dump from file or flash and run GDB debug session with it
        """
        exe_elf = ESPCoreDumpElfFile(self.prog)
        with self._handle_coredump_loader_error():
            core_header_info_dict = self.get_core_header_info_dict(e_machine=exe_elf.e_machine)
            self.core_elf = ESPCoreDumpElfFile(core_header_info_dict['core_elf_path'])

        temp_files = core_header_info_dict.pop('temp_files')
        self.chip = self.verify_target(core_header_info_dict)

        gdb_args = self.get_gdb_args(is_dbg_mode=True, **core_header_info_dict)

        p = subprocess.Popen(
            bufsize=0,
            args=gdb_args,
            stdin=None,
            stdout=None,
            stderr=None,
            close_fds=CLOSE_FDS,
        )
        p.wait()
        print('Done!')
        return temp_files  # type: ignore

    def info_corefile(self):  # type: () -> Optional[list[str]]
        """
        Command to load core dump from file or
        flash and print it's data in user friendly form
        """
        with self._handle_coredump_loader_error():
            self.exe_elf = ESPCoreDumpElfFile(self.prog)
            core_header_info_dict = self.get_core_header_info_dict(e_machine=self.exe_elf.e_machine)
            self.core_elf = ESPCoreDumpElfFile(core_header_info_dict['core_elf_path'])

        temp_files = core_header_info_dict.pop('temp_files')
        self.chip = self.verify_target(core_header_info_dict)

        if self.exe_elf.e_machine != self.core_elf.e_machine:
            raise ValueError('The arch should be the same between core elf and exe elf')

        task_info, extra_note = self.get_task_info_extra_note_tuple()

        print('===============================================================')
        print('==================== ESP32 CORE DUMP START ====================')

        gdb_args = self.get_gdb_args(is_dbg_mode=False, **core_header_info_dict)

        self.gdb_esp = EspGDB(gdb_args, timeout_sec=self.gdb_timeout_sec)

        extra_info = None
        if extra_note:
            extra_info = Struct('regs' / GreedyRange(Int32ul)).parse(extra_note.desc).regs
            marker = extra_info[0]
            self.print_crashed_task_info(marker)
            self.print_isr_context(extra_info)

        panic_details = self.get_panic_details()
        if panic_details:
            print('Panic reason: ' + panic_details.desc.decode('utf-8'))

        uptime = self.get_note(ESPCoreDumpElfFile.PT_ESP_UPTIME)
        if uptime and len(uptime.desc) == 8:
            uptime_us = Int64sl.parse(uptime.desc)
            print(f'Uptime: {uptime_us} us ({uptime_us / 1e6:.3f} s)')

        print('\n================== CURRENT THREAD REGISTERS ===================')
        self.print_current_thread_registers(extra_note, extra_info)

        print('\n==================== CURRENT THREAD STACK =====================')
        self.print_current_thread_stack(task_info)
        print('\n======================== THREADS INFO =========================')
        self.print_threads_info(task_info)
        user_vars = self.get_tagged_vars() if self.print_all_vars else []
        if self.print_all_vars and not user_vars:
            log.warn('No variables with a COREDUMP_*_ATTR attribute found.')
        user_vars += [(line, line) for line in self.print_vars or []]
        if user_vars:
            print('\n\n======================= USER VARIABLES ========================')
            self.print_user_vars(user_vars)
        print('\n\n======================= ALL MEMORY REGIONS ========================')
        self.print_all_memory_regions()

        self.print_riscv_trace_info()

        if self.print_mem:
            print('\n====================== CORE DUMP MEMORY CONTENTS ========================')
            self.print_core_dump_memory_contents()

        print('\n===================== ESP32 CORE DUMP END =====================')
        print('===============================================================')

        del self.gdb_esp
        print('Done!')
        return temp_files  # type: ignore
