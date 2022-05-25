#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#
# ESP-IDF Core Dump Utility
#

import os
import subprocess
import sys
from distutils.spawn import find_executable
from shutil import copyfile
from typing import List, Optional, Tuple, Union

try:
    # esptool>=4.0
    from esptool.cmds import detect_chip
    from esptool.loader import ESPLoader
except (AttributeError, ModuleNotFoundError):
    # esptool<4.0
    from esptool import ESPLoader
    detect_chip = ESPLoader.detect_chip

from construct import Container, GreedyRange, Int32ul, ListContainer, Struct
from pygdbmi.gdbcontroller import DEFAULT_GDB_TIMEOUT_SEC

from .corefile import RISCV_TARGETS, SUPPORTED_TARGETS, XTENSA_TARGETS, xtensa
from .corefile.elf import (TASK_STATUS_CORRECT, ElfFile, ElfSegment,
                           ESPCoreDumpElfFile, EspTaskStatus)
from .corefile.gdb import EspGDB
from .corefile.loader import ESPCoreDumpFileLoader, ESPCoreDumpFlashLoader

IDF_PATH = os.getenv('IDF_PATH')
if not IDF_PATH:
    sys.stderr.write('IDF_PATH is not found! Set proper IDF_PATH in environment.\n')
    sys.exit(2)

if os.name == 'nt':
    CLOSE_FDS = False
else:
    CLOSE_FDS = True


class CoreDump:
    def __init__(self,
                 baud: Optional[int] = int(os.environ.get('ESPTOOL_BAUD', ESPLoader.ESP_ROM_BAUD)),
                 chip: str = os.environ.get('ESPTOOL_CHIP', 'auto'),
                 core_format: str = 'elf',
                 port: str = os.environ.get('ESPTOOL_PORT', ESPLoader.DEFAULT_PORT),
                 gdb_timeout_sec: int = DEFAULT_GDB_TIMEOUT_SEC,
                 core: Optional[str] = None,
                 gdb: Optional[str] = None,
                 extra_gdbinit_file: Optional[str] = None,
                 off: Optional[int] = None,
                 prog: Optional[str] = None,
                 print_mem: Optional[str] = None,
                 rom_elf: Optional[str] = None,
                 save_core: Optional[str] = None,
                 ):
        if prog is None:
            raise ValueError("Path to program\'s ELF binary is not provided")

        self.baud = baud
        self.chip = chip
        self.core = core
        self.core_format = core_format
        self.gdb = gdb
        self.gdb_timeout_sec = gdb_timeout_sec
        self.extra_gdbinit_file = extra_gdbinit_file
        self.off = off
        self.prog = prog
        self.port = port
        self.print_mem = print_mem
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
            for s in elf.sections:
                if s.name == '.text':
                    sym_cmd = 'add-symbol-file %s 0x%x' % (elf_path, s.addr)
        return sym_cmd

    def get_core_dump_elf(self, e_machine=ESPCoreDumpFileLoader.ESP32):
        # type: (Optional[int]) -> Tuple[str, Optional[str], Optional[list[str]]]
        loader = None  # type: Union[ESPCoreDumpFlashLoader, ESPCoreDumpFileLoader, None]
        core_filename = None
        target = None
        temp_files = None

        if not self.core:
            # Core file not specified, try to read core dump from flash.
            loader = ESPCoreDumpFlashLoader(self.off, self.chip, port=self.port, baud=self.baud)
        elif self.core_format != 'elf':
            # Core file specified, but not yet in ELF format. Convert it from raw or base64 into ELF.
            loader = ESPCoreDumpFileLoader(self.core, self.core_format == 'b64')
        else:
            # Core file is already in the ELF format
            core_filename = self.core

        # Load/convert the core file
        if loader:
            loader.create_corefile(exe_name=self.prog, e_machine=e_machine)
            core_filename = loader.core_elf_file
            if self.save_core:
                # We got asked to save the core file, make a copy
                copyfile(loader.core_elf_file, self.save_core)
            target = loader.target
            temp_files = loader.temp_files

        return core_filename, target, temp_files  # type: ignore

    def get_target(self):  # type: () -> str
        if self.chip != 'auto':
            return self.chip  # type: ignore

        inst = detect_chip(self.port, self.baud)
        return inst.CHIP_NAME.lower().replace('-', '')  # type: ignore

    def get_gdb_path(self, target=None):  # type: (Optional[str]) -> str
        if self.gdb:
            return self.gdb  # type: ignore

        if target is None:
            target = self.get_target()

        if target in XTENSA_TARGETS:
            # For some reason, xtensa-esp32s2-elf-gdb will report some issue.
            # Use xtensa-esp32-elf-gdb instead.
            gdb_path = 'xtensa-esp32-elf-gdb'
        elif target in RISCV_TARGETS:
            gdb_path = 'riscv32-esp-elf-gdb'
        else:
            raise ValueError('Invalid value: {}. For now we only support {}'.format(target, SUPPORTED_TARGETS))
        if not find_executable(gdb_path):
            raise ValueError(f'gdb executable could not be resolved '
                             f' \n\n\tPlease run: \n\n{IDF_PATH}/install.sh\n\n')

        return gdb_path

    def get_gdb_args(self, target, core_elf_path, is_dbg_mode=False):
        # type: (Optional[str], Optional[str], bool) -> List[str]
        gdb_tool = self.get_gdb_path(target)
        rom_elf_path = self.get_rom_elf_path(target)
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

    def get_rom_elf_path(self, target=None):  # type: (Optional[str]) -> str
        if self.rom_elf:
            return self.rom_elf  # type: ignore

        if target is None:
            target = self.get_target()

        return '{}_rom.elf'.format(target)

    def get_task_info_extra_note_tuple(self):  # type: () -> Tuple[Optional[list[str]], Optional[Container]]
        extra_note = None
        task_info = []
        for note_seg in self.core_elf.note_segments:
            for note_sec in note_seg.note_secs:
                if note_sec.type == ESPCoreDumpElfFile.PT_EXTRA_INFO and 'EXTRA_INFO' in note_sec.name.decode('ascii'):
                    extra_note = note_sec
                if note_sec.type == ESPCoreDumpElfFile.PT_TASK_INFO and 'TASK_INFO' in note_sec.name.decode('ascii'):
                    task_info_struct = EspTaskStatus.parse(note_sec.desc)
                    task_info.append(task_info_struct)
        return task_info, extra_note

    def print_crashed_task_info(self, marker):  # type: (Optional[int]) -> None
        if marker == ESPCoreDumpElfFile.CURR_TASK_MARKER:
            print('\nCrashed task has been skipped.')
        else:
            task_name = self.gdb_esp.get_freertos_task_name(marker)
            print("\nCrashed task handle: 0x%x, name: '%s', GDB name: 'process %d'"
                  % (marker, task_name, marker))  # type: ignore

    def print_threads_info(self, task_info):  # type: (Optional[list[Container]]) -> None
        print(self.gdb_esp.run_cmd('info threads'))
        # THREADS STACKS
        threads, _ = self.gdb_esp.get_thread_info()
        for thr in threads:
            thr_id = int(thr['id'])
            tcb_addr = self.gdb_esp.gdb2freertos_thread_id(thr['target-id'])
            task_index = int(thr_id) - 1
            task_name = self.gdb_esp.get_freertos_task_name(tcb_addr)
            self.gdb_esp.switch_thread(thr_id)
            print('\n==================== THREAD {} (TCB: 0x{:x}, name: \'{}\') ====================='
                  .format(thr_id, tcb_addr, task_name))
            print(self.gdb_esp.run_cmd('bt'))
            if task_info and task_info[task_index].task_flags != TASK_STATUS_CORRECT:
                print("The task '%s' is corrupted." % thr_id)
                print('Task #%d info: flags, tcb, stack (%x, %x, %x).' % (task_info[task_index].task_index,
                                                                          task_info[task_index].task_flags,
                                                                          task_info[task_index].task_tcb_addr,
                                                                          task_info[task_index].task_stack_start))

    def print_current_thread_registers(self, extra_note, extra_info):
        # type: (Optional[Container], Optional[ListContainer]) -> None
        if self.exe_elf.e_machine == ESPCoreDumpElfFile.EM_XTENSA:
            if extra_note and extra_info:
                xtensa.print_exc_regs_info(extra_info)
            else:
                print('Exception registers have not been found!')
        print(self.gdb_esp.run_cmd('info registers'))

    def print_current_thread_stack(self, task_info):  # type: (Optional[list[Container]]) -> None
        print(self.gdb_esp.run_cmd('bt'))
        if task_info and task_info[0].task_flags != TASK_STATUS_CORRECT:
            print('The current crashed task is corrupted.')
            print('Task #%d info: flags, tcb, stack (%x, %x, %x).' % (task_info[0].task_index,
                                                                      task_info[0].task_flags,
                                                                      task_info[0].task_tcb_addr,
                                                                      task_info[0].task_stack_start))

    def print_all_memory_regions(self):  # type: () -> None
        print('Name   Address   Size   Attrs')
        core_segs = self.core_elf.load_segments
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
            print('%s 0x%x 0x%x %s' % (ms[0], ms[1], ms[2], ms[3]))

        for cs in core_segs:
            # core dump exec segments are from ROM, other are belong to tasks (TCB or stack)
            if cs.flags & ElfSegment.PF_X:
                seg_name = 'rom.text'
            else:
                seg_name = 'tasks.data'
            print('.coredump.%s 0x%x 0x%x %s' % (seg_name, cs.addr, len(cs.data), cs.attr_str()))

    def print_core_dump_memory_contents(self):  # type: () -> None
        for cs in self.core_elf.load_segments:
            # core dump exec segments are from ROM, other are belong to tasks (TCB or stack)
            if cs.flags & ElfSegment.PF_X:
                seg_name = 'rom.text'
            else:
                seg_name = 'tasks.data'
            print('.coredump.%s 0x%x 0x%x %s' % (seg_name, cs.addr, len(cs.data), cs.attr_str()))
            print(self.gdb_esp.run_cmd('x/%dx 0x%x' % (len(cs.data) // 4, cs.addr)))

    def dbg_corefile(self):  # type: () -> Optional[list[str]]
        """
        Command to load core dump from file or flash and run GDB debug session with it
        """
        exe_elf = ESPCoreDumpElfFile(self.prog)
        core_elf_path, target, temp_files = self.get_core_dump_elf(e_machine=exe_elf.e_machine)
        gdb_args = self.get_gdb_args(target, core_elf_path, is_dbg_mode=True)

        p = subprocess.Popen(bufsize=0,
                             args=gdb_args,
                             stdin=None, stdout=None, stderr=None,
                             close_fds=CLOSE_FDS)
        p.wait()
        print('Done!')
        return temp_files

    def info_corefile(self):  # type: () -> Optional[list[str]]
        """
        Command to load core dump from file or flash and print it's data in user friendly form
        """
        self.exe_elf = ESPCoreDumpElfFile(self.prog)
        core_elf_path, target, temp_files = self.get_core_dump_elf(e_machine=self.exe_elf.e_machine)
        self.core_elf = ESPCoreDumpElfFile(core_elf_path)

        if self.exe_elf.e_machine != self.core_elf.e_machine:
            raise ValueError('The arch should be the same between core elf and exe elf')

        task_info, extra_note = self.get_task_info_extra_note_tuple()

        print('===============================================================')
        print('==================== ESP32 CORE DUMP START ====================')

        gdb_args = self.get_gdb_args(target, core_elf_path, is_dbg_mode=False)
        self.gdb_esp = EspGDB(gdb_args, timeout_sec=self.gdb_timeout_sec)

        extra_info = None
        if extra_note:
            extra_info = Struct('regs' / GreedyRange(Int32ul)).parse(extra_note.desc).regs
            marker = extra_info[0]
            self.print_crashed_task_info(marker)

        print('\n================== CURRENT THREAD REGISTERS ===================')
        # Only xtensa have exception registers
        self.print_current_thread_registers(extra_note, extra_info)

        print('\n==================== CURRENT THREAD STACK =====================')
        self.print_current_thread_stack(task_info)

        print('\n======================== THREADS INFO =========================')
        self.print_threads_info(task_info)

        print('\n\n======================= ALL MEMORY REGIONS ========================')
        self.print_all_memory_regions()

        if self.print_mem:
            print('\n====================== CORE DUMP MEMORY CONTENTS ========================')
            self.print_core_dump_memory_contents()

        print('\n===================== ESP32 CORE DUMP END =====================')
        print('===============================================================')

        del self.gdb_esp
        print('Done!')
        return temp_files
