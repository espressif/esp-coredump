#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Build an AnalysisReport from a core dump and the application ELF.
Data is read from the core dump notes and from GDB, not from printed text.
"""

from __future__ import annotations

import binascii
import os
import re

from construct import ConstructError, GreedyRange, Int32ul
from esp_pylib.errors import FatalError

from ..corefile import ESPCoreDumpError
from ..corefile.elf import TASK_STATUS_CORRECT, ESPCoreDumpElfFile, EspTaskStatus
from ..corefile.gdb import EspGDB
from ..corefile.loader import EspCoreDumpLoader, app_sha_matches, parse_core_dump_info, remove_temp_files
from ..corefile.riscv import (
    IDF_FAKE_FRAME_PC,
    PT_PRSTATUS,
    RISCV_CRASHED_TCB_IDX,
    RISCV_ISR_CTX_IDX,
    PrStruct,
    find_exc_frame,
    parse_exc_frame_csrs,
)
from . import riscv
from .checks import run_checks
from .paths import short_path, short_paths_in_text
from .report import (
    DISASM_ROW_RE,
    NOT_AVAILABLE,
    STACK_DAMAGED,
    STACK_ISR,
    STACK_OK,
    STACK_SP_OUTSIDE,
    AnalysisReport,
    CrashInfo,
    Disassembly,
    ElfInfo,
    Fact,
    Frame,
    InputInfo,
    MemoryArea,
    RomInfo,
    TargetInfo,
    Task,
    Warn,
    no_source,
    source_problem,
)
from .sections import data_holds, read_elf_sections, read_instruction

MAX_FRAMES = 64
# instructions kept before and after the anchor in the disassembly window
DISASM_BEFORE = 8
DISASM_AFTER = 2
# What a GDB command raises when GDB fails or its answer has an unexpected shape
GDB_ERRORS = (ESPCoreDumpError, KeyError, TypeError)
# crash.kind for each kind of mcause that riscv.decode_mcause() returns
CRASH_KINDS = {'exception': 'cpu_exception', 'idf_cause': 'interrupt', 'interrupt': 'interrupt'}


class ReportError(FatalError):
    """
    The report can not be made. The message says why.

    Based on esp_pylib.errors.FatalError so an IDE reports it as a tool error.
    Not on ESPCoreDumpError: that one is caught in five places here to mean a GDB
    or ELF read failed and the report should degrade, which must not swallow this.
    """


class ElfMismatchError(ReportError):
    """The core dump was made by a different application ELF."""


def _row_address(line: str) -> int | None:
    """The address a GDB disassembly row starts with, for example '=> 0x4000d612 <+18>:'."""
    match = DISASM_ROW_RE.match(line)
    return int(match.group(2), 16) if match else None


def find_call(gdb: EspGDB, elf: ESPCoreDumpElfFile, ra: int) -> tuple[int, int] | None:
    """
    Find the call that ends at the return address, as (address, instruction).
    The four bytes before it can decode as a 32-bit instruction and as two
    16-bit ones, so the only honest way to tell is to ask GDB, which decodes
    a whole function from its first instruction. Without an answer the call
    stays unknown, because a guess here would name the wrong register.
    """
    try:
        text = gdb.run_cmd(f'disassemble {ra:#x}')
    except GDB_ERRORS:
        return None
    addresses = [a for a in (_row_address(ln) for ln in text.splitlines()) if a is not None]
    # the instruction before the row that starts at ra, in one linear decode of the function
    previous = next((prev for prev, addr in zip(addresses, addresses[1:]) if addr == ra), None)
    if previous is None:
        return None
    insn = read_instruction(elf, previous)
    if insn is None:
        return None
    decoded = riscv.decode_jalr(insn)
    # rd must be ra: a jalr that links elsewhere, or not at all, left the
    # return address untouched, so it is not what the resolver followed
    if decoded is None or decoded[1] != 1:
        return None
    return previous, insn


def check_elf_match(core_sha: str, app_sha256: str) -> str:
    """
    Compare the app SHA saved in the core dump with the ELF SHA.
    Return 'match' or 'not_checked'. Raise ElfMismatchError if they differ.
    """
    if not core_sha:
        return 'not_checked'
    if not app_sha_matches(core_sha, app_sha256):
        raise ElfMismatchError(f'The ELF file does not match the core dump. The core dump app SHA256 is {core_sha}, and the ELF SHA256 is {app_sha256}.')
    return 'match'


class ReportCollector:
    """Build the report for a CoreDump object."""

    def __init__(self, coredump):
        self.cd = coredump
        self.notes: dict[int, list] = {}
        self.temp_files: list[str] = []
        # set by _add_tasks
        self.in_interrupt: bool | None = None
        self.crashed: Task | None = None
        self.crashed_regs: list[int] = []
        # set by _add_crash
        # address of the saved RvExcFrame, when it was located uniquely
        self.frame_addr: int | None = None
        self.mtval: int | None = None
        self.pc_insn: int | None = None
        # return address of the call to resolve, set when the crash looks like a wild jump
        self.call_ra: int | None = None
        # set by _add_gdb_data: (address, instruction) of the call that ends at call_ra
        self.call: tuple[int, int] | None = None

    def build(self) -> AnalysisReport:
        try:
            return self._build()
        finally:
            remove_temp_files(self.temp_files)

    def _load(self) -> dict:
        """Read the core dump."""
        cd = self.cd
        if not os.path.isfile(cd.prog):
            raise ReportError(f'ELF file {cd.prog} not found')
        if cd.core and not os.path.isfile(cd.core):
            raise ReportError(f'Core dump file {cd.core} not found')
        try:
            cd.exe_elf = ESPCoreDumpElfFile(cd.prog)
        except (ConstructError, ValueError) as e:
            raise ReportError(f'Can not read the ELF file ({e})')
        try:
            info = cd.get_core_header_info_dict(e_machine=cd.exe_elf.e_machine)
            self.temp_files = info.pop('temp_files') or []
            cd.core_elf = ESPCoreDumpElfFile(info['core_elf_path'])
        except ESPCoreDumpError as e:
            if 'Invalid application image' in str(e):
                raise ElfMismatchError(f'The ELF file does not match the core dump ({e})')
            raise ReportError(f'Can not read the core dump ({e})')
        except (ConstructError, ValueError, OSError) as e:
            raise ReportError(f'Can not read the core dump ({e})')
        return dict(info)

    def _build(self) -> AnalysisReport:
        cd = self.cd
        info = self._load()
        if cd.exe_elf.e_machine != ESPCoreDumpElfFile.EM_RISCV:
            raise ReportError('The report supports only RISC-V applications for now.')
        if cd.core_elf.e_machine != cd.exe_elf.e_machine:
            raise ReportError('The core dump and the ELF file are for different architectures.')

        for seg in cd.core_elf.note_segments:
            for note in seg.note_secs:
                self.notes.setdefault(note.type, []).append(note)

        app_sha256 = binascii.hexlify(cd.exe_elf.sha256).decode()
        info_note = self._note_desc(ESPCoreDumpElfFile.PT_ESP_INFO, b'ESP_CORE_DUMP_INFO')
        core_info = parse_core_dump_info(info_note) if info_note else None
        elf_match = check_elf_match(core_info[1] if core_info else '', app_sha256)
        # the loader of BIN dumps writes this note with the version only
        dump_version = Int32ul.parse(info_note[:4]) & 0xFFFF if info_note and len(info_note) >= 4 else None

        chip = cd.verify_target(info)
        report = AnalysisReport(
            input=InputInfo(format=cd.core_format if cd.core else 'flash', dump_version=dump_version),
            target=TargetInfo(chip=chip, architecture='riscv', chip_rev=info.get('chip_rev')),
            elf=ElfInfo(
                name=os.path.basename(cd.prog),
                sha256=app_sha256,
                match=elf_match,
                sections=read_elf_sections(cd.prog),
            ),
            crash=CrashInfo(),
        )
        if elf_match == 'not_checked':
            report.warn(Warn.ELF_NOT_CHECKED, 'The core dump has no app SHA256, so the ELF match was not checked.')
        if dump_version is not None and dump_version < EspCoreDumpLoader.ELF_CRC32_V2:
            report.warn(
                Warn.BIN_NO_PANIC_REASON,
                'BIN core dumps do not save the panic reason. A software panic like abort() can look like a CPU fault here.',
            )

        self._add_tasks(report)
        self._add_crash(report)
        self._add_gdb_data(report, chip, info)
        self._add_rom(report, chip, info.get('chip_rev'))
        self._add_stack_status(report)
        self._add_memory_areas(report)
        self._add_facts(report)
        return report

    def _add_rom(self, report: AnalysisReport, chip: str, chip_rev: int | None) -> None:
        """
        Map the executable sections of the ROM ELF, the same file GDB loads for
        ROM symbols. ROM code is in no core dump and in no app ELF, so without
        this an address in ROM cannot be told from a wild one.
        """
        try:
            path = self.cd.get_rom_elf_path(chip_rev=chip_rev, target=chip)
        except Exception:
            path = ''
        if not path or not os.path.isfile(path):
            report.warn(Warn.NO_ROM_ELF, 'The ROM ELF was not found, so ROM code is not mapped and a ROM address looks unknown.')
            return
        # --rom-elf takes any file, and another chip's ROM maps real addresses to the
        # wrong code. esp_pylib.rom.get_rom_elf_path defines the name these carry.
        # Match through '_rev', since 'esp32' also starts 'esp32s3'.
        name = os.path.basename(path)
        if not name.startswith(f'{chip}_rev'):
            report.warn(
                Warn.ROM_ELF_MISMATCH,
                f'The ROM ELF {name} is not named like a ROM of {chip}, so ROM code is not mapped. ROM symbols in the backtrace are not affected.',
            )
            return
        try:
            rom_elf = ESPCoreDumpElfFile(path)
            if rom_elf.e_machine != self.cd.exe_elf.e_machine:
                report.warn(Warn.ROM_ELF_MISMATCH, f'The ROM ELF {name} is for another architecture, so ROM code is not mapped.')
                return
            sections = [s for s in read_elf_sections(path) if s.kind == 'code']
        except Exception as e:
            report.warn(Warn.ROM_ELF_FAILED, short_paths_in_text(f'The ROM ELF could not be read ({e})'))
            return
        if sections:
            report.rom = RomInfo(name=os.path.basename(path), sections=sections)

    def _note_desc(self, note_type: int, name: bytes | None = None) -> bytes | None:
        for note in self.notes.get(note_type, []):
            if name is None or note.name == name:
                return bytes(note.desc)
        return None

    def _add_tasks(self, report: AnalysisReport) -> None:
        extra = self._note_desc(ESPCoreDumpElfFile.PT_ESP_EXTRA_INFO) or b''
        extra_values = GreedyRange(Int32ul).parse(extra)
        crashed_tcb = extra_values[RISCV_CRASHED_TCB_IDX] if extra_values else None
        # the loader of BIN dumps writes only the TCB
        self.in_interrupt = bool(extra_values[RISCV_ISR_CTX_IDX]) if len(extra_values) > RISCV_ISR_CTX_IDX else None
        task_status = {}
        for note in self.notes.get(ESPCoreDumpElfFile.PT_ESP_TASK_INFO, []):
            try:
                status = EspTaskStatus.parse(note.desc)
            except ConstructError:
                report.warn(Warn.BAD_TASK_INFO, 'A task status note in the core dump can not be read.')
                continue
            task_status[status.task_tcb_addr] = status.task_flags

        # task ids follow the order of the register notes in the core dump
        for index, note in enumerate(self.notes.get(PT_PRSTATUS, [])):
            try:
                pr = PrStruct.parse(note.desc)
            except ConstructError:
                report.warn(Warn.BAD_TASK_REGS, f'The register note of task:{index} can not be read, so this task is skipped.')
                continue
            task = Task(id=f'task:{index}', tcb=pr.pr_pid)
            regs = list(pr.regs)
            damaged = regs[0] == IDF_FAKE_FRAME_PC or task_status.get(pr.pr_pid, TASK_STATUS_CORRECT) != TASK_STATUS_CORRECT
            if damaged:
                task.stack.status = STACK_DAMAGED
                report.warn(Warn.TASK_DAMAGED, f'Task {task.id} has damaged data in the core dump.', [task.id])
            if pr.pr_pid == crashed_tcb and self.crashed is None:
                task.crashed = True
                self.crashed = task
                self.crashed_regs = regs
                # A fake frame is only a placeholder that lets GDB list a
                # damaged task. Its sentinel PC/SP and zeroed registers are
                # not captured crash facts.
                if not damaged:
                    task.stack.sp = regs[2]
                    task.registers = dict(zip(riscv.REG_NAMES, regs))
            report.tasks.append(task)

        if crashed_tcb is None:
            report.warn(Warn.NO_CRASHED_TASK, 'The core dump does not say which task crashed.')
        elif crashed_tcb == ESPCoreDumpElfFile.CURR_TASK_MARKER:
            report.warn(Warn.CRASHED_TASK_SKIPPED, 'The crashed task was not saved in the core dump.')
        elif self.crashed is None:
            report.warn(Warn.CRASHED_TASK_MISSING, f'The crashed task 0x{crashed_tcb:x} has no saved registers.')

    def _add_crash(self, report: AnalysisReport) -> None:
        crash = report.crash
        crash.in_interrupt = self.in_interrupt
        if self.in_interrupt is None:
            report.warn(Warn.NO_ISR_FLAG, 'The core dump does not say if the crash was in an interrupt.')
        details = self._note_desc(ESPCoreDumpElfFile.PT_ESP_PANIC_DETAILS)
        if details is not None:
            text = details.rstrip(b'\x00').decode('utf-8', 'replace').strip()
            crash.panic_details = short_paths_in_text(text) or None

        if self.crashed is not None:
            crash.crashed_task_id = self.crashed.id
            csrs: dict | None = None
            if self.crashed.stack.status != STACK_DAMAGED:
                crash.pc = self.crashed_regs[0]
                frame = find_exc_frame(self.cd.core_elf.load_segments, self.crashed_regs)
                if frame is not None:
                    self.frame_addr = frame[0]
                    csrs = parse_exc_frame_csrs(frame[1])
            if csrs is None:
                report.warn(Warn.NO_EXCEPTION_FRAME, 'The saved exception frame was not found, so mcause and mtval are not available.', [self.crashed.id])
            else:
                self.mtval = csrs['mtval']
                self.crashed.registers.update(csrs)
                crash.core = csrs['mhartid']
                crash.mcause = csrs['mcause']

        cause_reason, cause_kind = riscv.decode_mcause(crash.mcause)
        if details is not None:
            # software panic: mcause and mtval do not describe the crash
            crash.kind = 'software_panic'
            crash.reason = crash.panic_details.splitlines()[0] if crash.panic_details else None
        else:
            crash.kind = CRASH_KINDS.get(cause_kind or '')
            crash.reason = cause_reason
            if crash.pc is not None:
                self.pc_insn = read_instruction(self.cd.exe_elf, crash.pc)
            ra = self.crashed_regs[1] if self.crashed is not None and crash.pc is not None else None
            if crash.mcause in riscv.INSTRUCTION_FETCH_CAUSES and ra is not None and ra >= 4:
                # the call that jumped to the bad address ends at the return address.
                # Which instruction that is needs GDB, so resolve it in the GDB phase.
                self.call_ra = ra
            crash.bad_address = riscv.get_bad_address(crash.mcause, self.mtval)
        if crash.reason is None:
            report.warn(Warn.NO_CRASH_REASON, 'The crash reason is not available.')

    def _add_gdb_data(self, report: AnalysisReport, chip: str, info: dict) -> None:
        by_tcb = {t.tcb: t for t in report.tasks}
        # without GDB the report has no task names, frames or stack bounds
        if not self.cd.get_gdb_path(chip):
            report.warn(Warn.GDB_NOT_FOUND, 'GDB was not found, so task names, frames and stack bounds are not available.')
            return
        try:
            gdb = EspGDB(self.cd.get_gdb_args(is_dbg_mode=False, **info), timeout_sec=self.cd.gdb_timeout_sec)
        except Exception as e:
            report.warn(Warn.GDB_FAILED, short_paths_in_text(f'GDB could not start ({e})'))
            return
        try:
            threads, _ = gdb.get_thread_info_retry()
            if not threads:
                report.warn(Warn.NO_GDB_THREADS, 'GDB did not return task information.')
                return
            for thr in threads:
                task = by_tcb.get(gdb.gdb2freertos_thread_id(thr['target-id']))
                if task is None:
                    continue
                self._read_task(gdb, thr['id'], task, report)
            if self.call_ra is not None:
                self.call = find_call(gdb, self.cd.exe_elf, self.call_ra)
            self._add_disassembly(report, gdb)
        finally:
            gdb.close()

    def _add_disassembly(self, report: AnalysisReport, gdb: EspGDB) -> None:
        """Attach a small disassembly window around the code that faulted or made the bad call."""
        crash = report.crash
        if self.pc_insn is not None and crash.pc is not None:
            addr, title = crash.pc, 'the faulting instruction'
        elif self.call is not None:
            addr, title = self.call[0], 'the call that ends at the return address'
        else:
            return
        # GDB reads the source itself, so the freshness rule has to be applied here too.
        # Only the function being disassembled matters: an IDF caller with no local
        # source must not hide the application source of the frame that crashed.
        frame = self._window_frame(report, addr)
        path = frame.source_path if frame is not None else None
        fresh = path is not None and source_problem(path, self.cd.prog) is None
        window = self._disassemble_window(gdb, addr, with_source=fresh)
        if window:
            report.disassembly = Disassembly(id='disasm:0', address=addr, text=window, title=title)

    @staticmethod
    def _window_frame(report: AnalysisReport, addr: int) -> Frame | None:
        """
        The crashed task's frame that holds addr.

        A frame's pc is the faulting address in frame 0 and the return address
        further out, so the frame we disassemble is the one whose pc sits at or
        just after addr. Frames in other functions are further away.
        """
        frames = [f for t in report.tasks if t.crashed for f in t.frames if f.pc is not None and f.pc >= addr]
        return min(frames, key=lambda f: f.pc - addr) if frames else None

    def _disassemble_window(self, gdb: EspGDB, addr: int, with_source: bool = True) -> str | None:
        """
        Keep a few instructions around addr, with C source interleaved when GDB
        can find it and the local file still matches the ELF.
        """
        # '/s' interleaves source lines. Fall back to plain asm if source is not available.
        plain = (f'disassemble {addr:#x}',)
        cmds = plain if no_source() or not with_source else (f'disassemble /s {addr:#x}',) + plain
        for cmd in cmds:
            try:
                text = gdb.run_cmd(cmd)
            except GDB_ERRORS:
                return None
            lines = text.splitlines()
            asm = [i for i, ln in enumerate(lines) if DISASM_ROW_RE.match(ln)]
            hit = next((k for k, i in enumerate(asm) if _row_address(lines[i]) == addr), None)
            if hit is None:
                continue
            start = asm[max(0, hit - DISASM_BEFORE)]
            end = asm[min(len(asm) - 1, hit + DISASM_AFTER)]
            # pull in the source line(s) printed right above the first kept instruction
            while start > 0 and lines[start - 1].strip() and not DISASM_ROW_RE.match(lines[start - 1]):
                start -= 1
            kept = [ln.rstrip().replace('\t', '  ') for ln in lines[start : end + 1] if ln.strip()]
            return short_paths_in_text('\n'.join(kept)) if kept else None
        return None

    def _read_task(self, gdb: EspGDB, thread_id: str, task: Task, report: AnalysisReport) -> None:
        task.name = gdb.get_freertos_task_name(task.tcb) or None
        start = self._tcb_int(gdb, task.tcb, 'pxStack')
        end = self._tcb_int(gdb, task.tcb, 'pxEndOfStack')
        if start is not None and end is not None and start < end:
            task.stack.start, task.stack.end = start, end
        if not task.crashed:
            # the saved sp of other tasks can be 0
            task.stack.sp = self._tcb_int(gdb, task.tcb, 'pxTopOfStack')

        try:
            gdb.switch_thread(thread_id)
            payload, _, error = gdb._run_mi(f'-stack-list-frames 0 {MAX_FRAMES}')
        except GDB_ERRORS:
            payload, error = None, 'GDB failed'
        if error or not payload:
            report.warn(Warn.NO_FRAMES, f'GDB did not return frames for task {task.id}.', [task.id])
            return
        frames = payload.get('stack') or []
        task_index = task.id.split(':')[1]
        if len(frames) > MAX_FRAMES:
            frames = frames[:MAX_FRAMES]
            report.warn(Warn.FRAMES_TRUNCATED, f'Only the first {MAX_FRAMES} frames of task {task.id} are shown.', [task.id])
        for index, fr in enumerate(frames):
            try:
                pc = int(fr.get('addr', ''), 16)
            except ValueError:
                continue
            func = fr.get('func')
            line = fr.get('line')
            task.frames.append(
                Frame(
                    id=f'frame:{task_index}:{index}',
                    pc=pc,
                    function=func if func and func != '??' else None,
                    file=short_path(fr.get('fullname') or fr.get('file')),
                    source_path=fr.get('fullname'),
                    line=int(line) if line and line.isdigit() else None,
                )
            )

    @staticmethod
    def _tcb_int(gdb: EspGDB, tcb: int, name: str) -> int | None:
        value = gdb.parse_tcb_variable(tcb, name)
        return int(value, 16) if re.match(r'^0x[0-9a-fA-F]+$', value or '') else None

    def _add_stack_status(self, report: AnalysisReport) -> None:
        # With CONFIG_ESP_COREDUMP_CAPTURE_DRAM the frame sits inside a larger captured
        # DRAM segment instead of starting one, so search by containment. The segment is
        # only used to tell whether an SP points at the same captured region as the frame;
        # it is not the bounds of the interrupt stack when the segment is a whole DRAM area.
        frame_segment = None
        if self.frame_addr is not None:
            frame_segment = next((s for s in self.cd.core_elf.load_segments if data_holds(s, self.frame_addr)), None)
        for task in report.tasks:
            stack = task.stack
            if stack.status == STACK_DAMAGED:
                continue
            if stack.start is None or stack.end is None or stack.sp is None:
                report.warn(Warn.NO_STACK_INFO, f'Stack bounds or SP of task {task.id} are not available.', [task.id])
                continue
            if stack.start <= stack.sp <= stack.end:
                stack.status = STACK_OK
            elif task.crashed and report.crash.in_interrupt and frame_segment is not None and data_holds(frame_segment, stack.sp):
                stack.status = STACK_ISR
            else:
                stack.status = STACK_SP_OUTSIDE

    def _add_memory_areas(self, report: AnalysisReport) -> None:
        frame_addr = self.frame_addr

        for index, seg in enumerate(self.cd.core_elf.load_segments):
            area = MemoryArea(id=f'area:{index}', start=seg.addr, size=len(seg.data), kind='data', flags=seg.attr_str().replace(' ', ''))
            seg_end = seg.addr + len(seg.data)
            if seg.flags & seg.PF_X:
                area.kind = 'code'
            for task in report.tasks:
                if seg.addr == task.tcb:
                    area.kind, area.task_id = 'task_tcb', task.id
                    break
                if task.stack.start is not None and seg.addr < task.stack.end and seg_end > task.stack.start:
                    area.kind, area.task_id = 'task_stack', task.id
                    break
            else:
                # Only a segment that starts at the frame is the saved exception stack.
                # With CONFIG_ESP_COREDUMP_CAPTURE_DRAM the frame sits inside a whole
                # captured DRAM area, and that area is not a stack. The frame address is
                # reported as fact:exception-frame instead of relabelling the segment.
                if seg.addr == frame_addr and self.crashed is not None:
                    area.kind, area.task_id = 'exception_stack', self.crashed.id
            area.elf_section = next((s.name for s in report.elf.sections if s.contains(seg.addr)), None)
            report.memory_areas.append(area)

    def _add_facts(self, report: AnalysisReport) -> None:
        crash = report.crash
        facts = report.facts

        def add(fact_id, kind, value, source):
            if value is not None:
                facts.append(Fact(fact_id, kind, value, source))

        add('fact:elf-match', 'elf_match', report.elf.match, 'coredump')
        add('fact:rom-elf', 'rom_elf', report.rom.name if report.rom else None, 'rom_elf')
        reason_source = 'panic_details' if crash.kind == 'software_panic' else 'mcause'
        add('fact:crash-kind', 'crash_kind', crash.kind, reason_source)
        add('fact:crash-reason', 'crash_reason', crash.reason, reason_source)
        add('fact:panic-details', 'panic_details', crash.panic_details, 'panic_details')
        add('fact:exception-frame', 'exception_frame_address', self.frame_addr, 'exception_frame')
        add('fact:mcause', 'mcause', crash.mcause, 'exception_frame')
        add('fact:pc', 'program_counter', crash.pc, 'exception_frame')
        add('fact:bad-address', 'bad_address', crash.bad_address, 'mtval')
        if crash.mcause == riscv.MCAUSE_BREAKPOINT:
            # mtval has no fixed meaning here: watchpoint address, PC or 0
            add('fact:mtval', 'mtval', self.mtval, 'exception_frame')
        if self.call is not None:
            add('fact:call-address', 'call_address', self.call[0], 'elf')
            add('fact:call-instruction', 'instruction', self.call[1], 'elf')
        add('fact:pc-instruction', 'instruction', self.pc_insn, 'elf')
        add('fact:in-interrupt', 'in_interrupt', crash.in_interrupt, 'extra_info')
        add('fact:core', 'core', crash.core, 'mhartid')
        add('fact:crashed-task', 'crashed_task', crash.crashed_task_id, 'extra_info')
        if self.crashed is not None:
            add('fact:crashed-sp', 'stack_pointer', self.crashed.stack.sp, 'exception_frame')
            # GDB reads the stack bounds this status is derived from. Without GDB the status
            # is never established, so record no fact rather than credit gdb with the default.
            status = self.crashed.stack.status
            add('fact:crashed-stack-status', 'stack_status', None if status == NOT_AVAILABLE else status, 'gdb')


def build_report(coredump) -> AnalysisReport:
    """Build the crash report for a CoreDump object and run the checks."""
    report = ReportCollector(coredump).build()
    run_checks(report)
    return report
