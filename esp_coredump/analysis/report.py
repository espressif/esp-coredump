#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Report model for crash analysis. The JSON report is made from these classes.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from typing import Any

from .riscv import format_instruction

REPORT_VERSION = '1.0'
# Set to keep C source text out of the output, for example to compare it on another machine
NO_SOURCE_ENV = 'ESP_COREDUMP_NO_SOURCE'
# Values that leave it off, so that '0' does not read as "on" like any other non-empty string
NO_SOURCE_OFF = ('', '0', 'false', 'no')
NOT_AVAILABLE = 'not_available'


def no_source() -> bool:
    """True when the environment asks to keep C source text out of the output."""
    return os.environ.get(NO_SOURCE_ENV, '').strip().lower() not in NO_SOURCE_OFF


def source_problem(source_path: str | None, elf_path: str | None) -> str | None:
    """
    Why the local source file must not be shown, phrased to follow the file name,
    or None when it can be shown. The reasons otherwise look alike, because all of
    them print nothing. DWARF 4 carries no file checksum, so a timestamp newer than
    the ELF is the only sign that the line numbers may point at other code.
    """
    try:
        if not source_path or not os.path.isfile(source_path):
            return 'is not on this machine'
        if elf_path and os.path.getmtime(source_path) > os.path.getmtime(elf_path):
            return 'changed after the ELF was built'
    except OSError:
        return 'could not be read'
    return None


def hex_or_na(value: int | None) -> str:
    return NOT_AVAILABLE if value is None else f'0x{value:08x}'


def value_or_na(value: Any) -> Any:
    return NOT_AVAILABLE if value is None else value


def drop_none(data: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in data.items() if v is not None}


@dataclass
class InputInfo:
    format: str
    dump_version: int | None = None

    def to_dict(self):
        return {'kind': 'coredump', 'format': self.format, 'dump_version': hex_or_na(self.dump_version)}


@dataclass
class TargetInfo:
    chip: str
    architecture: str
    chip_rev: int | None = None

    def to_dict(self):
        return {'chip': self.chip, 'architecture': self.architecture, 'chip_rev': value_or_na(self.chip_rev)}


@dataclass
class ElfSectionInfo:
    name: str
    start: int
    size: int
    kind: str  # code, data or bss

    def contains(self, addr: int) -> bool:
        return self.start <= addr < self.start + self.size

    def to_dict(self):
        return {'name': self.name, 'start': hex_or_na(self.start), 'size': self.size, 'kind': self.kind}


@dataclass
class ElfInfo:
    name: str
    sha256: str
    match: str  # match or not_checked
    sections: list[ElfSectionInfo] = field(default_factory=list)

    def to_dict(self):
        return {
            'name': self.name,
            'sha256': self.sha256,
            'match': self.match,
            'sections': [s.to_dict() for s in self.sections],
        }


@dataclass
class RomInfo:
    """Executable sections of the ROM ELF, when one was loaded. ROM code is in no core dump."""

    name: str
    sections: list[ElfSectionInfo] = field(default_factory=list)

    def to_dict(self):
        return {'name': self.name, 'sections': [s.to_dict() for s in self.sections]}


@dataclass
class CrashInfo:
    kind: str | None = None  # software_panic, cpu_exception or interrupt
    reason: str | None = None
    panic_details: str | None = None
    core: int | None = None
    pc: int | None = None
    bad_address: int | None = None
    mcause: int | None = None
    in_interrupt: bool | None = None
    crashed_task_id: str | None = None

    def to_dict(self):
        return {
            'kind': value_or_na(self.kind),
            'reason': value_or_na(self.reason),
            'panic_details': value_or_na(self.panic_details),
            'core': value_or_na(self.core),
            'pc': hex_or_na(self.pc),
            'bad_address': hex_or_na(self.bad_address),
            'mcause': hex_or_na(self.mcause),
            'in_interrupt': value_or_na(self.in_interrupt),
            'crashed_task_id': value_or_na(self.crashed_task_id),
        }


@dataclass
class Frame:
    id: str
    pc: int
    function: str | None = None
    file: str | None = None
    line: int | None = None
    # Local path from GDB, only for printing source lines. Not in the JSON.
    source_path: str | None = field(default=None, repr=False, compare=False)

    def to_dict(self):
        return drop_none({'id': self.id, 'pc': hex_or_na(self.pc), 'function': self.function, 'file': self.file, 'line': self.line})


# Stack status values
STACK_OK = 'ok'
STACK_SP_OUTSIDE = 'sp_outside_bounds'
STACK_ISR = 'isr_stack'
STACK_DAMAGED = 'damaged'


@dataclass
class StackInfo:
    start: int | None = None
    end: int | None = None
    sp: int | None = None
    status: str = NOT_AVAILABLE

    def to_dict(self):
        return {'start': hex_or_na(self.start), 'end': hex_or_na(self.end), 'sp': hex_or_na(self.sp), 'status': self.status}


@dataclass
class Task:
    id: str
    tcb: int
    name: str | None = None
    crashed: bool = False
    registers: dict[str, int] = field(default_factory=dict)
    stack: StackInfo = field(default_factory=StackInfo)
    frames: list[Frame] = field(default_factory=list)

    def to_dict(self):
        return {
            'id': self.id,
            'tcb': hex_or_na(self.tcb),
            'name': value_or_na(self.name),
            'crashed': self.crashed,
            'registers': {k: hex_or_na(v) for k, v in self.registers.items()},
            'stack': self.stack.to_dict(),
            'frames': [f.to_dict() for f in self.frames],
        }


@dataclass
class MemoryArea:
    id: str
    start: int
    size: int
    kind: str  # task_tcb, task_stack, exception_stack, code or data
    flags: str
    task_id: str | None = None
    elf_section: str | None = None

    def contains(self, addr: int) -> bool:
        return self.start <= addr < self.start + self.size

    def to_dict(self):
        return drop_none(
            {
                'id': self.id,
                'kind': self.kind,
                'start': hex_or_na(self.start),
                'size': self.size,
                'flags': self.flags,
                'task_id': self.task_id,
                'elf_section': self.elf_section,
            }
        )


# Facts with these kinds are written as hex numbers
HEX_FACT_KINDS = ('program_counter', 'bad_address', 'mcause', 'mtval', 'stack_pointer', 'call_address', 'exception_frame_address')


@dataclass
class Fact:
    id: str
    kind: str
    value: Any
    source: str

    def to_dict(self):
        if self.kind in HEX_FACT_KINDS:
            value = hex_or_na(self.value)
        elif self.kind == 'instruction':
            value = format_instruction(self.value)
        else:
            value = self.value
        return {'id': self.id, 'kind': self.kind, 'value': value, 'source': self.source}


# Check result values
CHECK_CONFIRMED = 'confirmed'
CHECK_FOUND = 'found'
CHECK_NOT_ENOUGH_DATA = 'not_enough_data'


@dataclass
class CheckResult:
    id: str
    rule: str
    result: str  # confirmed, found or not_enough_data
    summary: str
    evidence_ids: list[str] = field(default_factory=list)
    value: str | None = None

    def to_dict(self):
        return drop_none(
            {
                'id': self.id,
                'rule': self.rule,
                'result': self.result,
                'value': self.value,
                'summary': self.summary,
                'evidence_ids': list(self.evidence_ids),
            }
        )


# One instruction row of GDB disassembly: the indent, the '=>' GDB puts on the
# current row, then the address. Source lines interleaved by '/s' do not match.
DISASM_ROW_RE = re.compile(r'^(\s*(?:=>\s*)?)(0x[0-9a-fA-F]+)\b')


@dataclass
class Disassembly:
    id: str
    address: int
    text: str
    title: str | None = None  # what the window shows, for example the call site

    def to_dict(self):
        return drop_none({'id': self.id, 'title': self.title, 'address': hex_or_na(self.address), 'text': self.text})


class Warn:
    """Warning codes. Rules match warnings by code, so each one is spelled only here."""

    ELF_NOT_CHECKED = 'elf_not_checked'
    BIN_NO_PANIC_REASON = 'bin_no_panic_reason'
    NO_ROM_ELF = 'no_rom_elf'
    ROM_ELF_MISMATCH = 'rom_elf_mismatch'
    ROM_ELF_FAILED = 'rom_elf_failed'
    BAD_TASK_INFO = 'bad_task_info'
    BAD_TASK_REGS = 'bad_task_regs'
    TASK_DAMAGED = 'task_damaged'
    NO_CRASHED_TASK = 'no_crashed_task'
    CRASHED_TASK_SKIPPED = 'crashed_task_skipped'
    CRASHED_TASK_MISSING = 'crashed_task_missing'
    NO_ISR_FLAG = 'no_isr_flag'
    NO_EXCEPTION_FRAME = 'no_exception_frame'
    NO_CRASH_REASON = 'no_crash_reason'
    GDB_NOT_FOUND = 'gdb_not_found'
    GDB_FAILED = 'gdb_failed'
    NO_GDB_THREADS = 'no_gdb_threads'
    NO_FRAMES = 'no_frames'
    FRAMES_TRUNCATED = 'frames_truncated'
    NO_STACK_INFO = 'no_stack_info'


@dataclass
class ReportWarning:
    id: str
    code: str
    message: str
    ids: list[str] = field(default_factory=list)

    def to_dict(self):
        return {'id': self.id, 'code': self.code, 'message': self.message, 'ids': list(self.ids)}


@dataclass
class AnalysisReport:
    input: InputInfo
    target: TargetInfo
    elf: ElfInfo
    crash: CrashInfo
    rom: RomInfo | None = None
    tasks: list[Task] = field(default_factory=list)
    memory_areas: list[MemoryArea] = field(default_factory=list)
    facts: list[Fact] = field(default_factory=list)
    checks: list[CheckResult] = field(default_factory=list)
    disassembly: Disassembly | None = None
    warnings: list[ReportWarning] = field(default_factory=list)

    def warn(self, code: str, message: str, ids: list[str] | None = None) -> None:
        self.warnings.append(ReportWarning(f'warning:{len(self.warnings)}', code, message, ids or []))

    def crashed_task(self) -> Task | None:
        """The task that crashed, or None when the core dump does not say which one."""
        return next((t for t in self.tasks if t.crashed), None)

    def crashed_frame(self, index: int = 0) -> Frame | None:
        """
        Backtrace frame *index* of the crashed task, or None when it is not there.

        Frame 0 is where the CPU faulted and frame 1 is its caller. This selects by
        backtrace position, unlike the summary window, which picks the frame closest
        to a disassembly address.
        """
        task = self.crashed_task()
        return task.frames[index] if task is not None and len(task.frames) > index else None

    def all_ids(self) -> set:
        ids = {t.id for t in self.tasks}
        ids.update(f.id for t in self.tasks for f in t.frames)
        ids.update(a.id for a in self.memory_areas)
        ids.update(f.id for f in self.facts)
        ids.update(w.id for w in self.warnings)
        return ids

    def to_dict(self) -> dict[str, Any]:
        return {
            'report_version': REPORT_VERSION,
            'input': self.input.to_dict(),
            'target': self.target.to_dict(),
            'elf': self.elf.to_dict(),
            'crash': self.crash.to_dict(),
            **({'rom': self.rom.to_dict()} if self.rom else {}),
            'tasks': [t.to_dict() for t in self.tasks],
            'memory_areas': [a.to_dict() for a in self.memory_areas],
            'facts': [f.to_dict() for f in self.facts],
            'checks': [c.to_dict() for c in self.checks],
            **({'disassembly': self.disassembly.to_dict()} if self.disassembly else {}),
            'warnings': [w.to_dict() for w in self.warnings],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2) + '\n'

    def write_json(self, path: str) -> None:
        """Write the report to path, only once all of it is ready, so a failed run leaves no file."""
        tmp_path = None
        try:
            directory = os.path.dirname(os.path.abspath(path))
            prefix = f'.{os.path.basename(path)}.'
            with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=directory, prefix=prefix, suffix='.tmp', delete=False) as f:
                tmp_path = f.name
                f.write(self.to_json())
            os.replace(tmp_path, path)
        finally:
            if tmp_path is not None and os.path.exists(tmp_path):
                os.remove(tmp_path)
