# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
"""
Tests for the crash analysis that do not need an expected output file: the
machine-readable report against its schema, and rule and decoder cases that no
captured dump covers.
"""

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
from types import SimpleNamespace

import jsonschema
import pytest
from analysis_helpers import (
    ANALYSIS_CASES,
    ESP_PROG_DIR,
    TARGET,
    TEST_DIR_ABS_PATH,
    analysis_args,
    analysis_paths,
    analyze_argv,
    assert_analysis_error,
    no_source_env,
)

from esp_coredump import CoreDump
from esp_coredump.analysis import SCHEMA_PATH, collect, riscv, sections
from esp_coredump.analysis.checks import run_checks
from esp_coredump.analysis.checks.address import AddressClassRule
from esp_coredump.analysis.checks.breakpoint import BreakpointKindRule
from esp_coredump.analysis.checks.cache_error import CacheErrorRule
from esp_coredump.analysis.checks.category import CrashCategoryRule
from esp_coredump.analysis.checks.context import ContextQualityRule
from esp_coredump.analysis.checks.faulting_access import FaultingAccessRule
from esp_coredump.analysis.checks.indirect_call import IndirectCallRule
from esp_coredump.analysis.checks.riscv_target import InvalidInstructionTargetRule
from esp_coredump.analysis.collect import ReportCollector
from esp_coredump.analysis.report import (
    CHECK_CONFIRMED,
    CHECK_FOUND,
    CHECK_NOT_ENOUGH_DATA,
    NO_SOURCE_ENV,
    NOT_AVAILABLE,
    AnalysisReport,
    CheckResult,
    CrashInfo,
    Disassembly,
    ElfInfo,
    ElfSectionInfo,
    Fact,
    Frame,
    InputInfo,
    RomInfo,
    TargetInfo,
    Task,
    Warn,
    no_source,
    source_problem,
)
from esp_coredump.analysis.summary import source_lines, summary_text
from esp_coredump.corefile.elf import ElfSection, ESPCoreDumpElfFile
from esp_coredump.corefile.gdb import EspGDB
from esp_coredump.log import log


@pytest.mark.parametrize('fmt', [(), ('-t', 'b64')])
def test_missing_dump_is_an_analysis_error(tmp_path, fmt):
    """Format detection opens the file first, so the auto path must report it the same way."""
    argv = analyze_argv(str(tmp_path / 'no-such-dump.b64'), os.path.join(ESP_PROG_DIR, f'{TARGET}.elf'), *fmt)
    proc = subprocess.run([sys.executable, *argv], capture_output=True)
    assert_analysis_error(proc)


@pytest.mark.parametrize('case', ANALYSIS_CASES)
def test_report_matches_the_schema(tmp_path, case):
    """The JSON report is the documented interface, so hold it to its own schema."""
    report_path = tmp_path / 'report.json'
    proc = subprocess.run(
        [sys.executable, *analysis_args(case, ('--json', str(report_path)))],
        capture_output=True,
        env=no_source_env(),
    )
    assert proc.returncode == 0, proc.stderr.decode()
    with open(SCHEMA_PATH) as f:
        schema = json.load(f)
    report = json.loads(report_path.read_text())
    jsonschema.validate(report, schema)
    # every check must cite ids that the report defines, so a consumer can follow them
    defined = {report['crash']['crashed_task_id']}
    for key in ('tasks', 'memory_areas', 'facts', 'warnings'):
        defined.update(item['id'] for item in report[key])
    defined.update(frame['id'] for task in report['tasks'] for frame in task['frames'])
    for check in report['checks']:
        assert not set(check['evidence_ids']) - defined, check['id']


def make_report(mcause, reason=None, pc=None, bad_address=None):
    """A report with the crash fields and their facts, set as the collector sets them."""
    report = AnalysisReport(
        input=InputInfo('elf'),
        target=TargetInfo(TARGET, 'riscv'),
        elf=ElfInfo('app.elf', '0' * 64, 'match'),
        crash=CrashInfo(kind='cpu_exception', reason=reason, mcause=mcause, pc=pc, bad_address=bad_address),
    )
    report.facts.append(Fact('fact:mcause', 'mcause', mcause, 'exception_frame'))
    if pc is not None:
        report.facts.append(Fact('fact:pc', 'program_counter', pc, 'exception_frame'))
    if bad_address is not None:
        report.facts.append(Fact('fact:bad-address', 'bad_address', bad_address, 'mtval'))
    return report


def test_invalid_mcause_is_not_a_category():
    """
    IDF writes 0xDEADC0DE when it has no mcause. The value has the interrupt bit
    set, so it must not be read as an interrupt. The reason text is deliberately
    set here: with it empty, a later guard would return the same result and this
    test would pass with the sentinel check removed.
    """
    report = make_report(riscv.MCAUSE_INVALID, reason='Interrupt 1437266142')
    run_checks(report, [CrashCategoryRule()])
    assert [c.result for c in report.checks] == [CHECK_NOT_ENOUGH_DATA]
    assert report.checks[0].value is None
    assert '1437266142' not in report.checks[0].summary


def test_mcause_without_a_reason_is_not_a_category():
    """A category with no reason text would print "The CPU reported 'None'"."""
    report = make_report(riscv.MCAUSE_INTERRUPT_BIT | 7, reason=None)
    run_checks(report, [CrashCategoryRule()])
    assert [c.result for c in report.checks] == [CHECK_NOT_ENOUGH_DATA]
    assert 'None' not in report.checks[0].summary


def test_real_interrupt_is_a_category():
    """The guard above must not swallow a genuine interrupt cause."""
    report = make_report(riscv.MCAUSE_INTERRUPT_BIT | 7, reason='Interrupt 7')
    run_checks(report, [CrashCategoryRule()])
    assert report.checks[0].value == 'interrupt'


def test_every_task_warning_reaches_a_rule():
    """
    A warning nobody reads is invisible in the summary. _read_task() warns
    'no_frames', so ContextQualityRule has to list it. This caught a real gap.
    """
    report = make_report(5, reason='Load access fault')
    report.warn(Warn.NO_FRAMES, 'GDB did not return frames for task task:0.', [])
    run_checks(report, [ContextQualityRule()])
    summaries = [c.summary for c in report.checks]
    assert any('not complete' in s for s in summaries), summaries


# One real encoding per load and store form, taken from the test ELFs and checked
# against riscv32-esp-elf-objdump. (raw instruction, base register, offset, width)
MEMORY_ACCESSES = (
    (0x0004A983, 's1', 0, 4),  # lw s3,0(s1)
    (0x9DD2A283, 't0', -1571, 4),  # lw t0,-1571(t0), negative offset
    (0x4C612103, 'sp', 1222, 4),  # lw sp,1222(sp)
    (0x00178703, 'a5', 1, 1),  # lb a4,1(a5)
    (0x0197C783, 'a5', 25, 1),  # lbu a5,25(a5)
    (0x01255783, 'a0', 18, 2),  # lhu a5,18(a0)
    (0x0007A423, 'a5', 8, 4),  # sw zero,8(a5)
    (0xB80783A3, 'a5', -1145, 1),  # sb zero,-1145(a5)
    (0x00F51923, 'a0', 18, 2),  # sh a5,18(a0)
    (0x09C2A007, 't0', 156, 4),  # flw ft0,156(t0)
    (0x0802AE27, 't0', 156, 4),  # fsw ft0,156(t0)
    (0x439C, 'a5', 0, 4),  # c.lw a5,0(a5)
    (0x4858, 's0', 20, 4),  # c.lw a4,20(s0)
    (0x41B2, 'sp', 12, 4),  # c.lwsp gp,12(sp)
    (0xC808, 's0', 16, 4),  # c.sw a0,16(s0)
    (0xC206, 'sp', 4, 4),  # c.swsp ra,4(sp)
    (0x7100, 'a0', 32, 4),  # c.flw fs0,32(a0)
    (0xF100, 'a0', 32, 4),  # c.fsw fs0,32(a0)
    (0x839C, 'a5', 0, 1),  # Zcb c.lbu a5,0(a5)
    (0x83C8, 'a5', 1, 1),  # Zcb c.lbu a0,1(a5)
    (0x873C, 'a4', 2, 2),  # Zcb c.lhu a5,2(a4)
    (0x87D8, 'a5', 0, 2),  # Zcb c.lh a4,0(a5)
    (0x8BC0, 'a5', 1, 1),  # Zcb c.sb s0,1(a5)
    (0x8F98, 'a5', 0, 2),  # Zcb c.sh a4,0(a5)
)


@pytest.mark.parametrize(('insn', 'base', 'offset', 'width'), MEMORY_ACCESSES)
def test_decode_memory_access_matches_objdump(insn, base, offset, width):
    """A wrong base register or offset would name the wrong register in a finding."""
    assert riscv.decode_memory_access(insn) == (riscv.REG_NAMES.index(base), offset, width)


@pytest.mark.parametrize(
    'insn',
    [
        0xB846,  # cm.push {ra},-32: several registers at a computed offset from sp
        0xBA46,  # cm.pop {ra},32
        0x9782,  # c.jalr a5
        0x4791,  # c.li a5,4
        0x8082,  # c.ret
        0x00100073,  # ebreak
    ],
)
def test_decode_memory_access_stops_on_other_instructions(insn):
    """
    None has to mean 'no single base register and offset', so the rule stays silent
    instead of naming a register it did not decode. The Zcmp forms matter most:
    instruction_kind() calls them load and store, so only this guard keeps them out.
    """
    assert riscv.decode_memory_access(insn) is None


def access_report(mcause, insn, bad_address, registers, function='null_read'):
    """A report with the facts and the crashed task the faulting-access rule reads."""
    report = make_report(mcause, reason='Load access fault', pc=0x4000E966, bad_address=bad_address)
    report.facts.append(Fact('fact:pc-instruction', 'instruction', insn, 'elf'))
    task = Task(id='task:0', tcb=0x2F016000, name='main', crashed=True, registers=registers)
    task.frames.append(Frame(id='frame:0:0', pc=0x4000E966, function=function, file='main/test_core_dump.c', line=86))
    report.tasks.append(task)
    return report


def test_faulting_access_names_the_base_register():
    """c.lw a4,0(a5) with a5 == 0: the finding has to name a5, not the loaded register."""
    report = access_report(5, 0x87D8, 0x0, {'a5': 0x0, 'a4': 0x1234})
    run_checks(report, [FaultingAccessRule()])
    assert [c.result for c in report.checks] == [CHECK_CONFIRMED]
    check = report.checks[0]
    assert check.id == 'check:faulting-access.v1:a5'
    assert 'a5 holds 0x00000000' in check.summary
    assert 'fact:pc-instruction' in check.evidence_ids


def test_faulting_access_reports_a_store_as_a_store():
    """c.sw a5,0(a4) faults on a4, the base, not a5, which holds the stored value."""
    report = access_report(7, 0xC31C, 0x0, {'a4': 0x0, 'a5': 0xA5A5A5A5})
    run_checks(report, [FaultingAccessRule()])
    check = report.checks[0]
    assert check.result == CHECK_CONFIRMED
    assert check.id == 'check:faulting-access.v1:a4'
    assert check.value == 'store_through_register'
    assert 'writes 4 bytes' in check.summary


def test_faulting_access_checks_the_address_against_mtval():
    """
    Disagreement means our decoding or the saved registers are wrong, so no register
    is named. Without this the rule would report a confirmed finding built on a bad
    decode.
    """
    report = access_report(5, 0x87D8, 0x2000, {'a5': 0x0})
    run_checks(report, [FaultingAccessRule()])
    assert [c.result for c in report.checks] == [CHECK_NOT_ENOUGH_DATA]
    assert 'but the CPU reported 0x00002000' in report.checks[0].summary


def test_faulting_access_needs_the_register():
    """Only the crashed task has registers, and a damaged frame has none."""
    report = access_report(5, 0x87D8, 0x0, {})
    run_checks(report, [FaultingAccessRule()])
    assert report.checks == []


def test_faulting_access_skips_fetch_faults():
    """A fetch fault belongs to indirect-call.v1: there the PC is the jump target."""
    report = access_report(1, 0x87D8, 0x4000E966, {'a5': 0x4000E966})
    run_checks(report, [FaultingAccessRule()])
    assert report.checks == []


def test_faulting_access_says_so_when_the_form_is_unsupported():
    """A Zcmp stack fault still gets an answer, naming why no register is given."""
    report = access_report(7, 0xB846, 0x0, {'sp': 0x0})
    run_checks(report, [FaultingAccessRule()])
    assert [c.result for c in report.checks] == [CHECK_NOT_ENOUGH_DATA]
    assert 'not a load or store' in report.checks[0].summary


@pytest.mark.parametrize(
    'mcause, insn, expected, decoded',
    [
        (5, 0xC31C, 'load', 'store'),  # load fault, but sw a5,0(a4)
        (7, 0x439C, 'store', 'load'),  # store fault, but lw a5,0(a5)
    ],
)
def test_faulting_access_requires_the_direction_to_match_mcause(mcause, insn, expected, decoded):
    """A matching address must not outvote mcause: a disagreement means the evidence is wrong."""
    report = access_report(mcause, insn, 0x0, {'a4': 0x0, 'a5': 0x0})
    run_checks(report, [FaultingAccessRule()])
    assert [c.result for c in report.checks] == [CHECK_NOT_ENOUGH_DATA]
    assert f'reported a {expected} fault' in report.checks[0].summary
    assert f'is a {decoded}' in report.checks[0].summary


@pytest.mark.parametrize('insn', [0x0007B503, 0x0007E503, 0x00F7B023])  # ld, lwu, sd
def test_decode_memory_access_rejects_rv64_only_widths(insn):
    """Every supported target is RV32, so an RV64 integer width is not code that ran."""
    assert riscv.decode_memory_access(insn) is None


@pytest.mark.parametrize(
    'mcause, insn, bad, operand',
    [
        (5, 0x00002503, 0x0, '0(zero)'),  # lw a0,0(zero)
        (5, 0x01002503, 0x10, '16(zero)'),  # lw a0,16(zero)
        (7, 0x00A02023, 0x0, '0(zero)'),  # sw a0,0(zero)
    ],
)
def test_faulting_access_treats_x0_as_zero(mcause, insn, bad, operand):
    """x0 reads as zero on every core, so the collector saves no word for it and none is needed."""
    report = access_report(mcause, insn, bad, {'pc': 0x4000E966, 'a0': 0x1234})
    run_checks(report, [FaultingAccessRule()])
    assert [c.result for c in report.checks] == [CHECK_CONFIRMED]
    check = report.checks[0]
    assert check.id == 'check:faulting-access.v1:zero'
    assert operand in check.summary
    assert 'wired to zero' in check.summary


class FakeSection:
    """One executable section, so a read can be asked for more bytes than are there."""

    flags = ElfSection.SHF_EXECINSTR

    def __init__(self, addr, data):
        self.addr = addr
        self.data = data


@pytest.mark.parametrize(
    'data, expected',
    [
        (b'\x82\x80', 0x8082),  # a whole c.ret at the very end still reads
        (b'\x03\xa5', None),  # two bytes of a four byte load
        (b'\x03\xa5\x00', None),  # three bytes of a four byte load
        (b'\x03\xa5\x00\x00', 0x0000A503),  # all four bytes are there
    ],
)
def test_read_instruction_needs_every_byte(data, expected):
    """A short read would leave the upper half zero, which names a register the code never used."""
    elf = SimpleNamespace(sections=[FakeSection(0x40000000, data)])
    assert sections.read_instruction(elf, 0x40000000) == expected


def test_disassembly_source_ignores_callers_without_source(tmp_path):
    """An IDF caller with no local source must not hide the application source of frame 0."""
    elf = tmp_path / 'app.elf'
    elf.write_text('elf')
    src = tmp_path / 'main.c'
    src.write_text('int main(void) { return 0; }')
    os.utime(elf, (src.stat().st_mtime + 10, src.stat().st_mtime + 10))

    report = make_report(5, pc=0x40001000)
    task = Task(id='task:0', tcb=0x2F016000, name='main', crashed=True)
    task.frames.append(Frame(id='frame:0:0', pc=0x40001000, function='null_read', source_path=str(src)))
    task.frames.append(Frame(id='frame:0:1', pc=0x40002000, function='main_task', source_path='/absent/app_startup.c'))
    report.tasks.append(task)

    asked = []

    class RecordingGDB:
        def run_cmd(self, cmd):
            asked.append(cmd)
            return 'Dump of assembler code\nEnd of assembler dump.'

    collector = ReportCollector(SimpleNamespace(prog=str(elf)))
    collector.pc_insn = 0x87D8
    collector._add_disassembly(report, RecordingGDB())
    assert any('/s' in cmd for cmd in asked), asked


def test_source_problem_names_the_reason(tmp_path):
    """All the reasons print nothing on their own, so each one has to be named."""
    elf = tmp_path / 'app.elf'
    elf.write_text('elf')
    src = tmp_path / 'main.c'
    src.write_text('int main(void) { return 0; }')
    os.utime(src, (1, 1))
    assert source_problem(str(src), str(elf)) is None
    os.utime(src, (2**31, 2**31))
    assert source_problem(str(src), str(elf)) == 'changed after the ELF was built'
    assert source_problem(str(tmp_path / 'gone.c'), str(elf)) == 'is not on this machine'
    assert source_problem(None, str(elf)) == 'is not on this machine'


def test_summary_says_why_source_is_missing(tmp_path, monkeypatch):
    monkeypatch.delenv(NO_SOURCE_ENV, raising=False)
    elf = tmp_path / 'app.elf'
    elf.write_text('elf')
    frame = Frame('frame:0', 0x40000000, 'f', 'main/app_main.c', 10, source_path=str(tmp_path / 'gone.c'))
    assert [line.plain for line in source_lines(frame, str(elf))] == ['  source not shown because main/app_main.c is not on this machine']
    # a frame the debug info gave no file for has no source to explain
    assert source_lines(Frame('frame:1', 0x40000000, 'f', None, None), str(elf)) == []


@pytest.mark.parametrize(
    'value, expected',
    [
        (None, False),
        ('', False),
        ('0', False),
        ('false', False),
        ('NO', False),
        ('1', True),
        ('true', True),
    ],
)
def test_no_source_reads_the_environment(monkeypatch, value, expected):
    """A value that spells "off" must not turn it on just by being a non-empty string."""
    if value is None:
        monkeypatch.delenv(NO_SOURCE_ENV, raising=False)
    else:
        monkeypatch.setenv(NO_SOURCE_ENV, value)
    assert no_source() is expected


@pytest.mark.parametrize(
    'insn, kind',
    [
        (0xB846, 'store'),  # cm.push {ra},-32
        (0xBA46, 'load'),  # cm.pop {ra},32
        (0xBE42, 'load'),  # cm.popret {ra},32
        (0xC63E, 'store'),  # c.swsp a5,12(sp)
        (0x47B2, 'load'),  # c.lwsp a5,12(sp)
        (0x9782, 'other'),  # c.jalr a5
        (0x8082, 'other'),  # c.ret
        (0xB802, 'other'),  # reserved rlist, not a stack instruction at all
        (0x9002, 'ebreak'),  # c.ebreak
        (0x00100073, 'ebreak'),  # ebreak
    ],
)
def test_instruction_kind(insn, kind):
    """
    Zcmp reuses the encodings of the compressed double-word stack stores, so the
    quadrant and funct3 alone would call cm.pop a store. A false store sends the
    breakpoint rule looking for a stack overflow.
    """
    assert riscv.instruction_kind(insn) == kind


def test_four_bytes_before_a_return_address_are_ambiguous():
    """
    Why the call site is resolved with GDB instead of the four bytes before the
    return address: 'lui' followed by 'c.jalr a5' is a valid stream whose last
    four bytes also decode as a 32-bit jalr through another register. Only a
    linear decode from the start of the function tells the two apart.
    """
    stream = bytes.fromhex('b700e78082 97'.replace(' ', ''))
    misleading = int.from_bytes(stream[-4:], 'little')
    assert riscv.decode_jalr(misleading) is not None
    real = int.from_bytes(stream[-2:], 'little')
    assert riscv.decode_jalr(real) == (15, 1, 0)  # c.jalr a5


# What GDB prints for read_id_core in esp32s31.elf, around its c.jalr a5 at 0x2f0004c4.
# find_call reads the real instruction bytes, so the text and that ELF must agree.
INDIRECT_CALL_DISASSEMBLY = """Dump of assembler code for function read_id_core:
   0x2f0004ba <+12>:\tmv\ts2,a0
   0x2f0004bc <+14>:\tlw\ta5,736(gp)
   0x2f0004c0 <+18>:\tlw\ta5,0(a5)
   0x2f0004c2 <+20>:\tmv\ta0,s1
   0x2f0004c4 <+22>:\tjalr\ta5
   0x2f0004c6 <+24>:\tbnez\ta0,0x2f00051a
End of assembler dump."""


class FakeGDB:
    def __init__(self, text):
        self.text = text

    def run_cmd(self, cmd):
        return self.text


def find_call(ra, text=INDIRECT_CALL_DISASSEMBLY):
    """Run collect.find_call against one disassembly, with the real ELF behind it."""
    elf = ESPCoreDumpElfFile(os.path.join(ESP_PROG_DIR, f'{TARGET}.elf'))
    return collect.find_call(FakeGDB(text), elf, ra)


def test_find_call_takes_the_instruction_that_ends_at_ra():
    """0x2f0004c4 is a two byte c.jalr, and the four bytes before RA start inside the mv."""
    assert find_call(0x2F0004C6) == (0x2F0004C4, 0x9782)


def test_find_call_needs_a_row_starting_at_ra():
    """An RA that no row starts at leaves the call unknown instead of picking a neighbour."""
    assert find_call(0x2F0004C7) is None


# One row ending at 0x4000e968, so the resolver reads whatever the ELF holds at 0x4000e964
ONE_CALL_ROW = 'Dump of assembler code for function f:\n   0x4000e964 <+0>:\tjalr\n   0x4000e968 <+4>:\tret\n'


@pytest.mark.parametrize(
    'insn, resolved',
    [
        (0x000280E7, True),  # jalr ra,0(t0): links, so it can be where RA came from
        (0x00028067, False),  # jalr zero,0(t0): a plain jump, it never writes RA
        (0x000282E7, False),  # jalr t0,0(t0): links, but not to RA
    ],
)
def test_find_call_needs_a_jump_that_links_to_ra(monkeypatch, insn, resolved):
    """
    Only an instruction that writes the return address can be where it came
    from. These three differ in rd alone, so the test fails if rd is ignored.
    """
    monkeypatch.setattr(sections, 'read_code', lambda elf, addr, size: insn.to_bytes(4, 'little'))
    assert (find_call(0x4000E968, ONE_CALL_ROW) is not None) == resolved


def rom_report(mcause=1, pc=0x40000100, rom=True):
    """A report whose PC is in ROM code, with or without the ROM ELF mapped."""
    report = make_report(mcause, reason='Instruction access fault', pc=pc, bad_address=pc)
    report.elf.sections.append(ElfSectionInfo('.flash.text', 0x42000000, 0x1000, 'code'))
    if rom:
        report.rom = RomInfo('esp32s31_rev0_rom.elf', [ElfSectionInfo('.text', 0x40000000, 0x10000, 'code')])
    report.facts.append(Fact('fact:rom-elf', 'rom_elf', report.rom.name if report.rom else None, 'rom_elf'))
    return report


def test_rom_code_is_named_not_guessed():
    """With the ROM ELF mapped, an address in ROM is ROM, not 'can be ROM or garbage'."""
    report = rom_report()
    run_checks(report, [AddressClassRule()])
    summary = report.checks[0].summary
    assert report.checks[0].value == 'rom_code', summary
    assert '.text' in summary and 'fact:rom-elf' in report.checks[0].evidence_ids


def test_a_fetch_fault_in_rom_is_not_an_invalid_target():
    """
    ROM is executable code. A fetch fault there has some other cause, so the
    rule must stay quiet rather than call the address invalid.
    """
    report = rom_report()
    run_checks(report, [InvalidInstructionTargetRule()])
    assert report.checks == []


def test_without_the_rom_elf_a_rom_address_stays_unknown():
    """The same address, with no ROM ELF: the rule may not pretend to know."""
    report = rom_report(rom=False)
    run_checks(report, [InvalidInstructionTargetRule()])
    assert len(report.checks) == 1
    assert 'ROM, which this report does not map' in report.checks[0].summary


@pytest.mark.parametrize('kind, site', [('data', 's_dram_code (data, .dram0.data)'), ('code', 's_dram_code()')])
def test_crash_site_in_data_is_named_as_a_variable(kind, site):
    """A PC in a data section, like a buffer called through a pointer, is a variable and not a function."""
    report = make_report(1, reason='Instruction access fault', pc=0x2F00BB20, bad_address=0x2F00BB20)
    report.elf.sections.append(ElfSectionInfo('.dram0.data', 0x2F00B000, 0x1000, kind))
    task = Task(id='task:0', tcb=0x2F016000, name='main', crashed=True)
    task.frames.append(Frame(id='frame:0:0', pc=0x2F00BB20, function='s_dram_code'))
    task.frames.append(Frame(id='frame:0:1', pc=0x4000DA88, function='execute_dram_buffer', file='main/app_main.c', line=1198))
    report.tasks.append(task)
    lines = summary_text(report).plain.splitlines()
    assert lines[lines.index('Called from:') - 1] == f'  in {site}'


def test_cache_error_names_the_code_section_where_sections_overlap():
    """Sections can overlap. The PC runs code, so a data section listed first must not name it."""
    report = make_report(riscv.MCAUSE_CACHE_ERROR, reason='Cache error', pc=0x42000100)
    report.elf.sections.append(ElfSectionInfo('.flash.rodata', 0x42000000, 0x2000, 'data'))
    report.elf.sections.append(ElfSectionInfo('.flash.text', 0x42000000, 0x1000, 'code'))
    run_checks(report, [CacheErrorRule()])
    assert report.checks[0].value == 'cache_error_in_flash_code'
    assert 'in .flash.text.' in report.checks[0].summary


def test_cache_error_with_mtval_in_flash_data_points_to_a_load():
    """ESP-IDF keeps mtval of the original exception, and a load access fault leaves the address it loaded from."""
    report = make_report(riscv.MCAUSE_CACHE_ERROR, reason='Cache error', pc=0x40800020)
    report.elf.sections.append(ElfSectionInfo('.iram0.text', 0x40800000, 0x1000, 'code'))
    report.elf.sections.append(ElfSectionInfo('.flash.rodata', 0x42000000, 0x1000, 'data'))
    report.tasks.append(Task(id='task:0', tcb=0x2F016000, crashed=True, registers={'mtval': 0x42000010}))
    run_checks(report, [CacheErrorRule()])
    assert (report.checks[0].result, report.checks[0].value) == (CHECK_FOUND, 'cache_error_on_flash_data')
    assert 'mtval holds 0x42000010, which is in .flash.rodata' in report.checks[0].summary


def test_a_missing_category_explains_itself_in_the_summary():
    """
    The headline carries the category, so a category finding that only restates
    it is hidden. A result that explains missing data is not a restatement, and
    the terminal is the only place most people look.
    """
    report = make_report(0x10, reason=None)
    run_checks(report, [CrashCategoryRule()])
    summary = summary_text(report).plain
    assert 'mcause 0x10' in summary, summary


def test_a_positive_category_stays_out_of_the_findings():
    """The counterpart: a known category is already in the headline."""
    report = make_report(5, reason='Load access fault')
    run_checks(report, [CrashCategoryRule()])
    assert 'Findings:\n  none\n' in summary_text(report).plain


def styled_report(tmp_path):
    """A report with every confidence level, a warning, and a source line holding brackets."""
    source = tmp_path / 'app_main.c'
    source.write_text('void f(int *arr, int i)\n{\n    arr[i] = 0;\n}\n')
    report = make_report(5, reason='Store access fault')
    report.disassembly = Disassembly(
        id='disasm:0',
        address=0x4000EA08,
        title='the faulting instruction',
        text='Dump of assembler code for function f:\n   0x4000ea04 <+12>:  lui  a5,0xa5a5a\n   0x4000ea08 <+16>:  sw  a5,0(a4)\n   0x4000ea0a <+18>:  ret',
    )
    report.tasks.append(
        Task(
            'task:0',
            0x3FC8,
            name='main',
            crashed=True,
            frames=[
                Frame('frame:0', 0x4000EA08, 'f', 'main/app_main.c', 3, str(source)),
                Frame('frame:1', 0x4000EB00, 'app_main', 'main/app_main.c', 9),
            ],
        )
    )
    for index, result in enumerate((CHECK_CONFIRMED, CHECK_FOUND, CHECK_NOT_ENOUGH_DATA)):
        report.checks.append(CheckResult(f'check:{index}', f'rule-{index}.v1', result, 'Something about arr[i].'))
    report.warn(Warn.NO_ROM_ELF, 'The ROM ELF was not found.')
    return report


def printed_by_log(text):
    """What the production print path puts on a piped stdout, through the real logger."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        log.stdout.print(text, soft_wrap=True)
    return buf.getvalue()


def test_styling_does_not_change_what_a_pipe_receives(tmp_path):
    """[confirmed] and arr[i] would be read as Rich markup in a str, and dropped without an error."""
    report = styled_report(tmp_path)
    plain = summary_text(report).plain
    assert 'arr[i] = 0;' in plain
    assert printed_by_log(summary_text(report)) == plain + '\n'


@pytest.mark.parametrize(
    'name, mapped',
    [
        ('esp32s31_rev0_rom.elf', True),
        ('esp32c3_rev0_rom.elf', False),  # another chip maps real addresses to the wrong code
        ('esp32_rev0_rom.elf', False),  # 'esp32' is also the start of 'esp32s31'
        ('rom.elf', False),  # nothing ties it to this target
    ],
)
def test_rom_elf_must_belong_to_the_target(tmp_path, monkeypatch, name, mapped):
    """A ROM ELF of another chip would make the analysis confidently wrong."""
    rom = tmp_path / name
    shutil.copy(os.path.join(ESP_PROG_DIR, f'{TARGET}.elf'), rom)
    report = make_report(1, reason='Instruction access fault')
    elf = ESPCoreDumpElfFile(os.path.join(ESP_PROG_DIR, f'{TARGET}.elf'))
    collector = ReportCollector(SimpleNamespace(get_rom_elf_path=lambda chip_rev, target: str(rom), exe_elf=elf))
    collector._add_rom(report, TARGET, 0)
    assert (report.rom is not None) == mapped
    assert mapped or report.warnings[0].code == Warn.ROM_ELF_MISMATCH


@pytest.mark.parametrize(
    'mtval, held',
    [
        (None, 'mtval was not saved'),
        (0, 'mtval is 0x00000000'),
        (0x4000E966, 'mtval holds the PC'),
    ],
)
def test_breakpoint_does_not_claim_a_breakpoint_for_an_ambiguous_access(mtval, held):
    """
    A load or store raised mcause 3, so a watchpoint fits the state as well as a hardware
    breakpoint. Without an mtval that carries an address, neither may be named.
    """
    report = make_report(riscv.MCAUSE_BREAKPOINT, reason='Breakpoint', pc=0x4000E966)
    # c.lw a4,0(a5): a load, so mtval is what would separate the two causes
    report.facts.append(Fact('fact:pc-instruction', 'instruction', 0x87D8, 'elf'))
    if mtval is not None:
        report.facts.append(Fact('fact:mtval', 'mtval', mtval, 'exception_frame'))
    run_checks(report, [BreakpointKindRule()])
    assert [c.result for c in report.checks] == [CHECK_NOT_ENOUGH_DATA]
    check = report.checks[0]
    assert held in check.summary
    assert 'hardware breakpoint' in check.summary
    assert check.value is None


def test_breakpoint_still_names_a_hardware_trigger_for_a_non_access():
    """An instruction that touches no memory cannot be a watchpoint, so the finding stands."""
    report = make_report(riscv.MCAUSE_BREAKPOINT, reason='Breakpoint', pc=0x4000E966)
    report.facts.append(Fact('fact:pc-instruction', 'instruction', 0x00000013, 'elf'))  # nop
    run_checks(report, [BreakpointKindRule()])
    assert [c.result for c in report.checks] == [CHECK_FOUND]
    assert report.checks[0].value == 'hw_breakpoint'


def test_indirect_call_needs_the_base_register_to_be_saved():
    """
    A missing register must not read as zero: that would invent a NULL function pointer.
    The collector saves all registers or none, so this guards the rule, not a captured dump.
    """
    # the target is 0x0, so an assumed-zero a5 would match it and read as a NULL pointer
    report = make_report(1, reason='Instruction access fault', pc=0x0, bad_address=0x0)
    report.facts.append(Fact('fact:call-address', 'call_address', 0x4000E960, 'elf'))
    # jalr a5: the base is a5, which this task never saved
    report.facts.append(Fact('fact:call-instruction', 'instruction', 0x000780E7, 'elf'))
    report.tasks.append(Task(id='task:0', tcb=0x2F016000, name='main', crashed=True, registers={'pc': 0x0}))
    run_checks(report, [IndirectCallRule()])
    assert report.checks == []


def test_thread_info_is_asked_again_only_while_gdb_is_silent():
    """An empty thread list is an answer: asking again would wait longer for the same one."""
    waits = []
    answers = iter([(None, None), ([], None)])
    gdb = EspGDB.__new__(EspGDB)
    gdb.timeout = 2
    gdb.get_thread_info = lambda delay: waits.append(delay) or next(answers)
    assert gdb.get_thread_info_retry() == ([], None)
    assert waits == [2, 4]


def test_stack_status_is_not_attributed_to_gdb_when_it_was_never_read():
    """
    GDB reads the bounds the status comes from. Without GDB the status stays not_available,
    and a fact claiming gdb established it would be false provenance.
    """
    collector = ReportCollector(None)
    collector.crashed = Task(id='task:0', tcb=0x2F016000, crashed=True)
    collector.crashed.stack.sp = 0x2F019B40
    assert collector.crashed.stack.status == NOT_AVAILABLE
    collector.frame_addr = 0x2F019AA0
    report = make_report(5, reason='Load access fault')
    collector._add_facts(report)
    assert [f.id for f in report.facts if f.id == 'fact:crashed-stack-status'] == []
    assert [f.id for f in report.facts if f.id == 'fact:crashed-sp'] == ['fact:crashed-sp']


def test_error_paths_are_not_read_as_rich_markup(tmp_path):
    """
    log.die renders Rich markup, so a path holding '[' and ']' must be escaped. Without
    escaping Rich eats '[bold red]' as a style tag and the message names a path that
    does not exist. Every OSError message also opens with '[Errno N]'.
    """
    bad_dir = tmp_path / '[bold red]dir'
    bad_dir.mkdir()
    missing = bad_dir / 'missing.elf'
    core, _, _ = analysis_paths('null_write')
    proc = subprocess.run(
        [sys.executable, *analyze_argv(core, str(missing), '-t', 'b64')],
        capture_output=True,
        env=no_source_env(),
    )
    stderr = assert_analysis_error(proc)
    # the whole directory name survives, rather than Rich consuming the tag
    assert '[bold red]dir' in stderr.replace('\n', '')


def test_unwritable_json_destination_is_an_analysis_error(tmp_path):
    """
    The JSON write is inside the guarded section, so a bad destination reports the same way
    as any other missing input and never prints a summary implying the file is there.
    """
    missing_dir = tmp_path / 'no-such-dir' / 'report.json'
    proc = subprocess.run(
        [sys.executable, *analysis_args('null_write', ('--json', str(missing_dir)))],
        capture_output=True,
        env=no_source_env(),
    )
    assert_analysis_error(proc)
    assert not missing_dir.exists()
    assert 'Crash:' not in proc.stdout.decode()


def dram_collector(frame_offset, seg_size=0x400):
    """A collector whose exception frame sits inside one larger captured DRAM segment."""
    segment = SimpleNamespace(
        addr=0x2F019000,
        data=bytes(seg_size),
        flags=0,
        PF_X=0x1,
        attr_str=lambda: 'RW',
    )
    collector = ReportCollector(SimpleNamespace(core_elf=SimpleNamespace(load_segments=[segment])))
    collector.frame_addr = 0x2F019000 + frame_offset
    collector.crashed = Task(id='task:0', tcb=0x2F016000, crashed=True)
    return collector


def test_a_containing_dram_segment_is_not_called_an_exception_stack():
    """A whole captured DRAM area is not a stack, so it keeps the kind it earns on its own."""
    collector = dram_collector(0x100)
    report = make_report(5, reason='Load access fault')
    collector._add_memory_areas(report)
    assert [a.kind for a in report.memory_areas] == ['data']


def test_a_segment_starting_at_the_frame_is_the_exception_stack():
    """Without CAPTURE_DRAM the saved stack starts at the frame, and that is a stack."""
    collector = dram_collector(0)
    report = make_report(5, reason='Load access fault')
    collector._add_memory_areas(report)
    assert [a.kind for a in report.memory_areas] == ['exception_stack']
    assert report.memory_areas[0].task_id == 'task:0'


def test_the_frame_address_is_reported_as_a_fact():
    """The frame location is reported instead of relabelling the segment that contains it."""
    collector = dram_collector(0x100)
    collector.crashed.stack.sp = 0x2F019100
    report = make_report(5, reason='Load access fault')
    collector._add_facts(report)
    fact = next(f for f in report.facts if f.id == 'fact:exception-frame')
    assert fact.value == collector.frame_addr
    assert fact.source == 'exception_frame'
    assert fact.to_dict()['value'] == f'0x{collector.frame_addr:08x}'


@pytest.mark.parametrize(
    'sp, in_interrupt, expected',
    [
        # SP on the interrupt stack, inside the segment that holds the frame. The frame
        # is 0x100 into that segment, so matching only a segment start would miss it.
        (0x2F019200, True, 'isr_stack'),
        # same SP, but nothing recorded an interrupt, so the region alone proves nothing
        (0x2F019200, False, 'sp_outside_bounds'),
        # an interrupt, but SP is nowhere near the captured frame
        (0x50000000, True, 'sp_outside_bounds'),
        # SP inside the task's own stack wins over both
        (0x2F030100, True, 'ok'),
    ],
)
def test_stack_status_classifies_an_interrupt_stack(sp, in_interrupt, expected):
    """
    Under CONFIG_ESP_COREDUMP_CAPTURE_DRAM the frame sits in a whole DRAM area, so
    STACK_ISR rests on three things together: in_interrupt from extra_info, an SP
    outside the task's own bounds, and an SP in the same captured region as the frame.
    """
    collector = dram_collector(0x100)
    report = make_report(5, reason='Load access fault')
    report.crash.in_interrupt = in_interrupt
    task = Task(id='task:0', tcb=0x2F030000, name='main', crashed=True)
    task.stack.start, task.stack.end, task.stack.sp = 0x2F030000, 0x2F031000, sp
    report.tasks.append(task)
    collector._add_stack_status(report)
    assert task.stack.status == expected


def test_coredump_analyze_method_is_the_public_entry_point(tmp_path, capsys, monkeypatch):
    """
    idf.py builds a CoreDump and calls a method on it, as it does for info_corefile.
    Without this method an integration would have to import esp_coredump.analysis itself.
    """
    json_path = tmp_path / 'report.json'
    coredump = CoreDump(
        chip=TARGET,
        core=os.path.join(TEST_DIR_ABS_PATH, TARGET, 'coredump_null_write.b64'),
        core_format='b64',
        prog=os.path.join(ESP_PROG_DIR, f'{TARGET}_null_write.elf'),
    )
    monkeypatch.setenv(NO_SOURCE_ENV, '1')
    coredump.analyze(json_path=str(json_path))
    assert 'Crash:' in capsys.readouterr().out
    report = json.loads(json_path.read_text())
    assert report['report_version'] == '1.0'
    jsonschema.validate(report, json.loads(open(SCHEMA_PATH).read()))
