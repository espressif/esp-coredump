#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Rule (RISC-V): a cache error, most often code that ran with the flash cache off
and then reached into flash.

ESP-IDF writes the cache error cause over the original one, so the core dump does
not show whether the failing access was an instruction fetch or a load. An mtval
in flash data away from the PC points to a load from there.
"""

from __future__ import annotations

from .. import riscv
from ..report import AnalysisReport, ElfSectionInfo
from .base import Rule, app_section_at, frame_place, get_fact

UNKNOWN = (
    'ESP-IDF reports a cache error in place of the original exception, so the core dump '
    'does not show whether the failing access was an instruction fetch or a load, and it '
    'does not save the cache state.'
)


def _data_section(report: AnalysisReport, addr: int) -> ElfSectionInfo | None:
    """The app ELF section addr falls in, data first where sections overlap."""
    sections = [s for s in report.elf.sections if s.contains(addr)]
    return next((s for s in sections if s.kind != 'code'), sections[0] if sections else None)


class CacheErrorRule(Rule):
    id = 'cache-error.v1'
    architectures = ('riscv',)
    needs = ('fact:mcause', 'fact:pc', 'crashed task frames 0 and 1', 'crashed task mtval', 'elf.sections')

    def run(self, report):
        mcause = get_fact(report, 'fact:mcause')
        if report.crash.kind == 'software_panic' or mcause is None or mcause.value != riscv.MCAUSE_CACHE_ERROR:
            return []
        pc = get_fact(report, 'fact:pc')
        if pc is None:
            return [self.confirmed('The CPU reported a cache error, but the PC is not available.', [mcause.id])]

        evidence = [mcause.id, pc.id]
        pc_section = app_section_at(report, pc.value)
        if pc_section is not None and 'flash' in pc_section.name:
            return [self._flash_code(report, pc.value, pc_section, UNKNOWN, evidence)]
        found = self._flash_mtval(report, pc.value, pc_section, evidence)
        if found is not None:
            return [found]
        # a cache error away from flash, so the flash-off pattern does not apply
        return [
            self.confirmed(
                f'The CPU reported a cache error at 0x{pc.value:08x}. The core dump does not save the cache state, so the reason is not shown.',
                evidence,
                value='cache_error',
            )
        ]

    def _flash_code(self, report, pc, pc_section, access, evidence):
        head = f'The CPU reported a cache error while running flash code at 0x{pc:08x} in {pc_section.name}.'
        # frame 0 is the flash code that faulted, frame 1 is the caller
        caller = report.crashed_frame(1)
        place = frame_place(caller)
        if not place:
            summary = f'{head} {access}'
        else:
            evidence.append(caller.id)
            section = app_section_at(report, caller.pc)
            if section is not None and 'iram' in section.name:
                summary = (
                    f'{head} The next frame is {section.name}, {place}. Code in {section.name} '
                    'often runs with the flash cache off, and then every flash address is unreachable. '
                    f'{access} Check that this path keeps the code and the data it uses out of flash.'
                )
            else:
                summary = f'{head} The next frame is {place}. {access}'
        return self.confirmed(summary, evidence, value='cache_error_in_flash_code')

    def _flash_mtval(self, report, pc, pc_section, evidence):
        """
        ESP-IDF keeps mtval of the original exception. Away from the PC and in flash
        data, it is most likely the address of a load; it can also be the bits of an
        illegal instruction, which only the original mcause would rule out.
        """
        task = report.crashed_task()
        mtval = task.registers.get('mtval') if task is not None else None
        if mtval is None or mtval == pc:
            return None
        data = _data_section(report, mtval)
        if data is None or data.kind == 'code' or 'flash' not in data.name:
            return None
        evidence.append(task.id)
        summary = (
            self._head(report, pc, evidence) + f' mtval holds 0x{mtval:08x}, which is in {data.name}. ESP-IDF keeps mtval of the '
            'original exception, where a load access fault leaves the address it loaded from, so this is most likely a load '
            'from flash data. The core dump does not save the original mcause, which would confirm it.' + _flash_off(pc_section)
        )
        return self.found(summary, evidence, value='cache_error_on_flash_data')

    @staticmethod
    def _head(report, pc, evidence):
        frame = report.crashed_frame(0)
        place = frame_place(frame)
        if place:
            evidence.append(frame.id)
        return f'The CPU reported a cache error at 0x{pc:08x}' + (f' in {place}' if place else '') + '.'


def _flash_off(pc_section: ElfSectionInfo | None) -> str:
    """Why code in IRAM can not reach flash, when the PC is in IRAM."""
    if pc_section is None or 'iram' not in pc_section.name:
        return ''
    return (
        f' Code in {pc_section.name} often runs with the flash cache off, and then every flash address is unreachable. '
        'Check that this path keeps the data it uses out of flash.'
    )
