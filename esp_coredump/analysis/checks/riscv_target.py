#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Rule (RISC-V): the CPU tried to run code at a clearly bad address.
"""

from .. import riscv
from .base import NEAR_ZERO_LIMIT, Rule, code_section, frame_place, get_fact


class InvalidInstructionTargetRule(Rule):
    id = 'invalid-instruction-target.v1'
    architectures = ('riscv',)
    needs = ('fact:mcause', 'fact:pc (mepc)', 'fact:bad-address (mtval)', 'crashed task frame 1')

    def run(self, report):
        if report.crash.kind in ('software_panic', 'interrupt'):
            return []
        mcause = get_fact(report, 'fact:mcause')
        if mcause is None:
            return [self.not_enough_data('mcause is not available, so an instruction fetch fault can not be checked.')]
        if mcause.value not in riscv.INSTRUCTION_FETCH_CAUSES:
            return []

        pc = get_fact(report, 'fact:pc')
        bad = get_fact(report, 'fact:bad-address')
        if pc is None or bad is None:
            have = [f.id for f in (mcause, pc, bad) if f is not None]
            return [self.not_enough_data('This is an instruction fetch fault, but mepc or mtval is not available.', have)]
        if pc.value != bad.value:
            # the fault was not at the jump target itself, for example code that runs off the end of a section
            return []
        if code_section(report, pc.value) is not None:
            # the target is real code, so the fetch fault has another cause, not a wild jump
            return []

        evidence = [mcause.id, pc.id, bad.id]
        # frame 0 is the bad target, frame 1 comes from RA
        caller = report.crashed_frame(1)
        place = frame_place(caller)
        where = ''
        if place:
            evidence.append(caller.id)
            where = f' The next frame is {place}.'
        if pc.value < NEAR_ZERO_LIMIT:
            # nothing executable is mapped near zero, so the fetch fault settles this one
            return [
                self.confirmed(
                    f'The CPU tried to run code at 0x{pc.value:08x}, which is near zero, so this code address is not valid.'
                    f'{where} The core dump does not show where the bad address came from.',
                    evidence,
                    value='near_zero_target',
                )
            ]
        if report.rom is not None:
            evidence.append('fact:rom-elf')
            what = f'which is in no executable section of the app ELF or of {report.rom.name}.'
            tail = ' The core dump does not show where the address came from.'
        else:
            # without the ROM ELF, absence from the app ELF is not absence from memory
            what = 'which is in no executable section of the app ELF.'
            tail = ' It can still be ROM, which this report does not map. The core dump does not show where the address came from.'
        return [
            self.confirmed(
                f'The CPU tried to run code at 0x{pc.value:08x}, {what}{where}{tail}',
                evidence,
                value='target_outside_app_code',
            )
        ]
