#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Rule (RISC-V): say where the CPU was when the interrupt watchdog fired.
IDF masks interrupts by raising the interrupt threshold, not by clearing
mstatus.MIE, and the core dump does not save the threshold. So this rule
does not say if interrupts were masked.
"""

from .. import riscv
from .base import Rule, frame_place, get_fact

IWDT_CAUSES = {cause: cpu for cpu, cause in enumerate(riscv.INTERRUPT_WDT_CAUSES)}


class InterruptWatchdogRule(Rule):
    id = 'interrupt-watchdog.v1'
    architectures = ('riscv',)
    needs = ('fact:mcause', 'fact:pc', 'fact:core', 'fact:pc-instruction', 'crashed task frame 0')

    def run(self, report):
        mcause = get_fact(report, 'fact:mcause')
        # after a software panic the saved mcause does not describe the crash
        if report.crash.kind == 'software_panic' or mcause is None or mcause.value not in IWDT_CAUSES:
            return []
        cpu = IWDT_CAUSES[mcause.value]
        pc = get_fact(report, 'fact:pc')
        if pc is None:
            return [self.not_enough_data(f'Interrupts on CPU{cpu} did not run for too long, but the PC is not available.', [mcause.id])]

        core = get_fact(report, 'fact:core')
        if core is None or core.value != cpu:
            # the saved registers are from another CPU, so they do not show where CPU{cpu} was
            return [
                self.not_enough_data(
                    f'Interrupts on CPU{cpu} did not run for too long, but the saved registers are not from CPU{cpu}.',
                    [f.id for f in (mcause, core) if f is not None],
                )
            ]
        evidence = [mcause.id, pc.id, core.id]
        frame = report.crashed_frame()
        where = frame_place(frame)
        if where:
            evidence.append(frame.id)
        else:
            where = f'0x{pc.value:08x}'
        summary = f'Interrupts on CPU{cpu} did not run for too long, so the watchdog was not fed. CPU{cpu} was running {where}.'

        insn = get_fact(report, 'fact:pc-instruction')
        if insn is not None and riscv.is_self_jump(insn.value):
            evidence.append(insn.id)
            return [
                self.confirmed(
                    f'{summary} The instruction there jumps to itself, so the code is an endless empty loop. '
                    'Check the path into it for interrupts left masked, for example by portDISABLE_INTERRUPTS(). '
                    'The core dump does not show how long the loop ran or what masked interrupts.',
                    evidence,
                    value='endless_loop',
                )
            ]
        return [
            self.found(
                f'{summary} Common causes are code that runs too long with interrupts masked, a long critical section '
                'or a long ISR. The core dump does not save the interrupt mask, so it can not show which one.',
                evidence,
                value='long_masked_code',
            )
        ]
