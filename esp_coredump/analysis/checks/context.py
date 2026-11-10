#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Rule: say which captured data is damaged or missing.
It does not say why. An SP outside the stack is not called a stack overflow, unless
the RISC-V stack guard fired, which it does when the SP leaves the stack.
"""

from .. import riscv
from ..report import STACK_DAMAGED, STACK_ISR, STACK_SP_OUTSIDE, Warn
from .base import Rule, get_fact

# Report warnings that mean the crash context is not complete
INCOMPLETE_WARNINGS = (
    Warn.NO_CRASHED_TASK,
    Warn.CRASHED_TASK_SKIPPED,
    Warn.CRASHED_TASK_MISSING,
    Warn.NO_EXCEPTION_FRAME,
    Warn.BAD_TASK_REGS,
    Warn.GDB_NOT_FOUND,
    Warn.GDB_FAILED,
    Warn.NO_GDB_THREADS,
    Warn.NO_FRAMES,
)


class ContextQualityRule(Rule):
    id = 'context-quality.v1'
    needs = ('tasks[].stack.status', 'warnings', 'fact:in-interrupt')

    def run(self, report):
        results = []
        warnings = [w for w in report.warnings if w.code in INCOMPLETE_WARNINGS]
        if warnings:
            text = ' '.join(w.message for w in warnings)
            results.append(self.found(f'The crash data is not complete. {text}', [w.id for w in warnings], 'report', 'incomplete'))
        if not report.tasks:
            results.append(self.not_enough_data('The core dump has no readable tasks.', subject='tasks'))
            return results

        in_isr = get_fact(report, 'fact:in-interrupt')
        mcause = get_fact(report, 'fact:mcause')
        guard = report.crash.kind != 'software_panic' and mcause is not None and mcause.value == riscv.MCAUSE_STACK_PROTECTION
        for task in report.tasks:
            subject = task.id.replace(':', '-')
            status = task.stack.status
            if status == STACK_ISR and not (in_isr and in_isr.value is True):
                # without the ISR flag this is just an SP outside the stack
                status = STACK_SP_OUTSIDE
            if status == STACK_DAMAGED:
                results.append(self.confirmed(f'The saved data of {task.id} is damaged.', [task.id], subject, 'task_damaged'))
            elif status == STACK_SP_OUTSIDE:
                evidence = [task.id]
                if task.crashed and get_fact(report, 'fact:crashed-sp'):
                    evidence.append('fact:crashed-sp')
                text = f'The SP of {task.id} is outside its stack bounds.'
                if task.crashed and guard:
                    assert mcause is not None
                    evidence.append(mcause.id)
                    text += ' The stack guard fires when the SP leaves the stack, so this is the overflow it caught, not bad task data.'
                else:
                    text += ' The SP or the task data may be wrong.'
                results.append(self.confirmed(text, evidence, subject, 'sp_outside_stack'))
            elif status == STACK_ISR:
                results.append(
                    self.found(
                        f'The crash was in an interrupt, so the SP of {task.id} is on the interrupt stack. This is normal.',
                        [task.id, 'fact:in-interrupt'],
                        subject,
                        'isr_stack',
                    )
                )
        return results
