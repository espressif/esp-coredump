#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Rule (RISC-V): tell what raised a breakpoint exception.
The CPU uses mcause 3 for an ebreak instruction, a hardware breakpoint and a
watchpoint, so IDF prints "Breakpoint" for all of them.
"""

from .. import riscv
from .base import Rule, get_fact

# FreeRTOS watches this many bytes at the start of the task stack (port.c)
STACK_WATCH_AREA_SIZE = 32


class BreakpointKindRule(Rule):
    id = 'breakpoint-kind.v1'
    architectures = ('riscv',)
    needs = ('fact:mcause', 'fact:pc', 'fact:mtval', 'fact:pc-instruction', 'task stack bounds')

    def run(self, report):
        mcause = get_fact(report, 'fact:mcause')
        if report.crash.kind == 'software_panic' or mcause is None or mcause.value != riscv.MCAUSE_BREAKPOINT:
            return []
        pc = get_fact(report, 'fact:pc')
        insn = get_fact(report, 'fact:pc-instruction')
        if pc is None or insn is None:
            have = [f.id for f in (mcause, pc) if f is not None]
            return [self.not_enough_data('The instruction at the PC is not in the ELF, so the breakpoint source is not known.', have)]

        kind = riscv.instruction_kind(insn.value)
        evidence = [mcause.id, pc.id, insn.id]
        if kind == 'ebreak':
            return [
                self.confirmed(
                    f'The instruction at 0x{pc.value:08x} is ebreak. It is usually there on purpose, from '
                    '__builtin_trap(), an assert that compiles to a trap, or a breakpoint left in the source, '
                    'but code that runs into it by accident reaches it the same way. Whether ebreak raises an '
                    'exception or enters debug mode depends on a debug configuration the core dump does not save, '
                    'and an execution trigger can raise this exception before the instruction runs.',
                    evidence,
                    value='ebreak_instruction',
                )
            ]

        if kind not in ('load', 'store'):
            return [
                self.found(
                    f'The instruction at 0x{pc.value:08x} is not ebreak and does not access memory, so a '
                    'hardware trigger fired, for example a breakpoint set with esp_cpu_set_breakpoint() '
                    'or left by a debugger.',
                    evidence,
                    value='hw_breakpoint',
                )
            ]

        mtval = get_fact(report, 'fact:mtval')
        if mtval is None:
            held = 'mtval was not saved'
        elif mtval.value == 0:
            held = 'mtval is 0x00000000'
        elif mtval.value == pc.value:
            held = 'mtval holds the PC'
        else:
            held = None
        if mtval is not None:
            evidence.append(mtval.id)
        if held is not None:
            # A load or store raised this, so a watchpoint is as consistent with the state as a
            # breakpoint. mtval would separate them, but here it is missing or carries no address.
            # Ruling out ebreak does not establish a hardware breakpoint, so name neither.
            return [
                self.not_enough_data(
                    f'The instruction at 0x{pc.value:08x} is a {kind} and {held}, so a watchpoint and a hardware breakpoint cannot be told apart.',
                    evidence,
                )
            ]

        summary = f'This is a watchpoint, not a breakpoint. The {kind} at 0x{pc.value:08x} accessed 0x{mtval.value:08x}.'
        # only a store can trigger the FreeRTOS stack watchpoint
        task = self._stack_watch_owner(report, mtval.value) if kind == 'store' else None
        if task is None:
            return [self.found(summary, evidence, value='watchpoint')]
        evidence.append(task.id)
        return [
            self.found(
                f'{summary} This address is in the first {STACK_WATCH_AREA_SIZE} bytes of the stack of '
                f"task '{task.name or task.id}'. With CONFIG_FREERTOS_WATCHPOINT_END_OF_STACK, FreeRTOS "
                'watches this area to catch a stack overflow.',
                evidence,
                value='stack_overflow_watchpoint',
            )
        ]

    @staticmethod
    def _stack_watch_owner(report, addr):
        """The crashed task, when addr is in the watched area at the start of its stack."""
        # only the running task has the watchpoint, so another task's stack means nothing
        task = report.crashed_task()
        if task is None or task.stack.start is None:
            return None
        # FreeRTOS rounds the watched address up to STACK_WATCH_AREA_SIZE
        watch = (task.stack.start + STACK_WATCH_AREA_SIZE - 1) & ~(STACK_WATCH_AREA_SIZE - 1)
        return task if watch <= addr < watch + STACK_WATCH_AREA_SIZE else None
