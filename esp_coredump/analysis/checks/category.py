#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Rule: give the crash a stable category name.
"""

from .. import riscv
from .base import Rule, get_fact

# Start of the panic text written by ESP-IDF, and the category for it
PANIC_TEXT_CATEGORIES = (
    ('abort() was called', 'abort'),
    ('assert failed', 'assert'),
    ('***ERROR*** A stack overflow in task', 'stack_overflow'),
    ('Stack smashing protect failure', 'stack_smashing'),
    ('Task watchdog got triggered', 'task_watchdog'),
)

# Stable report values. The groups come from the architecture, the slugs are report policy.
RISCV_CAUSE_CATEGORIES = {
    **dict.fromkeys(riscv.INSTRUCTION_FETCH_CAUSES, 'instruction_fetch'),
    **dict.fromkeys(riscv.LOAD_CAUSES, 'load_fault'),
    **dict.fromkeys(riscv.STORE_CAUSES, 'store_fault'),
    **dict.fromkeys(riscv.ENVIRONMENT_CALL_CAUSES, 'environment_call'),
    **dict.fromkeys(riscv.INTERRUPT_WDT_CAUSES, 'interrupt_watchdog'),
    riscv.MCAUSE_ILLEGAL_INSTRUCTION: 'illegal_instruction',
    riscv.MCAUSE_BREAKPOINT: 'breakpoint',
    riscv.MCAUSE_CACHE_ERROR: 'cache_error',
    riscv.MCAUSE_MEMORY_PROTECTION: 'memory_protection',
    riscv.MCAUSE_STACK_PROTECTION: 'stack_protection',
}

# If the first frame is one of these, the crash came from abort()
ABORT_FUNCTIONS = ('panic_abort', 'esp_system_abort')


class CrashCategoryRule(Rule):
    id = 'crash-category.v1'
    needs = ('fact:panic-details', 'fact:mcause', 'crashed task frame 0')

    def run(self, report):
        crash = report.crash
        if crash.kind == 'software_panic':
            return [self._from_panic_text(report)]

        mcause_fact = get_fact(report, 'fact:mcause')
        if mcause_fact is None or report.target.architecture != 'riscv':
            return [self.not_enough_data('There is no panic reason and no mcause, so the crash type is not known.')]

        # BIN core dumps have no panic text, so look at the first frame
        frame = report.crashed_frame()
        if frame is not None and frame.function in ABORT_FUNCTIONS:
            return [
                self.found(
                    f'The crashed task stopped in {frame.function}(), so this is most likely abort(). The core dump has no panic reason to confirm it.',
                    [frame.id, mcause_fact.id],
                    value='abort',
                )
            ]

        if crash.mcause is None or crash.mcause == riscv.MCAUSE_INVALID:
            # the sentinel has the interrupt bit set, so it must not reach the test below
            return [self.not_enough_data('The core dump holds no valid mcause, so the crash type is not known.', [mcause_fact.id])]

        category = RISCV_CAUSE_CATEGORIES.get(crash.mcause)
        if category is None:
            if crash.mcause & riscv.MCAUSE_INTERRUPT_BIT:
                category = 'interrupt'
            else:
                return [self.not_enough_data(f'mcause 0x{crash.mcause:x} is not a known crash type.', [mcause_fact.id])]
        if crash.reason is None:
            return [self.not_enough_data(f'mcause 0x{crash.mcause:x} has no reason text, so the crash type is not known.', [mcause_fact.id])]
        evidence = [f.id for f in (get_fact(report, 'fact:crash-kind'), mcause_fact, get_fact(report, 'fact:crash-reason')) if f]
        return [self.confirmed(f"The CPU reported '{crash.reason}'.", evidence, value=category)]

    def _from_panic_text(self, report):
        text = report.crash.panic_details or ''
        if not text:
            return self.not_enough_data('This is a software panic, but the panic reason note is empty.', ['fact:crash-kind'])
        evidence = ['fact:crash-kind', 'fact:panic-details']
        for start, category in PANIC_TEXT_CATEGORIES:
            if text.startswith(start):
                return self.confirmed(f"ESP-IDF reported a software panic, '{text.splitlines()[0]}'.", evidence, value=category)
        return self.confirmed(f"ESP-IDF reported a software panic, '{text.splitlines()[0]}'.", evidence, value='software_panic')
