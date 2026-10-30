#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Rule (RISC-V): name the call and the register that held the bad function pointer.
The call is the jalr or c.jalr that ends at the return address, which GDB resolves.
Its base register is used only if it still holds the address the CPU faulted on.

The result is 'found', not 'confirmed': the register value matches, but a dump
cannot show that this call was the jump that failed. A callee that overwrites the
same register and then jumps through it leaves a return address from an earlier,
successful call and the same matching value.
"""

from .. import riscv
from .base import Rule, frame_place, get_fact


class IndirectCallRule(Rule):
    id = 'indirect-call.v1'
    architectures = ('riscv',)
    needs = ('fact:mcause', 'fact:pc (mepc == mtval)', 'fact:call-address', 'fact:call-instruction', 'crashed task registers')

    def run(self, report):
        if report.crash.kind in ('software_panic', 'interrupt'):
            return []
        mcause = get_fact(report, 'fact:mcause')
        pc = get_fact(report, 'fact:pc')
        bad = get_fact(report, 'fact:bad-address')
        if mcause is None or pc is None or bad is None:
            return []
        # only meaningful on a wild jump, where the fault is at the jump target itself
        if mcause.value not in riscv.INSTRUCTION_FETCH_CAUSES or pc.value != bad.value:
            return []
        task = report.crashed_task()
        call_addr = get_fact(report, 'fact:call-address')
        call_insn = get_fact(report, 'fact:call-instruction')
        if task is None or not task.registers or call_addr is None or call_insn is None:
            return []

        rs1, rd, imm = riscv.decode_jalr(call_insn.value)  # type: ignore
        name = riscv.reg_name(rs1)
        # x0 reads as zero and is never saved. For any other base, missing register data must
        # not become a zero value: that would invent a NULL function pointer finding.
        if rs1 and name not in task.registers:
            return []
        value = task.registers[name] if rs1 else 0
        target = pc.value
        # the call wrote the return address to rd, so rs1 == rd no longer holds the pointer
        if rs1 == rd or (value + imm) & ~1 & 0xFFFFFFFF != target:
            return []

        operand = f'{imm}({name})' if imm else name
        # frame 0 is the bad target, frame 1 is the function that made the call
        caller = report.crashed_frame(1)
        place = frame_place(caller)
        where = f' in {place}' if place else ''
        what = 'A NULL function pointer was called' if value == 0 else 'A corrupted function pointer was called'
        evidence = [mcause.id, pc.id, bad.id, call_addr.id, call_insn.id, task.id]
        if caller is not None:
            evidence.append(caller.id)
        return [
            self.found(
                f'{what}. The jalr {operand} at 0x{call_addr.value:08x}{where} jumps through {name}, which holds '
                f'0x{value:08x}, the address the CPU faulted on. This is the call that ends at the return address; '
                'a later jump through the same register would leave the same evidence. The core dump does not '
                'show where the value came from.',
                evidence,
                subject=name,
                value='null_function_pointer' if value == 0 else 'corrupted_function_pointer',
            )
        ]
