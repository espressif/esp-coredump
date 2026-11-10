#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Rule (RISC-V): name the register that held the address a load or store faulted on.

The result is 'confirmed'. mepc points at the instruction that faulted, so it ran,
and the trap handler saved the register file at that point. The access never
completed, so the base register still holds what it held when the address was
formed, even when the load writes the same register it reads from. Nothing about
earlier events is assumed, and three separately recorded facts agree: the register
in the exception frame, mtval, and the direction mcause reports.

Where the value in the base register came from is a different question. A dump
does not answer it.
"""

from .. import riscv
from .base import Rule, frame_place, get_fact

# Load and store causes. The instruction fetch causes belong to IndirectCallRule,
# where the PC is the jump target and not an instruction that ran.
ACCESS_CAUSES = riscv.LOAD_CAUSES + riscv.STORE_CAUSES


class FaultingAccessRule(Rule):
    id = 'faulting-access.v1'
    architectures = ('riscv',)
    needs = ('fact:mcause', 'fact:pc', 'fact:bad-address', 'fact:pc-instruction', 'crashed task registers')

    def run(self, report):
        if report.crash.kind in ('software_panic', 'interrupt'):
            return []
        mcause = get_fact(report, 'fact:mcause')
        pc = get_fact(report, 'fact:pc')
        bad = get_fact(report, 'fact:bad-address')
        insn_fact = get_fact(report, 'fact:pc-instruction')
        if mcause is None or pc is None or bad is None or insn_fact is None:
            return []
        if mcause.value not in ACCESS_CAUSES:
            return []
        task = report.crashed_task()
        if task is None or not task.registers:
            return []

        insn = insn_fact.value
        insn_text = riscv.format_instruction(insn)
        access = riscv.decode_memory_access(insn)
        kind = riscv.instruction_kind(insn)
        if access is None:
            return [
                self.not_enough_data(
                    f'The faulting instruction {insn_text} is not a load or store with a base register and '
                    'offset, so the register that held the bad address cannot be named.',
                    [insn_fact.id],
                    subject='access',
                )
            ]
        base, offset, width = access
        name = riscv.reg_name(base)
        # x0 reads as zero on every RISC-V core, so the collector saves no word for
        # it and we need none. Every other base has to be in the exception frame.
        if base == 0:
            value = 0
        elif name in task.registers:
            value = task.registers[name]
        else:
            return []
        effective = (value + offset) & 0xFFFFFFFF
        evidence = [mcause.id, pc.id, bad.id, insn_fact.id, task.id]
        # frame 0 is the function that holds the faulting instruction
        frame = report.crashed_frame(0)
        if frame is not None:
            evidence.append(frame.id)

        # mcause says which direction faulted. A decode that disagrees means the
        # instruction bytes or the saved state are not the ones that faulted, and a
        # matching address does not make up for that.
        expected = 'load' if mcause.value in riscv.LOAD_CAUSES else 'store'
        if kind != expected:
            return [
                self.not_enough_data(
                    f'The CPU reported a {expected} fault, but the instruction {insn_text} at '
                    f'0x{pc.value:08x} is a {kind}. The instruction bytes and the saved state do not '
                    'describe the same fault, so no register is named.',
                    evidence,
                    subject='access',
                )
            ]

        if effective != bad.value:
            return [
                self.not_enough_data(
                    f'The address formed by {name} + {offset} is 0x{effective:08x}, but the CPU reported '
                    f'0x{bad.value:08x}. The instruction was decoded wrongly or the saved registers do not match '
                    'the fault, so no register is named.',
                    evidence,
                    subject='access',
                )
            ]

        verb = 'writes' if kind == 'store' else 'reads'
        place = frame_place(frame)
        where = f' in {place}' if place else ''
        operand = f'{offset}({name})' if offset else f'0({name})'
        if base == 0:
            holds = f'{name} is always 0x00000000'
            origin = f'Nothing set {name}, because the register is wired to zero.'
        else:
            holds = f'{name} holds 0x{value:08x}'
            origin = f'The core dump does not show where the value in {name} came from.'
        return [
            self.confirmed(
                f'A {kind} through {name} faulted. The instruction at 0x{pc.value:08x}{where} '
                f'{verb} {width} bytes at {operand}. {holds}, so the address is '
                f'0x{effective:08x}, which is the address the CPU faulted on. {origin}',
                evidence,
                subject=name,
                value=f'{kind}_through_register',
            )
        ]
