#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#
"""
RISC-V values used by the crash report.
"""

from __future__ import annotations

# Standard RISC-V values belong with the core dump loader, not here.
from ..corefile.riscv import MCAUSE_INTERRUPT_BIT, REG_NAMES, mcause_name

# IDF writes these interrupt numbers into mcause before the core dump.
# The values are the same on all RISC-V chips (see soc.h in ESP-IDF).
IDF_CPU1_FLAG = 1 << 12
# ETS_INT_WDT_INUM, the same on all RISC-V chips
MCAUSE_INTERRUPT_WDT = 24
INTERRUPT_WDT_CAUSES = (MCAUSE_INTERRUPT_WDT, MCAUSE_INTERRUPT_WDT | IDF_CPU1_FLAG)
# IDF writes these pseudo mcause values for its own faults
MCAUSE_CACHE_ERROR = 25
MCAUSE_MEMORY_PROTECTION = 26
MCAUSE_STACK_PROTECTION = 27
IDF_CAUSE_NAMES = {
    MCAUSE_INTERRUPT_WDT: 'Interrupt wdt timeout on CPU0',
    MCAUSE_INTERRUPT_WDT | IDF_CPU1_FLAG: 'Interrupt wdt timeout on CPU1',
    MCAUSE_CACHE_ERROR: 'Cache error',
    MCAUSE_MEMORY_PROTECTION: 'Memory protection fault',
    MCAUSE_STACK_PROTECTION: 'Stack protection fault',
}
# IDF uses this mcause when there is no real crash info
MCAUSE_INVALID = 0xDEADC0DE
MCAUSE_ILLEGAL_INSTRUCTION = 2
MCAUSE_BREAKPOINT = 3

# Instruction address misaligned, instruction access fault, instruction page fault
INSTRUCTION_FETCH_CAUSES = (0, 1, 12)
# Load address misaligned, load access fault, load page fault
LOAD_CAUSES = (4, 5, 13)
# Store/AMO address misaligned, store/AMO access fault, store/AMO page fault
STORE_CAUSES = (6, 7, 15)
# Environment call from U-mode, S-mode and M-mode
ENVIRONMENT_CALL_CAUSES = (8, 9, 11)
# For these causes, mtval holds the bad address
ADDRESS_CAUSES = INSTRUCTION_FETCH_CAUSES + LOAD_CAUSES + STORE_CAUSES


def decode_mcause(mcause: int | None) -> tuple[str | None, str | None]:
    """
    Return (reason, kind). kind is exception, idf_cause or interrupt.
    Return (None, None) when the value is not known.
    """
    if mcause is None or mcause == MCAUSE_INVALID:
        return None, None
    if mcause in IDF_CAUSE_NAMES:
        return IDF_CAUSE_NAMES[mcause], 'idf_cause'
    # The IDF pseudo-causes above stay in this module, so info_corefile does not
    # start naming them. Standard causes are named in one place.
    name = mcause_name(mcause)
    if name is None:
        return None, None
    return name, 'interrupt' if mcause & MCAUSE_INTERRUPT_BIT else 'exception'


def get_bad_address(mcause: int | None, mtval: int | None) -> int | None:
    if mcause in ADDRESS_CAUSES:
        return mtval
    return None


EBREAK = 0x00100073
C_EBREAK = 0x9002
# j . and c.j . : a loop with an empty body
SELF_JUMPS = (0x0000006F, 0xA001)
# Major opcodes (bits 6:0) of 32-bit loads and stores, incl. float ones
LOAD_OPCODES = (0x03, 0x07)
STORE_OPCODES = (0x23, 0x27)
# Compressed (quadrant, funct3) pairs of loads and stores
C_LOADS = ((0, 1), (0, 2), (0, 3), (2, 1), (2, 2), (2, 3))
C_STORES = ((0, 5), (0, 6), (0, 7), (2, 5), (2, 6), (2, 7))
# Zcmp reuses quadrant 2 funct3 5, which without the D extension holds no c.fsdsp.
# Bits 12:8 tell the stack instructions apart; the rest of the space is Zcmt and
# register moves, which touch no memory.
ZCMP_PUSH = 0b11000
ZCMP_POPS = (0b11010, 0b11100, 0b11110)  # cm.pop, cm.popretz, cm.popret
# Access width in bytes by funct3, for the 32-bit load and store opcodes.
# RV32 only. ld, lwu and sd (funct3 3 and 6 of the integer opcodes) are RV64
# encodings, so an instruction that looks like one did not come from code this
# CPU ran and we must not decode it. The 8-byte entries that remain are fld and
# fsd, which the D extension gives RV32 as well.
LOAD_WIDTHS = {0x03: {0: 1, 1: 2, 2: 4, 4: 1, 5: 2}, 0x07: {2: 4, 3: 8}}
STORE_WIDTHS = {0x23: {0: 1, 1: 2, 2: 4}, 0x27: {2: 4, 3: 8}}
SP_REG = 2
# rlist in bits 7:4 names the saved registers. 0..3 is reserved, so such an
# encoding is not a stack instruction at all.
ZCMP_RLIST_MIN = 4


def instruction_size(insn: int) -> int:
    return 4 if insn & 0x3 == 0x3 else 2


def format_instruction(insn: int) -> str:
    """Hex text of an instruction, two or four bytes wide by its own encoding."""
    return f'0x{insn:0{instruction_size(insn) * 2}x}'


def instruction_kind(insn: int) -> str:
    """Return ebreak, load, store or other. insn holds at least the first 16 bits."""
    if instruction_size(insn) == 2:
        insn &= 0xFFFF
        if insn == C_EBREAK:
            return 'ebreak'
        op = (insn & 0x3, insn >> 13)
        if op == (0, 4):
            # Zcb c.lbu/c.lh(u)/c.sb/c.sh, bit 11 marks the stores
            return 'store' if insn & (1 << 11) else 'load'
        if op == (2, 5):
            stack_op, rlist = (insn >> 8) & 0x1F, (insn >> 4) & 0xF
            if rlist < ZCMP_RLIST_MIN:
                return 'other'
            if stack_op == ZCMP_PUSH:
                return 'store'
            return 'load' if stack_op in ZCMP_POPS else 'other'
        return 'load' if op in C_LOADS else 'store' if op in C_STORES else 'other'
    if insn == EBREAK:
        return 'ebreak'
    opcode = insn & 0x7F
    return 'load' if opcode in LOAD_OPCODES else 'store' if opcode in STORE_OPCODES else 'other'


def is_self_jump(insn: int) -> bool:
    return (insn & (0xFFFF if instruction_size(insn) == 2 else 0xFFFFFFFF)) in SELF_JUMPS


def reg_name(index: int) -> str:
    """ABI name of register x<index>. REG_NAMES has pc where x0 would be."""
    return 'zero' if index == 0 else REG_NAMES[index]


def decode_jalr(insn: int) -> tuple[int, int, int] | None:
    """Return (rs1, rd, imm) of a jalr or c.jalr, or None for other instructions."""
    if instruction_size(insn) == 4:
        if insn & 0x707F != 0x67:
            return None
        imm = insn >> 20
        return (insn >> 15) & 0x1F, (insn >> 7) & 0x1F, imm - ((imm & 0x800) << 1)
    rs1 = (insn >> 7) & 0x1F
    if insn & 0xF07F == 0x9002 and rs1:
        # c.jalr rs1 is jalr ra, 0(rs1)
        return rs1, 1, 0
    return None


def decode_memory_access(insn: int) -> tuple[int, int, int] | None:
    """
    Return (base register, signed byte offset, width in bytes) of a load or store
    that addresses memory as base + offset, or None for any other instruction.

    None also covers the Zcmp stack instructions. cm.push and cm.pop move several
    registers at a computed offset from sp, so they have no single base register
    and offset to report. instruction_kind() still calls them load or store.
    """
    if instruction_size(insn) == 4:
        opcode, funct3 = insn & 0x7F, (insn >> 12) & 0x7
        if opcode in LOAD_WIDTHS:
            width = LOAD_WIDTHS[opcode].get(funct3)
            imm = insn >> 20
        elif opcode in STORE_WIDTHS:
            width = STORE_WIDTHS[opcode].get(funct3)
            imm = ((insn >> 25) << 5) | ((insn >> 7) & 0x1F)
        else:
            return None
        if width is None:
            return None
        return (insn >> 15) & 0x1F, imm - ((imm & 0x800) << 1), width

    insn &= 0xFFFF
    quadrant, funct3 = insn & 0x3, insn >> 13
    if quadrant == 0:
        rs1 = ((insn >> 7) & 0x7) + 8
        if funct3 == 4:
            # Zcb c.lbu, c.lhu, c.lh, c.sb, c.sh. Bits 12:10 pick the form.
            form = (insn >> 10) & 0x7
            if form in (0, 2):  # byte: uimm[1] is bit 5, uimm[0] is bit 6
                return rs1, ((insn >> 5) & 0x1) << 1 | ((insn >> 6) & 0x1), 1
            if form in (1, 3):  # halfword: uimm[1] is bit 5, uimm[0] is always 0
                return rs1, ((insn >> 5) & 0x1) << 1, 2
            return None
        if funct3 in (1, 5):  # c.fld, c.fsd
            return rs1, ((insn >> 10) & 0x7) << 3 | ((insn >> 5) & 0x3) << 6, 8
        if funct3 in (2, 3, 6, 7):  # c.lw, c.flw, c.sw, c.fsw
            return rs1, ((insn >> 10) & 0x7) << 3 | ((insn >> 6) & 0x1) << 2 | ((insn >> 5) & 0x1) << 6, 4
        return None
    if quadrant == 2:
        if funct3 == 5:
            # Zcmp owns this slot, see the note above ZCMP_PUSH
            return None
        if funct3 == 1:  # c.fldsp
            return SP_REG, ((insn >> 12) & 0x1) << 5 | ((insn >> 5) & 0x3) << 3 | ((insn >> 2) & 0x7) << 6, 8
        if funct3 in (2, 3):  # c.lwsp, c.flwsp
            return SP_REG, ((insn >> 12) & 0x1) << 5 | ((insn >> 4) & 0x7) << 2 | ((insn >> 2) & 0x3) << 6, 4
        if funct3 in (6, 7):  # c.swsp, c.fswsp
            return SP_REG, ((insn >> 9) & 0xF) << 2 | ((insn >> 7) & 0x3) << 6, 4
    return None
