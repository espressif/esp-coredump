#
# SPDX-FileCopyrightText: 2022-2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#

from typing import Any, Optional, Tuple  # noqa: F401

from construct import Int16ul, Int32ul, Padding, Struct

from esp_coredump.log import log

from . import BaseArchMethodsMixin, BaseTargetMethods, ESPCoreDumpLoaderError

RISCV_GP_REGS_COUNT = 32
PRSTATUS_SIZE = 204
PRSTATUS_OFFSET_PR_CURSIG = 12
PRSTATUS_OFFSET_PR_PID = 24
PRSTATUS_OFFSET_PR_REG = 72
ELF_GREGSET_T_SIZE = 128

# CSRs saved after the 32 regs in the IDF RvExcFrame
EXC_FRAME_CSR_NAMES = ('mstatus', 'mtvec', 'mcause', 'mtval', 'mhartid')
# IDF puts this PC in the frame of a task with a bad stack
IDF_FAKE_FRAME_PC = 0x70000000

# Standard RISC-V exception names. The high bit marks an interrupt.
MCAUSE_INTERRUPT_BIT = 1 << 31
EXCEPTION_NAMES = {
    0: 'Instruction address misaligned',
    1: 'Instruction access fault',
    2: 'Illegal instruction',
    3: 'Breakpoint',
    4: 'Load address misaligned',
    5: 'Load access fault',
    6: 'Store address misaligned',
    7: 'Store access fault',
    8: 'Environment call from U-mode',
    9: 'Environment call from S-mode',
    11: 'Environment call from M-mode',
    12: 'Instruction page fault',
    13: 'Load page fault',
    15: 'Store page fault',
}

PrStruct = Struct(
    Padding(PRSTATUS_OFFSET_PR_CURSIG),
    'pr_cursig' / Int16ul,
    Padding(PRSTATUS_OFFSET_PR_PID - PRSTATUS_OFFSET_PR_CURSIG - Int16ul.sizeof()),
    'pr_pid' / Int32ul,
    Padding(PRSTATUS_OFFSET_PR_REG - PRSTATUS_OFFSET_PR_PID - Int32ul.sizeof()),
    'regs' / Int32ul[RISCV_GP_REGS_COUNT],
    Padding(PRSTATUS_SIZE - PRSTATUS_OFFSET_PR_REG - ELF_GREGSET_T_SIZE),
)


class RiscvMethodsMixin(BaseArchMethodsMixin):
    @staticmethod
    def get_registers_from_stack(data, grows_down):
        # type: (bytes, bool) -> Tuple[list[int], Optional[dict[int, int]]]
        regs = Int32ul[RISCV_GP_REGS_COUNT].parse(data)
        if not grows_down:
            raise ESPCoreDumpLoaderError('Growing up stacks are not supported for now!')
        return regs, None

    @staticmethod
    def build_prstatus_data(tcb_addr, task_regs):  # type: (int, list[int]) -> Any
        return PrStruct.build(
            {
                'pr_cursig': 0,
                'pr_pid': tcb_addr,
                'regs': task_regs,
            }
        )


def get_exc_frame_csrs(load_segments, regs):
    # type: (list, list[int]) -> Optional[dict[str, int]]
    """
    Read the saved CSRs of the crashed task.
    IDF saves the crashed task stack from the start of its RvExcFrame,
    so find the segment that starts with the same 32 regs and read the CSRs after them.
    Return None if the frame is not found or is a fake one.
    """
    if len(regs) != RISCV_GP_REGS_COUNT or regs[0] == IDF_FAKE_FRAME_PC:
        return None
    head = Int32ul[RISCV_GP_REGS_COUNT].build(regs)
    csr_size = len(EXC_FRAME_CSR_NAMES) * 4
    hits = [seg for seg in load_segments if seg.data.startswith(head) and len(seg.data) >= len(head) + csr_size]
    if len(hits) != 1:
        return None
    values = Int32ul[len(EXC_FRAME_CSR_NAMES)].parse(hits[0].data[len(head) : len(head) + csr_size])
    return dict(zip(EXC_FRAME_CSR_NAMES, values))


def _crashed_task_regs(core_elf, extra_info):  # type: (Any, Optional[list]) -> Optional[list]
    """The 32 GPRs of the crashed task, taken from its PRSTATUS note."""
    if not extra_info:
        return None
    crashed_tcb = extra_info[0]
    for seg in core_elf.note_segments:
        for note in seg.note_secs:
            if note.type != 1:
                continue
            pr = PrStruct.parse(note.desc)
            if pr.pr_pid == crashed_tcb:
                return list(pr.regs)
    return None


def _mcause_name(mcause):  # type: (int) -> Optional[str]
    if mcause & MCAUSE_INTERRUPT_BIT:
        return f'Interrupt {mcause & ~MCAUSE_INTERRUPT_BIT}'
    return EXCEPTION_NAMES.get(mcause)


def print_exc_regs_info(core_elf, extra_info):  # type: (Any, Optional[list]) -> None
    """Print MEPC and the CSRs from the crashed task exception frame."""
    regs = _crashed_task_regs(core_elf, extra_info)
    csrs = get_exc_frame_csrs(core_elf.load_segments, regs) if regs else None
    if not regs or not csrs:
        log.warn('Exception registers have not been found!')
        return
    mcause = csrs['mcause']
    reason = _mcause_name(mcause)
    cause = f'0x{mcause:x}' + (f' ({reason})' if reason else '')
    rows = (
        ('mepc', f'0x{regs[0]:x}'),
        ('mstatus', f'0x{csrs["mstatus"]:x}'),
        ('mtvec', f'0x{csrs["mtvec"]:x}'),
        ('mcause', cause),
        ('mtval', f'0x{csrs["mtval"]:x}'),
        ('mhartid', f'0x{csrs["mhartid"]:x}'),
    )
    for name, value in rows:
        print(f'{name:<15}{value}')


class Esp32C3Methods(BaseTargetMethods, RiscvMethodsMixin):
    TARGET = 'esp32c3'


class Esp32C2Methods(BaseTargetMethods, RiscvMethodsMixin):
    TARGET = 'esp32c2'


class Esp32H2Methods(BaseTargetMethods, RiscvMethodsMixin):
    TARGET = 'esp32h2'


class Esp32C6Methods(BaseTargetMethods, RiscvMethodsMixin):
    TARGET = 'esp32c6'


class Esp32P4Methods(BaseTargetMethods, RiscvMethodsMixin):
    TARGET = 'esp32p4'


class Esp32C5Methods(BaseTargetMethods, RiscvMethodsMixin):
    TARGET = 'esp32c5'


class Esp32C61Methods(BaseTargetMethods, RiscvMethodsMixin):
    TARGET = 'esp32c61'


class Esp32H21Methods(BaseTargetMethods, RiscvMethodsMixin):
    TARGET = 'esp32h21'


class Esp32H4Methods(BaseTargetMethods, RiscvMethodsMixin):
    TARGET = 'esp32h4'


class Esp32S31Methods(BaseTargetMethods, RiscvMethodsMixin):
    TARGET = 'esp32s31'
