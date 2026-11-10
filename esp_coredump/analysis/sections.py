#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Read section bounds and instruction bytes from an ELF file.
"""

from __future__ import annotations

from ..corefile.elf import ElfFile, ElfHeaderTables, ElfSection, ElfSegment, ESPCoreDumpElfFile
from . import riscv
from .report import ElfSectionInfo


def read_elf_sections(elf_path: str) -> list[ElfSectionInfo]:
    """
    Name, address, size and kind of every section the loader maps.

    This reads the section headers again instead of using ElfFile.sections, which
    keeps only SHT_PROGBITS. A SHT_NOBITS section such as .dram0.bss occupies no
    file bytes, so ElfFile cannot carry one: it reads every section as
    Bytes(sh_size) at sh_offset, and callers take len(section.data) as the extent
    of the section. Address classification needs .bss, so its bounds are read here,
    as metadata only. Reading the headers of a 5 MB ELF costs about 2 ms.
    """
    with open(elf_path, 'rb') as f:
        data = f.read()
    tables = ElfHeaderTables.parse(data)
    names_sh = tables.section_headers[tables.elf_header.e_shstrndx]
    names = data[names_sh.sh_offset : names_sh.sh_offset + names_sh.sh_size]
    sections = []
    for sh in tables.section_headers:
        if not sh.sh_flags & ElfSection.SHF_ALLOC or sh.sh_addr == 0 or sh.sh_size == 0:
            continue
        name = names[sh.sh_name :].split(b'\x00')[0].decode('utf-8', 'replace')
        if sh.sh_flags & ElfSection.SHF_EXECINSTR:
            kind = 'code'
        elif sh.sh_type == ElfFile.SHT_NOBITS:
            kind = 'bss'
        else:
            kind = 'data'
        sections.append(ElfSectionInfo(name, sh.sh_addr, sh.sh_size, kind))
    return sections


def data_holds(chunk: ElfSection | ElfSegment, addr: int) -> bool:
    """True when the data of a segment or section, which starts at chunk.addr, covers addr."""
    return chunk.addr <= addr < chunk.addr + len(chunk.data)


def read_code(elf: ESPCoreDumpElfFile, addr: int, size: int) -> bytes | None:
    """Read size bytes of an executable ELF section, or None if fewer are there."""
    for sec in elf.sections:
        if sec.flags & ElfSection.SHF_EXECINSTR and data_holds(sec, addr):
            data = sec.data[addr - sec.addr : addr - sec.addr + size]
            return data if len(data) == size else None
    return None


def read_instruction(elf: ESPCoreDumpElfFile, addr: int) -> int | None:
    """
    One whole instruction at addr, or None.

    The first halfword says how long the instruction is. Reading fewer bytes than
    that would leave the upper half zero, and those bytes carry base register and
    immediate bits, so a short read would name a register the code never used. A
    compressed instruction at the very end of a section is still a full read.
    """
    head = read_code(elf, addr, 2)
    if head is None:
        return None
    size = riscv.instruction_size(int.from_bytes(head, 'little'))
    if size == 2:
        return int.from_bytes(head, 'little')
    code = read_code(elf, addr, 4)
    return int.from_bytes(code, 'little') if code is not None else None
