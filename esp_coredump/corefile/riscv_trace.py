#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#

from typing import Any, List, Optional, Tuple  # noqa: F401

from .elf import ElfFile, ESPCoreDumpElfFile  # noqa: F401

TRACE_NOTE_NAME = b'ESP_RISCV_TRACE'


class TraceNoteError(ValueError):
    """The core dump has a trace note that cannot be read."""


def parse_riscv_trace_note(core_elf):  # type: (ElfFile) -> Optional[Tuple[Any, List[Any]]]
    """
    Find the ESP_RISCV_TRACE note in a core ELF and parse it with esp-riscv-trace.
    Returns the note header and the per-core records, or None when the note is absent.
    """
    desc = next(
        (
            note.desc
            for segment in core_elf.note_segments
            for note in segment.note_secs
            if note.type == ESPCoreDumpElfFile.PT_ESP_RISCV_TRACE and note.name == TRACE_NOTE_NAME
        ),
        None,
    )
    if desc is None:
        return None
    try:
        from esp_riscv_trace import AbiError, parse_note
    except ImportError:
        raise TraceNoteError('Reading it needs the esp-riscv-trace package, which needs Python 3.11 or newer.')
    try:
        header, records = parse_note(desc)
    except AbiError as e:
        raise TraceNoteError(f'The note is malformed. {e}')
    return header, records


def format_riscv_trace_note(header, records):  # type: (Any, List[Any]) -> List[str]
    """Describe the note header and each core record, in the words of esp-riscv-trace."""
    from esp_riscv_trace import format_note

    return list(format_note(header, records))
