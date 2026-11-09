#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#
"""Reading the ESP_RISCV_TRACE note of a core dump without the esp-riscv-trace package."""

import sys
from types import SimpleNamespace
from unittest import mock

import pytest

from esp_coredump.corefile.elf import ESPCoreDumpElfFile
from esp_coredump.corefile.riscv_trace import TRACE_NOTE_NAME, TraceNoteError, parse_riscv_trace_note

TRACE_NOTE = SimpleNamespace(type=ESPCoreDumpElfFile.PT_ESP_RISCV_TRACE, name=TRACE_NOTE_NAME, desc=b'')


def test_missing_package_is_reported_only_with_note():
    with mock.patch.dict(sys.modules, {'esp_riscv_trace': None}):
        assert parse_riscv_trace_note(SimpleNamespace(note_segments=[])) is None
        with pytest.raises(TraceNoteError, match='needs the esp-riscv-trace package'):
            parse_riscv_trace_note(SimpleNamespace(note_segments=[SimpleNamespace(note_secs=[TRACE_NOTE])]))
