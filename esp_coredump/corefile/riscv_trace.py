#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#

from typing import List, Optional  # noqa: F401

from construct import Bytes, Container, Int8ul, Int16ul, Int32ul, Padding, Struct  # noqa: F401

from .elf import ElfFile  # noqa: F401

# ELF note identity written by the RISC-V trace coredump integration.
# Layout matches the snapshot ABI 1.0 note in esp_riscv_trace_coredump.c.
TRACE_NOTE_NAME = b'ESP_RISCV_TRACE'
TRACE_NOTE_TYPE = 680
TRACE_SNAPSHOT_MAGIC = 0x53545652  # "RVTS"
TRACE_NO_SEGMENT = 0xFFFFFFFF
TRACE_NOTE_HEADER_SIZE = 80
TRACE_NOTE_RECORD_SIZE = 44
TRACE_ABI_MAJOR = 1

CAPTURE_REASON_NAMES = {
    0: 'UNKNOWN',
    1: 'EXPLICIT_STOP',
    2: 'PANIC',
}

SNAPSHOT_STATE_NAMES = {
    0: 'UNAVAILABLE',
    1: 'READY',
    2: 'CAPTURING',
    3: 'STOPPED',
    4: 'FROZEN',
}

MEMORY_MODE_NAMES = {
    0: 'UNKNOWN',
    1: 'LINEAR',
    2: 'LOOP',
}

ADDRESS_MODE_NAMES = {
    0: 'UNKNOWN',
    1: 'DELTA',
    2: 'FULL',
}

RESYNC_MODE_NAMES = {
    0: 'UNKNOWN',
    1: 'DISABLED',
    2: 'PACKET',
    3: 'CYCLE',
}

PACKET_FORMAT_NAMES = {
    0: 'UNKNOWN',
    100: 'PT10',
    200: 'ET20',
}

# Shared encoder-parameter block, snapshot ABI 1.0 (28 bytes).
TraceEncoderParams = Struct(
    'params_version' / Int8ul,
    'params_size' / Int8ul,
    'arch_p' / Int8ul,
    'bpred_size_p' / Int8ul,
    'cache_size_p' / Int8ul,
    'call_counter_size_p' / Int8ul,
    'ctype_width_p' / Int8ul,
    'context_width_p' / Int8ul,
    'ecause_width_p' / Int8ul,
    'ecause_choice_p' / Int8ul,
    'f0s_width_p' / Int8ul,
    'filter_context_p' / Int8ul,
    'filter_excint_p' / Int8ul,
    'filter_privilege_p' / Int8ul,
    'filter_tval_p' / Int8ul,
    'iaddress_lsb_p' / Int8ul,
    'iaddress_width_p' / Int8ul,
    'iretire_width_p' / Int8ul,
    'ilastsize_width_p' / Int8ul,
    'itype_width_p' / Int8ul,
    'nocontext_p' / Int8ul,
    'notime_p' / Int8ul,
    'privilege_width_p' / Int8ul,
    'retires_p' / Int8ul,
    'return_stack_size_p' / Int8ul,
    'sijump_p' / Int8ul,
    'taken_branches_p' / Int8ul,
    'impdef_width_p' / Int8ul,
)

# Note directory header, snapshot ABI 1.0 (80 bytes, little-endian).
TraceNoteHeader = Struct(
    'magic' / Int32ul,
    'write_seq' / Int32ul,
    'target_id' / Int16ul,
    'chip_revision' / Int16ul,
    'abi_major' / Int8ul,
    'abi_minor' / Int8ul,
    'note_header_size' / Int8ul,
    'core_record_size' / Int8ul,
    'core_count' / Int8ul,
    'capture_reason' / Int8ul,
    'app_elf_sha256_size' / Int8ul,
    'encoder_params_size' / Int8ul,
    'app_elf_sha256' / Bytes(32),
    'encoder_params' / TraceEncoderParams,
)

# Per-core record, snapshot ABI 1.0 (44 bytes, little-endian).
TraceCoreRecord = Struct(
    'core_id' / Int8ul,
    'state' / Int8ul,
    'memory_mode' / Int8ul,
    'packet_format' / Int8ul,
    'address_mode' / Int8ul,
    'resync_mode' / Int8ul,
    'reserved0' / Int8ul,
    'head_valid' / Int8ul,
    'fifo_empty' / Int8ul,
    'memory_full' / Int8ul,
    'fifo_overflow' / Int8ul,
    Padding(1),
    'segment_index' / Int32ul,
    'buffer_addr' / Int32ul,
    'segment_size' / Int32ul,
    'capacity' / Int32ul,
    'head_offset' / Int32ul,
    'resync_threshold' / Int32ul,
    'fifo_status_raw' / Int32ul,
    'intr_status_raw' / Int32ul,
)


class RiscvTraceCore:
    def __init__(self, record):  # type: (Container) -> None
        self.core_id = record.core_id
        self.state = record.state
        self.memory_mode = record.memory_mode
        self.packet_format = record.packet_format
        self.address_mode = record.address_mode
        self.resync_mode = record.resync_mode
        self.head_valid = record.head_valid
        self.fifo_empty = record.fifo_empty
        self.memory_full = record.memory_full
        self.fifo_overflow = record.fifo_overflow
        self.segment_index = record.segment_index
        self.buffer_addr = record.buffer_addr
        self.buffer_size = record.segment_size
        self.capacity = record.capacity
        self.head_offset = record.head_offset
        self.resync_threshold = record.resync_threshold
        self.fifo_status_raw = record.fifo_status_raw
        self.intr_status_raw = record.intr_status_raw

    @property
    def buffer_present(self):  # type: () -> bool
        return bool(self.segment_index != TRACE_NO_SEGMENT)

    @property
    def state_name(self):  # type: () -> str
        return SNAPSHOT_STATE_NAMES.get(self.state, str(self.state))

    @property
    def memory_mode_name(self):  # type: () -> str
        return MEMORY_MODE_NAMES.get(self.memory_mode, str(self.memory_mode))

    @property
    def address_mode_name(self):  # type: () -> str
        return ADDRESS_MODE_NAMES.get(self.address_mode, str(self.address_mode))

    @property
    def resync_mode_name(self):  # type: () -> str
        return RESYNC_MODE_NAMES.get(self.resync_mode, str(self.resync_mode))

    @property
    def packet_format_name(self):  # type: () -> str
        return PACKET_FORMAT_NAMES.get(self.packet_format, str(self.packet_format))

    @property
    def quality_flags(self):  # type: () -> List[str]
        flags = []  # type: List[str]
        if not self.head_valid:
            flags.append('HEAD_INVALID')
        if self.memory_full:
            flags.append('MEMORY_FULL')
        if self.fifo_overflow:
            flags.append('FIFO_OVERFLOW')
        if self.buffer_present and not self.fifo_empty:
            flags.append('FIFO_NOT_EMPTY')
        return flags


class RiscvTraceSnapshot:
    def __init__(self, header, cores):  # type: (Container, List[RiscvTraceCore]) -> None
        self.abi_major = header.abi_major
        self.abi_minor = header.abi_minor
        self.write_seq = header.write_seq
        self.target_id = header.target_id
        self.chip_revision = header.chip_revision
        self.core_count = header.core_count
        self.capture_reason = header.capture_reason
        self.app_elf_sha256 = header.app_elf_sha256
        self.encoder_params = header.encoder_params
        self.cores = cores

    @property
    def capture_reason_name(self):  # type: () -> str
        return CAPTURE_REASON_NAMES.get(self.capture_reason, str(self.capture_reason))


def parse_riscv_trace_note(core_elf):  # type: (ElfFile) -> Optional[RiscvTraceSnapshot]
    """
    Find the ESP_RISCV_TRACE note in a core ELF and decode its snapshot header
    and per-core records. Returns None when the note is absent or unusable.
    """
    desc = None
    for segment in core_elf.note_segments:
        for note in segment.note_secs:
            if note.type == TRACE_NOTE_TYPE and note.name == TRACE_NOTE_NAME:
                desc = note.desc
                break
        if desc is not None:
            break
    if desc is None or len(desc) < TRACE_NOTE_HEADER_SIZE:
        return None

    header = TraceNoteHeader.parse(desc)
    if header.magic != TRACE_SNAPSHOT_MAGIC or header.abi_major != TRACE_ABI_MAJOR:
        return None
    if header.note_header_size < TRACE_NOTE_HEADER_SIZE or header.core_record_size < TRACE_NOTE_RECORD_SIZE:
        return None

    cores = []  # type: List[RiscvTraceCore]
    for i in range(header.core_count):
        start = header.note_header_size + i * header.core_record_size
        chunk = desc[start : start + header.core_record_size]
        if len(chunk) < header.core_record_size:
            break
        cores.append(RiscvTraceCore(TraceCoreRecord.parse(chunk)))

    return RiscvTraceSnapshot(header, cores)
