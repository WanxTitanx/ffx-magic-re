"""WD3 container parser.

Parses the WD3 container format — a flat particle rendering data container
with multiple overlapping byte streams. Instruction decoding is in the
sibling ``decoder`` module.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Final

from .decoder import _parse_record
from .stream import StreamInfo, SubSectionEntry
from .opcodes import OPCODES, ALPHA_FUNCTIONS


def u8(data: bytes, offset: int) -> int:
    return data[offset]


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def f32(data: bytes, offset: int) -> float:
    return struct.unpack_from("<f", data, offset)[0]


WD3_MAGIC: Final[bytes] = b"WD3\x01"


@dataclass(frozen=True, slots=True)
class Wd3Header:
    """Parsed 32-byte WD3 container header."""
    offset: int
    magic: str
    version: int
    total_size: int
    count_entries: int
    count_sections: int
    count3: int
    count4: int
    section1_off: int
    section2_off: int
    section3_off: int
    section4_off: int
    stream_count: int
    reserved: int


@dataclass(frozen=True, slots=True)
class StreamHeader:
    """Parsed 32-byte stream header."""
    unused0: int
    end_offset: int
    start_offset: int
    size: int
    packed1: int
    packed2: int
    scale: float
    unused1: int
    unused2: int


def find_wd3(data: bytes, start: int = 0) -> int:
    """Find the WD3 magic (``WD3\\x01``) in a data blob."""
    return data.find(WD3_MAGIC, start)


def _is_valid_wd3_container(data: bytes, offset: int) -> bool:
    if offset + 32 > len(data):
        return False
    total_size = u32(data, offset + 4)
    stream_count = u16(data, offset + 8)
    pointer_table_end = 0x20 + stream_count * 4
    if total_size < pointer_table_end or offset + total_size > len(data):
        return False
    if not 0 < stream_count <= 64:
        return False
    for index in range(stream_count):
        hdr_offset = u32(data, offset + 0x20 + index * 4)
        if hdr_offset < pointer_table_end or hdr_offset + 32 > total_size:
            return False
        start_offset = u32(data, offset + hdr_offset + 8)
        end_offset = u32(data, offset + hdr_offset + 4)
        if start_offset >= total_size:
            return False
        if end_offset and not start_offset <= end_offset <= total_size:
            return False
    return True


def find_wd3_container(data: bytes, start: int = 0) -> int:
    """Find a valid WD3 container by scanning for magic and validating."""
    candidate = find_wd3(data, start)
    while candidate >= 0:
        if _is_valid_wd3_container(data, candidate):
            return candidate
        candidate = find_wd3(data, candidate + 4)
    return -1


def parse_wd3_header(data: bytes, offset: int) -> Wd3Header:
    """Parse a 32-byte WD3 container header."""
    magic = data[offset : offset + 4]
    if magic[:3] != b"WD3":
        raise ValueError(f"No WD3 magic at offset 0x{offset:x}")
    return Wd3Header(
        offset=offset,
        magic=magic[:4].hex(),
        version=magic[3],
        total_size=u32(data, offset + 4),
        count_entries=u16(data, offset + 6),
        count_sections=u16(data, offset + 8),
        count3=u16(data, offset + 0x0A),
        count4=u16(data, offset + 0x0C),
        section1_off=u32(data, offset + 0x10),
        section2_off=u32(data, offset + 0x14),
        section3_off=u32(data, offset + 0x18),
        section4_off=u32(data, offset + 0x1C),
        stream_count=u16(data, offset + 8),
        reserved=u16(data, offset + 6),
    )


def parse_stream_header(data: bytes, abs_off: int) -> StreamHeader:
    """Parse a 32-byte stream header."""
    start = u32(data, abs_off + 8)
    end = u32(data, abs_off + 4)
    return StreamHeader(
        unused0=u32(data, abs_off),
        end_offset=end,
        start_offset=start,
        size=(end if end else 0x20000) - start,
        packed1=u32(data, abs_off + 12),
        packed2=u32(data, abs_off + 16),
        scale=f32(data, abs_off + 20),
        unused1=u32(data, abs_off + 24),
        unused2=u32(data, abs_off + 28),
    )


def parse_stream_pointer_table(data: bytes, offset: int, count: int) -> list[int]:
    """Parse u32 stream pointer table at *offset* + 0x20."""
    return [u32(data, offset + 0x20 + i * 4) for i in range(count)]


@dataclass
class SubSectionIterator:
    """Iterator for 16-byte sub-section entries."""
    STRIDE: int = 16

    def __init__(self, data: bytes, start: int, count: int) -> None:
        self.data = data
        self.start = start
        self.count = count
        self._pos = 0

    def __iter__(self):
        return self

    def __next__(self) -> SubSectionEntry:
        if self._pos >= self.count:
            raise StopIteration
        off = self.start + self._pos * self.STRIDE
        raw = self.data[off : off + self.STRIDE]
        entry = SubSectionEntry(
            offset=off,
            ptr_type_descriptor=u32(self.data, off),
            data_offset=u32(self.data, off + 4),
            opcode_byte=self.data[off + 8],
            type_tag=self.data[off + 9],
            count=u16(self.data, off + 10),
            runtime_data=u32(self.data, off + 12),
            raw_bytes=raw,
        )
        self._pos += 1
        return entry


@dataclass
class WD3Container:
    """A fully parsed WD3 container.

    Attributes:
        offset: Offset of the WD3 magic in the source data.
        version: WD3 version byte (typically 0x01).
        total_size: Total size of the WD3 blob.
        stream_count: Number of streams.
        streams: List of parsed ``StreamInfo`` objects.
    """
    offset: int
    version: int
    total_size: int
    stream_count: int
    count_entries: int = 0
    count_sections: int = 0
    count3: int = 0
    count4: int = 0
    section1_off: int = 0
    section2_off: int = 0
    section3_off: int = 0
    section4_off: int = 0
    header_reserved: int = 0
    stream_header_offsets: list[int] = field(default_factory=list)
    pointer_table_gap: bytes = b""
    streams: list[StreamInfo] = field(default_factory=list)
    raw_header: bytes = b""
    post_prefix_gap: bytes = b""
    body: bytes = b""

    def summary(self) -> str:
        lines = [
            f"WD3 v{self.version} — {self.total_size} bytes, "
            + f"{self.stream_count} streams",
        ]
        for s in self.streams:
            lines.append(
                f"  Stream {s.index}: offset=0x{s.start_offset:x} "
                + f"size=0x{s.size:x} ({s.size}) scale={s.scale:.1f} "
                + f"[{s.type_name}]"
            )
        return "\n".join(lines)


def parse_wd3(data: bytes, blob_base: int) -> WD3Container:
    """Parse a complete WD3 blob.

    Args:
        data: Raw bytes containing the WD3 blob.
        blob_base: Offset of the WD3 magic within *data*.

    Returns:
        A ``WD3Container`` with all streams parsed.
    """
    hdr = parse_wd3_header(data, blob_base)
    container = WD3Container(
        offset=blob_base,
        version=hdr.version,
        total_size=hdr.total_size,
        stream_count=hdr.stream_count,
        count_entries=hdr.count_entries,
        count_sections=hdr.count_sections,
        count3=hdr.count3,
        count4=hdr.count4,
        section1_off=hdr.section1_off,
        section2_off=hdr.section2_off,
        section3_off=hdr.section3_off,
        section4_off=hdr.section4_off,
        header_reserved=hdr.reserved,
        raw_header=data[blob_base : blob_base + 32],
    )

    stream_ptrs = parse_stream_pointer_table(data, blob_base, hdr.stream_count)
    container.stream_header_offsets = stream_ptrs
    pointer_table_end = 0x20 + hdr.stream_count * 4
    first_header = min(stream_ptrs)
    container.pointer_table_gap = data[
        blob_base + pointer_table_end : blob_base + first_header
    ]

    for i, ptr in enumerate(stream_ptrs):
        abs_off = blob_base + ptr
        sh = parse_stream_header(data, abs_off)
        si = StreamInfo(
            index=i,
            start_offset=sh.start_offset,
            end_offset=sh.end_offset if sh.end_offset else hdr.total_size,
            size=(sh.end_offset if sh.end_offset else hdr.total_size)
            - sh.start_offset,
            scale=sh.scale,
            packed1=sh.packed1,
            packed2=sh.packed2,
            raw_end_offset=sh.end_offset,
            unused0=sh.unused0,
            unused1=sh.unused1,
            unused2=sh.unused2,
        )
        abs_start = blob_base + si.start_offset
        abs_end = min(abs_start + si.size, blob_base + hdr.total_size)
        offset = abs_start

        while offset < abs_end - 16:
            rec = _parse_record(data, offset, blob_base)
            if rec is None:
                break
            if offset + rec.total_size > abs_end:
                break
            si.records.append(rec)
            offset += rec.total_size

        container.streams.append(si)

    structure_end = max(ptr + 32 for ptr in stream_ptrs)
    body_start = min(s.start_offset for s in container.streams)
    if structure_end > body_start:
        raise ValueError("stream start overlaps the structural prefix")
    blob_end = blob_base + hdr.total_size
    if blob_end > len(data):
        raise ValueError("WD3 total_size exceeds source data")

    container.post_prefix_gap = data[
        blob_base + structure_end : blob_base + body_start
    ]
    container.body = data[blob_base + body_start : blob_end]
    return container
