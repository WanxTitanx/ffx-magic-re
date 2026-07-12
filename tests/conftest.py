"""Pytest fixtures and helpers for synthetic WD3 blob construction."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from ppp_disassembler.stream import StreamInfo


def make_synthetic_container(
    stream_count: int = 1,
    body_size: int = 128,
) -> tuple[bytes, int]:
    """Build a minimal synthetic WD3 blob for testing.

    Returns (blob_bytes, offset_of_WD3_magic).
    """
    if stream_count < 1:
        raise ValueError("need at least 1 stream")

    pointer_table_end = 0x20 + stream_count * 4
    first_header = pointer_table_end
    structure_end = first_header + stream_count * 32
    body_start = (structure_end + 15) // 16 * 16
    total_size = body_start + body_size

    blob = bytearray(total_size)
    blob[0:4] = b"WD3\x01"
    struct.pack_into("<I", blob, 4, total_size)
    struct.pack_into("<H", blob, 6, (total_size >> 16) & 0xFFFF)
    struct.pack_into("<H", blob, 8, stream_count)
    struct.pack_into("<IIII", blob, 16, 0, 0, 0, 0)

    for i in range(stream_count):
        struct.pack_into("<I", blob, 0x20 + i * 4, first_header + i * 32)

    for i in range(stream_count):
        off = first_header + i * 32
        struct.pack_into("<I", blob, off, 0)
        struct.pack_into("<I", blob, off + 4, total_size)
        struct.pack_into("<I", blob, off + 8, body_start)
        struct.pack_into("<I", blob, off + 12, 0x5FC600FF)
        struct.pack_into("<I", blob, off + 16, 0xFE886E2B)
        struct.pack_into("<f", blob, off + 20, 4.0)
        struct.pack_into("<I", blob, off + 24, 0)
        struct.pack_into("<I", blob, off + 28, 0)

    return bytes(blob), 0


@dataclass
class FakeContainer:
    version: int = 1
    total_size: int = 0
    stream_count: int = 1
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
    post_prefix_gap: bytes = b""
    body: bytes = b""
    offset: int = 0
    raw_header: bytes = b""

    @classmethod
    def from_synthetic(cls, stream_count: int = 1, body_size: int = 128) -> FakeContainer:
        blob, base = make_synthetic_container(stream_count, body_size)
        high_word = (len(blob) >> 16) & 0xFFFF
        ptr_table_end = 0x20 + stream_count * 4
        first_hdr = ptr_table_end
        hdr_offsets = [first_hdr + i * 32 for i in range(stream_count)]
        structure_end = first_hdr + stream_count * 32
        body_start = (structure_end + 15) // 16 * 16
        streams: list[StreamInfo] = []
        for i in range(stream_count):
            si = StreamInfo(
                index=i,
                start_offset=body_start,
                end_offset=len(blob),
                size=body_size,
                scale=4.0,
                packed1=0x5FC600FF,
                packed2=0xFE886E2B,
                raw_end_offset=len(blob),
            )
            streams.append(si)

        return cls(
            total_size=len(blob),
            stream_count=stream_count,
            count_entries=high_word,
            count_sections=stream_count,
            count3=0,
            count4=0,
            stream_header_offsets=hdr_offsets,
            pointer_table_gap=blob[ptr_table_end:first_hdr],
            streams=streams,
            post_prefix_gap=blob[structure_end:body_start],
            body=blob[body_start:],
            offset=0,
            raw_header=blob[:32],
        )
