"""WD3 structure serialization — round-trips header/section/stream metadata.

Validates structural invariants and produces the byte-exact WD3 structure
prefix (header + pointer table + gaps + stream headers).
"""

from __future__ import annotations

import struct
from typing import Protocol

from .stream import StreamInfo


class Wd3StructureError(ValueError):
    """Raised when structural invariants are violated during serialization."""


class Wd3Structure(Protocol):
    """Minimal protocol for WD3 structural serialization."""
    version: int
    total_size: int
    stream_count: int
    count_entries: int
    count_sections: int
    count3: int
    count4: int
    section1_off: int
    section2_off: int
    section3_off: int
    section4_off: int
    header_reserved: int
    stream_header_offsets: list[int]
    pointer_table_gap: bytes
    streams: list[StreamInfo]


def serialize_wd3_structure(container: Wd3Structure) -> bytes:
    """Serialize the WD3 structural prefix (header + pointer table + stream headers).

    Args:
        container: An object implementing the ``Wd3Structure`` protocol.

    Returns:
        Byte-exact structural prefix.

    Raises:
        Wd3StructureError: If structural invariants are violated.
    """
    if container.stream_count != len(container.streams):
        raise Wd3StructureError(
            f"stream_count={container.stream_count} but "
            + f"{len(container.streams)} streams exist"
        )
    if container.stream_count != len(container.stream_header_offsets):
        raise Wd3StructureError(
            "stream header offset count does not match stream_count"
        )

    pointer_table_end = 0x20 + container.stream_count * 4
    first_header = min(container.stream_header_offsets)
    if first_header < pointer_table_end:
        raise Wd3StructureError("stream header overlaps pointer table")
    if len(container.pointer_table_gap) != first_header - pointer_table_end:
        raise Wd3StructureError(
            "pointer table gap length does not match header offsets"
        )

    structure_size = max(offset + 32 for offset in container.stream_header_offsets)
    output = bytearray(structure_size)
    output[0:4] = b"WD3" + bytes((container.version,))
    struct.pack_into("<I", output, 4, container.total_size)
    struct.pack_into("<H", output, 6, container.count_entries)
    struct.pack_into("<H", output, 8, container.count_sections)
    struct.pack_into("<H", output, 10, container.count3)
    struct.pack_into("<H", output, 12, container.count4)
    struct.pack_into("<H", output, 14, container.header_reserved)
    struct.pack_into(
        "<IIII", output, 16,
        container.section1_off, container.section2_off,
        container.section3_off, container.section4_off,
    )

    for index, offset in enumerate(container.stream_header_offsets):
        struct.pack_into("<I", output, 0x20 + index * 4, offset)
    output[pointer_table_end:first_header] = container.pointer_table_gap

    for offset, stream in zip(container.stream_header_offsets, container.streams):
        struct.pack_into(
            "<IIIIIfII", output, offset,
            stream.unused0, stream.raw_end_offset, stream.start_offset,
            stream.packed1, stream.packed2, stream.scale,
            stream.unused1, stream.unused2,
        )
    return bytes(output)
