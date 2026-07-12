"""PPP instruction decoder and stream disassembler.

Decodes 16-byte sub-section entries into typed Instruction objects and
disassembles entire streams. Alpha-function selectors and known opcodes
are classified using the opcode tables.
"""

from __future__ import annotations

import struct
from collections.abc import Sequence
from typing import Protocol

from .opcodes import OPCODES, ALPHA_FUNCTIONS, is_known_opcode, is_alpha_selector
from .operands import Operand
from .stream import Instruction, StreamInfo, StreamRecord, SpriteData

SPRITE_STRIDE: int = 40


class _ContainerLike(Protocol):
    """Minimal container interface for ``disassemble_wd3``."""
    offset: int
    streams: Sequence[StreamInfo]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _parse_sprite_data(data: bytes, offset: int) -> SpriteData:
    """Parse a single 40-byte sprite record into SpriteData."""
    v0 = struct.unpack_from("<hhh", data, offset)
    v1 = struct.unpack_from("<hhh", data, offset + 6)
    v2 = struct.unpack_from("<hhh", data, offset + 12)
    r, g, b, a = data[offset + 18 : offset + 22]
    u1, v1_uv, u2, v2_uv = struct.unpack_from("<HHHH", data, offset + 20)
    return SpriteData(
        v0=v0, v1=v1, v2=v2,
        color_rgba=f"#{r:02x}{g:02x}{b:02x}{a:02x}",
        uv1=(u1, v1_uv), uv2=(u2, v2_uv),
    )


def _parse_record(
    data: bytes,
    abs_off: int,
    blob_base: int,
) -> StreamRecord | None:
    """Parse a single 16-byte PPP sub-section entry.

    For ``type_tag == 3``, also parses the trailing sprite records (40 B each).
    """
    if abs_off + 16 > len(data):
        return None

    ptr_type_desc = u32(data, abs_off)
    data_off = u32(data, abs_off + 4)
    opcode_byte = data[abs_off + 8]
    type_tag = data[abs_off + 9]
    count = u16(data, abs_off + 10)
    rt_data = u32(data, abs_off + 12)

    alpha_entry = ALPHA_FUNCTIONS.get(opcode_byte)
    alpha_desc = alpha_entry.description if alpha_entry else ""

    sprites: list[SpriteData] = []
    body_size = 0
    total_size = 16

    if type_tag == 3:
        body_size = SPRITE_STRIDE * count
        total_size = 16 + body_size
        for i in range(min(count, 100)):
            spr_off = abs_off + 16 + i * SPRITE_STRIDE
            if spr_off + SPRITE_STRIDE > len(data):
                break
            sprites.append(_parse_sprite_data(data, spr_off))

    return StreamRecord(
        offset=abs_off - blob_base,
        ptr_type_descriptor=ptr_type_desc,
        data_offset=data_off,
        opcode=opcode_byte,
        type_tag=type_tag,
        count=count,
        runtime_data=rt_data,
        alpha_desc=alpha_desc,
        header_size=16,
        body_size=body_size,
        total_size=total_size,
        sprites=tuple(sprites),
    )


def decode_instruction(
    data: bytes,
    offset: int,
    stream_index: int = 0,
    blob_base: int = 0,
) -> Instruction | None:
    """Decode a single 16-byte sub-section entry from the stream."""
    if offset + 16 > len(data):
        return None

    opcode_byte = data[offset + 8]
    type_tag = data[offset + 9]
    count = u16(data, offset + 10)

    if is_alpha_selector(opcode_byte):
        alpha_entry = ALPHA_FUNCTIONS[opcode_byte]
        desc = alpha_entry.description
        return Instruction(
            opcode_byte=opcode_byte,
            opcode_name=f"ALPHA_{desc}",
            stream_index=stream_index,
            offset=offset - blob_base,
            raw_bytes=data[offset : offset + 16],
            is_alpha=True,
            alpha_desc=desc,
            total_size=16,
        )

    if is_known_opcode(opcode_byte):
        entry = OPCODES[opcode_byte]
        fields: list[Operand] = [
            Operand(
                type="type_ptr",
                raw_value=data[offset : offset + 4],
                decoded_value=f"0x{u32(data, offset):08x}",
            ),
            Operand(
                type="data_off",
                raw_value=data[offset + 4 : offset + 8],
                decoded_value=f"0x{u32(data, offset + 4):08x}",
            ),
            Operand(
                type="count",
                raw_value=data[offset + 10 : offset + 12],
                decoded_value=str(count),
            ),
            Operand(
                type="type_tag",
                raw_value=bytes([type_tag]),
                decoded_value=f"0x{type_tag:02x}",
            ),
        ]
        total = 16 + (SPRITE_STRIDE * count if type_tag == 3 and count > 0 else 0)
        return Instruction(
            opcode_byte=opcode_byte,
            opcode_name=entry.name,
            stream_index=stream_index,
            offset=offset - blob_base,
            raw_bytes=data[offset : offset + 16],
            operands=fields,
            total_size=total,
        )

    return Instruction(
        opcode_byte=opcode_byte,
        opcode_name=f"UNKNOWN_0x{opcode_byte:02x}",
        stream_index=stream_index,
        offset=offset - blob_base,
        raw_bytes=data[offset : offset + 16],
        total_size=16,
    )


def disassemble_stream(
    data: bytes,
    start: int,
    size: int,
    stream_index: int = 0,
    blob_base: int = 0,
) -> list[Instruction]:
    """Decode all instructions in a stream sequentially."""
    instructions: list[Instruction] = []
    abs_end = min(start + size, len(data))
    offset = start

    while offset < abs_end - 16:
        instr = decode_instruction(data, offset, stream_index, blob_base)
        if instr is None:
            break
        instructions.append(instr)
        offset += instr.total_size

    return instructions


def disassemble_wd3(container: _ContainerLike, data: bytes) -> _ContainerLike:
    """Disassemble all streams in a WD3 container.

    Updates each stream's ``instructions`` list with decoded instructions.
    """
    for stream in container.streams:
        abs_start = container.offset + stream.start_offset
        stream.instructions = disassemble_stream(
            data,
            abs_start,
            stream.size,
            stream_index=stream.index,
            blob_base=container.offset,
        )
    return container
