"""Operand decoders for PPP bytecode — typed operand extraction from raw byte streams.

Each decode function takes ``(data, offset)`` and returns an ``Operand``
namedtuple-like frozen dataclass with the raw value, decoded/human-readable
value, and type annotation.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import TypeAlias

# Union of all possible raw-value types returned by decoders.
RawValue: TypeAlias = float | int | bytes | tuple[int, ...] | tuple[float, ...]


@dataclass(frozen=True, slots=True)
class Operand:
    """A single decoded operand from a PPP instruction.

    Attributes:
        type: Semantic type label (e.g. ``"float"``, ``"vec3"``, ``"color"``).
        raw_value: The raw decoded value (float, int, bytes, or tuple).
        decoded_value: Human-readable string representation.
        description: Optional contextual description (empty by default).
    """
    type: str
    raw_value: RawValue
    decoded_value: str
    description: str = ""

    def __str__(self) -> str:
        return f"[{self.type}] {self.decoded_value}"


def decode_float(data: bytes, offset: int) -> Operand:
    """Decode a float32 little-endian operand."""
    val: float = struct.unpack_from("<f", data, offset)[0]
    return Operand(type="float", raw_value=val, decoded_value=f"{val:.6f}")


def decode_vec3(data: bytes, offset: int) -> Operand:
    """Decode a vec3 (3 × float32) operand."""
    x, y, z = struct.unpack_from("<fff", data, offset)
    return Operand(
        type="vec3",
        raw_value=(x, y, z),
        decoded_value=f"({x:.4f}, {y:.4f}, {z:.4f})",
    )


def decode_int16(data: bytes, offset: int) -> Operand:
    """Decode a signed int16 operand."""
    val: int = struct.unpack_from("<h", data, offset)[0]
    return Operand(type="int16", raw_value=val, decoded_value=str(val))


def decode_uint16(data: bytes, offset: int) -> Operand:
    """Decode an unsigned uint16 operand."""
    val: int = struct.unpack_from("<H", data, offset)[0]
    return Operand(type="uint16", raw_value=val, decoded_value=str(val))


def decode_vertex(data: bytes, offset: int) -> Operand:
    """Decode a vertex (3 × int16) normalized by /15.0."""
    x, y, z = struct.unpack_from("<hhh", data, offset)
    nx, ny, nz = x / 15.0, y / 15.0, z / 15.0
    return Operand(
        type="vertex",
        raw_value=(x, y, z),
        decoded_value=f"({nx:.4f}, {ny:.4f}, {nz:.4f}) norm=({x},{y},{z})/15",
    )


def decode_color(data: bytes, offset: int) -> Operand:
    """Decode RGBA color (4 × uint8) normalized by /128."""
    r, g, b, a = data[offset : offset + 4]
    nr, ng, nb, na = r / 128.0, g / 128.0, b / 128.0, a / 128.0
    return Operand(
        type="color",
        raw_value=(r, g, b, a),
        decoded_value=f"RGBA({nr:.3f},{ng:.3f},{nb:.3f},{na:.3f}) #{r:02x}{g:02x}{b:02x}{a:02x}",
    )


def decode_uv(data: bytes, offset: int) -> Operand:
    """Decode UV coordinates (2 × uint16) normalized by /4096."""
    u, v = struct.unpack_from("<HH", data, offset)
    nu = u / 4096.0
    nv = 1.0 - v / 4096.0
    return Operand(
        type="uv",
        raw_value=(u, v),
        decoded_value=f"U={nu:.6f} V={nv:.6f} raw=({u},{v})",
    )


def decode_texture_ref(data: bytes, offset: int) -> Operand:
    """Decode a texture reference from a 64-bit packed descriptor.

    Format: texture_id (14 bits) | sub_type (6 bits) | size_w_pow2 (4 bits)
            | size_h_pow2 (4 bits)
    """
    packed: int = struct.unpack_from("<Q", data, offset)[0]
    texture_id = packed & 0x3FFF
    sub_type = (packed >> 20) & 0x3F
    size_w_pow2 = (packed >> 26) & 0xF
    size_h_pow2 = (packed >> 30) & 0xF
    size_w = 1 << size_w_pow2
    size_h = 1 << size_h_pow2
    return Operand(
        type="texture_ref",
        raw_value=packed,
        decoded_value=f"id={texture_id} sub={sub_type} {size_w}x{size_h}",
    )


def decode_matrix_ref(data: bytes, offset: int) -> Operand:
    """Decode a matrix reference (4-byte index or pointer)."""
    val: int = struct.unpack_from("<I", data, offset)[0]
    return Operand(type="matrix_ref", raw_value=val, decoded_value=f"0x{val:08x}")


def decode_raw(data: bytes, offset: int, length: int) -> Operand:
    """Decode raw bytes as hex string."""
    raw = data[offset : offset + length]
    return Operand(type="raw", raw_value=raw, decoded_value=raw.hex())
