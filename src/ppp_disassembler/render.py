"""Sprite and stream visualization for PPP disassembler — ASCII hex/vertex rendering."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from .operands import Operand
from .opcodes import OPCODES, ALPHA_FUNCTIONS


def format_hex_dump(
    data: bytes,
    offset: int = 0,
    length: int | None = None,
    bytes_per_line: int = 16,
    annotate_opcodes: bool = True,
) -> list[str]:
    """Produce a hex dump with optional opcode annotations.

    Args:
        data: Raw bytes to dump.
        offset: Starting byte offset into *data*.
        length: How many bytes to dump (default: rest of data).
        bytes_per_line: Bytes per row in output (default 16).
        annotate_opcodes: Highlight known opcode/alpha bytes with ``>``.

    Returns:
        Lines of formatted hex dump.
    """
    if length is None:
        length = len(data) - offset
    end = min(offset + length, len(data))
    lines: list[str] = []

    for i in range(offset, end, bytes_per_line):
        chunk = data[i : i + bytes_per_line]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = hex_part.ljust(bytes_per_line * 3 - 1)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        marker = " "
        if annotate_opcodes and i < len(data):
            b = data[i]
            if b in OPCODES or b in ALPHA_FUNCTIONS:
                marker = ">"
        lines.append(f"{marker} {i:06x}: {hex_part}  |{ascii_part}|")
    return lines


def hex_dump(
    data: bytes,
    offset: int = 0,
    length: int | None = None,
    bytes_per_line: int = 16,
    annotate_opcodes: bool = True,
) -> str:
    """Return a hex dump string (multi-line)."""
    return "\n".join(
        format_hex_dump(data, offset, length, bytes_per_line, annotate_opcodes)
    )


def _clamp(val: float, lo: float, hi: float) -> int:
    return int(max(lo, min(hi, val)))


def render_vertex_grid(
    vertices: Sequence[tuple[float, float]],
    width: int = 48,
    height: int = 20,
    label: str = "Vertices",
) -> str:
    """Render a set of 2D vertices as an ASCII art grid.

    Origin (0,0) is bottom-left.
    """
    if not vertices:
        return f"  {label}: (none)"

    xs = [v[0] for v in vertices]
    ys = [v[1] for v in vertices]
    x0, x1 = min(xs), max(xs)
    y0, y1 = min(ys), max(ys)
    x_range = x1 - x0 or 1.0
    y_range = y1 - y0 or 1.0

    grid: list[list[str]] = [[" "] * width for _ in range(height)]

    for vx, vy in vertices:
        col = int((vx - x0) / x_range * (width - 1))
        row = int((vy - y0) / y_range * (height - 1))
        col = _clamp(col, 0, width - 1)
        row = _clamp(row, 0, height - 1)
        if grid[height - 1 - row][col] == " ":
            grid[height - 1 - row][col] = "*"
        else:
            grid[height - 1 - row][col] = "+"

    lines = [f"  {label}:"]
    for r in range(height):
        lines.append("  \u2502" + "".join(grid[r]) + "\u2502")
    lines.append(f"  \u2514{'─' * width}\u2518")
    lines.append(f"  x:[{x0:.1f},{x1:.1f}]  y:[{y0:.1f},{y1:.1f}]")
    return "\n".join(lines)


def render_triangle(
    v0: tuple[float, float],
    v1: tuple[float, float],
    v2: tuple[float, float],
    color: tuple[int, int, int, int] | None = None,
    width: int = 24,
    height: int = 12,
) -> str:
    """Render a single triangle via ASCII art."""
    verts = [v0, v1, v2]
    out = [
        f"  Tri: v0({v0[0]:.1f},{v0[1]:.1f}) "
        + f"v1({v1[0]:.1f},{v1[1]:.1f}) "
        + f"v2({v2[0]:.1f},{v2[1]:.1f})"
    ]
    if color:
        out.append(f"       RGBA({color[0]},{color[1]},{color[2]},{color[3]})")
    out.append(render_vertex_grid(verts, width, height, "").lstrip())
    return "\n".join(out)


def render_sprite_reference(
    texture_id: int,
    subtype: int,
    size_w: int,
    size_h: int,
    vertices: Sequence[tuple[float, float]] | None = None,
    colors: Sequence[tuple[int, int, int, int]] | None = None,
    uvs: Sequence[tuple[float, float]] | None = None,
) -> str:
    """Render a sprite reference with optional vertex/color/UV detail."""
    lines: list[str] = []
    lines.append(f"  Texture: id={texture_id} subtype={subtype} {size_w}\u00d7{size_h}")

    if vertices:
        lines.append(render_vertex_grid(vertices, 32, 14, "Vertices"))

    if colors:
        c_strs = ", ".join(f"rgba({r},{g},{b},{a})" for r, g, b, a in colors[:4])
        if len(colors) > 4:
            c_strs += f" \u2026 (+{len(colors) - 4} more)"
        lines.append(f"  Colors: [{c_strs}]")

    if uvs:
        uv_strs = ", ".join(f"({u:.3f},{v:.3f})" for u, v in uvs[:4])
        if len(uvs) > 4:
            uv_strs += f" \u2026 (+{len(uvs) - 4} more)"
        lines.append(f"  UVs: [{uv_strs}]")

    return "\n".join(lines)


class _InstructionLike(Protocol):
    """Minimal instruction interface for stream summarization."""
    opcode_byte: int
    raw_bytes: bytes
    operands: Sequence[Operand]


def summarize_stream(
    instructions: Sequence[_InstructionLike],
    stream_index: int = 0,
    max_instructions: int = 20,
) -> str:
    """Produce a human-readable summary of one stream's instructions.

    Args:
        instructions: Sequence of Instruction-like objects.
        stream_index: Which stream this is (0-4).
        max_instructions: Truncate output above this many.

    Returns:
        Multi-line summary string.
    """
    lines: list[str] = []
    total = len(instructions)
    shown = min(total, max_instructions)
    lines.append(
        f"  Stream {stream_index}: {total} instructions "
        + f"({'truncated' if shown < total else 'full'})"
    )

    for i in range(shown):
        insn = instructions[i]
        opcode_entry = OPCODES.get(insn.opcode_byte)
        name = (
            opcode_entry.name
            if opcode_entry
            else f"UNKNOWN_{insn.opcode_byte:02x}"
        )
        raw_hex = insn.raw_bytes.hex()
        operands_str = ", ".join(
            str(op.decoded_value or op.raw_value)
            for op in insn.operands[:4]
        )
        lines.append(
        f"    {i:4d}: [{insn.opcode_byte:02x}] {name:20s} | "
        + f"{raw_hex[:40]:40s} | {operands_str}"
        )

    if shown < total:
        lines.append(f"    \u2026 {total - shown} more instructions omitted")
    return "\n".join(lines)
