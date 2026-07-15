"""
ppp_disassembler — WD3 container format parser and EgoVM bytecode structural analysis.

ResearchStatus
==============
This is a **structural analysis toolkit** for the WD3 container format and its
embedded EgoVM-style bytecode. It decodes binary containers into typed Python
data structures, renders human-readable summaries, and round-trips the
structural layout through serialization.

**Supported (v0.1.0):**
    - WD3 container header and stream pointer-table parsing
    - Per-stream header parsing (offset, size, scale, packed fields)
    - 16-byte sub-section entry iteration and classification
    - Opcode table lookup (36 opcode entries + 6 alpha function selectors)
    - Typed operand decoding (float, vec3, vertex, color, UV, texture_ref)
    - Structural serialization (round-trip: parse → serialize → byte-identical)
    - Payload layout and stream ownership-span computation
    - ASCII hex dump and vertex-grid rendering

**Experimental / Not Supported:**
    - Semantic PPP authoring (writing new particle programs from scratch)
    - New effect generation or bytecode synthesis beyond structural round-trip
    - Host-context slot resolution (opcode handler binding to runtime functions)
    - PE/DLL file reading (callers provide raw bytes; the toolkit does not
      open or parse executable files)

Design Principles
-----------------
    - Accepts user-provided raw bytes. No game files are bundled or required.
    - All tests use synthetic fixtures — no proprietary data.
    - Strict typing: no ``Any``, no casts, no ``# type: ignore``.
    - Frozen, slotted dataclasses for immutable structural records.
"""

from .opcodes import OPCODES, ALPHA_FUNCTIONS, OpcodeEntry, AlphaEntry
from .operands import Operand, decode_float, decode_vec3, decode_vertex
from .operands import decode_color, decode_uv
from .stream import StreamType, StreamInfo, Instruction, StreamRecord, SpriteData
from .core import (
    WD3Container,
    find_wd3,
    find_wd3_container,
    parse_wd3_header,
    parse_wd3,
)
from .decoder import (
    decode_instruction,
    disassemble_stream,
    disassemble_wd3,
)
from .wd3_writer import serialize_wd3_structure
from .wd3_blob_writer import serialize_wd3_blob
from .payload_map import compute_payload_layout, compute_ownership_spans
from .c2_color_codec import ColorPayload, parse_color_payload, serialize_color_payload
from .c2_scale_codec import ScalePayload, parse_scale_payload, serialize_scale_payload
from .c2_effect_overlay import apply_overlay, verify_overlay, OverlayMapping, PeDataSection

__version__ = "0.3.0"

__all__ = [
    "__version__",
    "OPCODES",
    "ALPHA_FUNCTIONS",
    "OpcodeEntry",
    "AlphaEntry",
    "Operand",
    "decode_float",
    "decode_vec3",
    "decode_vertex",
    "decode_color",
    "decode_uv",
    "StreamType",
    "StreamInfo",
    "Instruction",
    "StreamRecord",
    "SpriteData",
    "WD3Container",
    "find_wd3",
    "find_wd3_container",
    "parse_wd3_header",
    "parse_wd3",
    "decode_instruction",
    "disassemble_stream",
    "disassemble_wd3",
    "serialize_wd3_structure",
    "serialize_wd3_blob",
    "compute_payload_layout",
    "compute_ownership_spans",
    "ColorPayload",
    "parse_color_payload",
    "serialize_color_payload",
    "ScalePayload",
    "parse_scale_payload",
    "serialize_scale_payload",
    "apply_overlay",
    "verify_overlay",
    "OverlayMapping",
    "PeDataSection",
]
