"""Stream models for the 5 EgoVM streams in a WD3 container.

Each WD3 container has a dynamic stream count (typically 5). Streams share
a common 16-byte stride sub-section entry structure and a 40-byte sprite
record format.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Sequence

from .operands import Operand


class EntryTypeEnum(Enum):
    """Type of sub-section entry in the PPP bytecode stream.

    Based on the type_tag field at entry+9:
        ``3`` = sprite/texture record (40 B per sprite)
        other = parameter/data record (16 B header only)
    """
    SPRITE_RECORD = 3
    PARAMETER = 0
    UNKNOWN = 1

    @classmethod
    def from_tag(cls, tag: int) -> EntryTypeEnum:
        if tag == 3:
            return cls.SPRITE_RECORD
        return cls.PARAMETER


@dataclass(frozen=True, slots=True)
class SpriteData:
    """A parsed sprite record within a stream.

    Attributes:
        v0/v1/v2: Raw int16 vertex coordinates (unnormalized).
        color_rgba: Hex-encoded RGBA string (e.g. ``"#ff8080ff"``).
        uv1/uv2: Raw uint16 UV coordinate pairs (unnormalized).
    """
    v0: tuple[int, int, int]
    v1: tuple[int, int, int]
    v2: tuple[int, int, int]
    color_rgba: str
    uv1: tuple[int, int]
    uv2: tuple[int, int]


@dataclass(frozen=True, slots=True)
class StreamRecord:
    """A parsed sub-section entry from the PPP bytecode stream.

    Attributes:
        offset: Offset from blob base.
        ptr_type_descriptor: Raw u32 pointer to EgoVM type descriptor.
        data_offset: Offset/relocation data into resource buffer.
        opcode: The secondary opcode byte.
        type_tag: Type tag (3 = sprite/texture, other = parameter).
        count: Sprite count (if type_tag == 3) or data count.
        runtime_data: Runtime/timestamp data.
        alpha_desc: Alpha function description (empty for standard opcodes).
        header_size: Size of the entry header (always 16).
        body_size: Size of the entry body (0 or ``count × 40`` for sprites).
        total_size: Total size of the entry in bytes.
        sprites: Parsed sprite records (empty for non-sprite entries).
    """
    offset: int
    ptr_type_descriptor: int
    data_offset: int
    opcode: int
    type_tag: int
    count: int
    runtime_data: int
    alpha_desc: str
    header_size: int = 16
    body_size: int = 0
    total_size: int = 16
    sprites: tuple[SpriteData, ...] = ()


@dataclass(frozen=True, slots=True)
class SubSectionEntry:
    """A single 16-byte sub-section entry from the PPP bytecode stream.

    Entry layout:
      +0x00: u32 ptr_type_descriptor
      +0x04: u32 data_offset
      +0x08: u8  opcode_byte
      +0x09: u8  type_tag — 3 = sprite, other = param
      +0x0A: u16 count
      +0x0C: u32 runtime_data
    """
    offset: int
    ptr_type_descriptor: int
    data_offset: int
    opcode_byte: int
    type_tag: int
    count: int
    runtime_data: int
    raw_bytes: bytes

    @property
    def entry_type(self) -> EntryTypeEnum:
        return EntryTypeEnum.from_tag(self.type_tag)

    @property
    def total_size(self) -> int:
        if self.type_tag == 3:
            return 16 + 40 * self.count
        return 16


class StreamType(Enum):
    """Semantic classification of a stream within the WD3 container.

    This is a heuristic based on observed stream roles; actual semantics
    may vary per WD3 blob.
    """
    UNKNOWN = 0
    PARTICLE_DEF = 1
    UPDATE = 2
    DRAW = 3
    TEXTURE = 4
    CLEANUP = 5

    @classmethod
    def classify(cls, stream_index: int) -> StreamType:
        mapping = {
            0: cls.PARTICLE_DEF,
            1: cls.UPDATE,
            2: cls.DRAW,
            3: cls.TEXTURE,
            4: cls.CLEANUP,
        }
        return mapping.get(stream_index, cls.UNKNOWN)


@dataclass
class StreamInfo:
    """Information about a single stream within a WD3 container."""
    index: int
    start_offset: int
    end_offset: int
    size: int
    scale: float
    packed1: int
    packed2: int
    raw_end_offset: int = 0
    unused0: int = 0
    unused1: int = 0
    unused2: int = 0
    instructions: list["Instruction"] = field(default_factory=list)
    records: list[StreamRecord] = field(default_factory=list)

    @property
    def stream_type(self) -> StreamType:
        return StreamType.classify(self.index)

    @property
    def type_name(self) -> str:
        return self.stream_type.name


@dataclass
class Instruction:
    """A single decoded PPP instruction from a stream."""
    opcode_byte: int
    opcode_name: str
    stream_index: int
    offset: int
    raw_bytes: bytes
    operands: Sequence[Operand] = field(default_factory=list)
    total_size: int = 16
    is_alpha: bool = False
    alpha_desc: str = ""
    type_tag: int = 0
    count: int = 0

    def __str__(self) -> str:
        prefix = "ALPHA" if self.is_alpha else "OP"
        ops = " ".join(str(o) for o in self.operands)
        return f"[{prefix} 0x{self.offset:06x}] {self.opcode_name:<20s} {ops}"
