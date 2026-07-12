"""Tests for PPP stream models — enums, entries, dataclasses."""

from ppp_disassembler.stream import (
    EntryTypeEnum,
    StreamType,
    SubSectionEntry,
    StreamInfo,
    Instruction,
    StreamRecord,
    SpriteData,
)
from ppp_disassembler.operands import Operand


class TestEntryTypeEnum:
    def test_from_tag_3_is_sprite(self) -> None:
        assert EntryTypeEnum.from_tag(3) == EntryTypeEnum.SPRITE_RECORD

    def test_from_tag_other_is_parameter(self) -> None:
        assert EntryTypeEnum.from_tag(0) == EntryTypeEnum.PARAMETER
        assert EntryTypeEnum.from_tag(5) == EntryTypeEnum.PARAMETER


class TestStreamType:
    def test_classify_streams(self) -> None:
        assert StreamType.classify(0) == StreamType.PARTICLE_DEF
        assert StreamType.classify(1) == StreamType.UPDATE
        assert StreamType.classify(2) == StreamType.DRAW
        assert StreamType.classify(3) == StreamType.TEXTURE
        assert StreamType.classify(4) == StreamType.CLEANUP
        assert StreamType.classify(5) == StreamType.UNKNOWN

    def test_name_in_stream_info(self) -> None:
        si = StreamInfo(index=2, start_offset=0x40, end_offset=0x100,
                        size=0xC0, scale=4.0, packed1=0, packed2=0)
        assert si.type_name == "DRAW"


class TestSubSectionEntry:
    def test_frozen_dataclass(self) -> None:
        entry = SubSectionEntry(
            offset=0x100, ptr_type_descriptor=0x1234, data_offset=0x5678,
            opcode_byte=0x10, type_tag=3, count=5, runtime_data=0,
            raw_bytes=b"\x00" * 16,
        )
        assert entry.offset == 0x100
        assert entry.ptr_type_descriptor == 0x1234

    def test_entry_type_sprite(self) -> None:
        entry = SubSectionEntry(
            offset=0, ptr_type_descriptor=0, data_offset=0,
            opcode_byte=0, type_tag=3, count=2, runtime_data=0,
            raw_bytes=b"\x00" * 16,
        )
        assert entry.entry_type == EntryTypeEnum.SPRITE_RECORD
        assert entry.total_size == 16 + 40 * 2  # header + 2 sprites

    def test_entry_type_parameter(self) -> None:
        entry = SubSectionEntry(
            offset=0, ptr_type_descriptor=0, data_offset=0,
            opcode_byte=0, type_tag=0, count=0, runtime_data=0,
            raw_bytes=b"\x00" * 16,
        )
        assert entry.entry_type == EntryTypeEnum.PARAMETER
        assert entry.total_size == 16


class TestInstruction:
    def test_str_representation(self) -> None:
        instr = Instruction(
            opcode_byte=0x10, opcode_name="pppColor",
            stream_index=2, offset=0x42,
            raw_bytes=b"\x00" * 16,
        )
        s = str(instr)
        assert "OP 0x000042" in s
        assert "pppColor" in s

    def test_alpha_str_representation(self) -> None:
        instr = Instruction(
            opcode_byte=0x41, opcode_name="ALPHA_alpha=1.0 (full)",
            stream_index=0, offset=0x00,
            raw_bytes=b"\x00" * 16, is_alpha=True,
            alpha_desc="alpha=1.0 (full)",
        )
        s = str(instr)
        assert "ALPHA" in s

    def test_default_fields(self) -> None:
        instr = Instruction(
            opcode_byte=0xFF, opcode_name="UNKNOWN_0xff",
            stream_index=0, offset=0,
            raw_bytes=b"\x00" * 16,
        )
        assert instr.total_size == 16
        assert not instr.is_alpha
        assert instr.operands == []


class TestStreamRecord:
    def test_frozen_dataclass(self) -> None:
        rec = StreamRecord(
            offset=0, ptr_type_descriptor=0, data_offset=0,
            opcode=0x10, type_tag=0, count=0, runtime_data=0,
            alpha_desc="",
        )
        assert rec.header_size == 16

    def test_with_sprites(self) -> None:
        sprite = SpriteData(
            v0=(0, 1, 2), v1=(3, 4, 5), v2=(6, 7, 8),
            color_rgba="#ff8000ff", uv1=(0, 0), uv2=(4096, 4096),
        )
        rec = StreamRecord(
            offset=0, ptr_type_descriptor=0x1234, data_offset=0x5678,
            opcode=0x10, type_tag=3, count=1, runtime_data=0xABCD,
            alpha_desc="", body_size=40, total_size=56,
            sprites=(sprite,),
        )
        assert rec.sprites[0].color_rgba == "#ff8000ff"
        assert rec.sprites[0].v0 == (0, 1, 2)


class TestSpriteData:
    def test_frozen_slots(self) -> None:
        sd = SpriteData(
            v0=(1, 2, 3), v1=(4, 5, 6), v2=(7, 8, 9),
            color_rgba="#00000000", uv1=(0, 0), uv2=(1, 1),
        )
        assert sd.v0 == (1, 2, 3)
