"""Tests for WD3 container parser and instruction decoder."""

import struct
import pytest
from ppp_disassembler.core import (
    u8, u16, u32, f32,
    find_wd3,
    find_wd3_container,
    parse_wd3_header,
    parse_stream_header,
    parse_stream_pointer_table,
    SubSectionIterator,
    WD3Container,
    parse_wd3,
)
from ppp_disassembler.decoder import (
    decode_instruction,
    disassemble_stream,
    disassemble_wd3,
)
from ppp_disassembler.stream import (
    StreamInfo, Instruction, SubSectionEntry, StreamRecord, SpriteData,
)
from tests.conftest import make_synthetic_container


class TestByteReaders:
    def test_u8(self) -> None:
        assert u8(b"\xFF\x00", 0) == 255
        assert u8(b"\xFF\x00", 1) == 0

    def test_u16(self) -> None:
        assert u16(b"\x01\x02", 0) == 0x0201

    def test_u32(self) -> None:
        assert u32(b"\x01\x02\x03\x04", 0) == 0x04030201

    def test_f32(self) -> None:
        val = f32(struct.pack("<f", 1.5), 0)
        assert abs(val - 1.5) < 0.001


class TestFindWd3:
    def test_finds_magic(self) -> None:
        data = b"xxxWD3\x01yyy"
        assert find_wd3(data) == 3

    def test_not_found(self) -> None:
        assert find_wd3(b"hello") == -1

    def test_start_offset(self) -> None:
        data = b"WD3\x01WD3\x01"
        assert find_wd3(data, 2) == 4


class TestFindWd3Container:
    def test_validates_and_finds(self) -> None:
        blob, base = make_synthetic_container()
        assert find_wd3_container(blob) == 0

    def test_not_found(self) -> None:
        assert find_wd3_container(b"\x00" * 32) == -1

    def test_too_short(self) -> None:
        assert find_wd3_container(b"WD3\x01") == -1


class TestParseWd3Header:
    def test_parses_synthetic(self) -> None:
        data = bytearray(64)
        data[0:4] = b"WD3\x01"
        struct.pack_into("<I", data, 4, 64)
        struct.pack_into("<H", data, 6, 0)
        struct.pack_into("<H", data, 8, 1)  # stream_count = 1
        hdr = parse_wd3_header(bytes(data), 0)
        assert hdr.magic == "57443301"
        assert hdr.version == 1
        assert hdr.total_size == 64
        assert hdr.stream_count == 1

    def test_invalid_magic_raises(self) -> None:
        with pytest.raises(ValueError, match="WD3 magic"):
            parse_wd3_header(b"XXXX\x00" * 8, 0)


class TestParseStreamHeader:
    def test_parses_synthetic(self) -> None:
        data = bytearray(32)
        struct.pack_into("<I", data, 0, 0)
        struct.pack_into("<I", data, 4, 256)
        struct.pack_into("<I", data, 8, 0)
        struct.pack_into("<I", data, 12, 0x5FC600FF)
        struct.pack_into("<I", data, 16, 0xFE886E2B)
        struct.pack_into("<f", data, 20, 4.0)
        struct.pack_into("<I", data, 24, 0)
        struct.pack_into("<I", data, 28, 0)
        sh = parse_stream_header(bytes(data), 0)
        assert sh.end_offset == 256
        assert sh.start_offset == 0
        assert abs(sh.scale - 4.0) < 0.001

    def test_zero_end_offset_uses_default(self) -> None:
        data = bytearray(32)
        struct.pack_into("<I", data, 4, 0)
        sh = parse_stream_header(bytes(data), 0)
        assert sh.size == 0x20000


class TestParseStreamPointerTable:
    def test_parses_offsets(self) -> None:
        data = bytearray(0x30)
        struct.pack_into("<III", data, 0x20, 0x40, 0x60, 0x80)
        ptrs = parse_stream_pointer_table(bytes(data), 0, 3)
        assert ptrs == [0x40, 0x60, 0x80]


class TestSubSectionIterator:
    def test_iterates_entries(self) -> None:
        data = b"\x00" * 16 * 3
        it = SubSectionIterator(data, 0, 3)
        entries = list(it)
        assert len(entries) == 3
        assert all(isinstance(e, SubSectionEntry) for e in entries)

    def test_empty(self) -> None:
        it = SubSectionIterator(b"", 0, 0)
        assert list(it) == []


class TestParseWd3:
    def test_parses_synthetic_1_stream(self) -> None:
        blob, base = make_synthetic_container(stream_count=1, body_size=128)
        container = parse_wd3(blob, base)
        assert container.version == 1
        assert container.stream_count == 1
        assert len(container.streams) == 1
        assert container.streams[0].size == 128

    def test_parses_5_streams(self) -> None:
        blob, base = make_synthetic_container(stream_count=5, body_size=256)
        container = parse_wd3(blob, base)
        assert container.stream_count == 5
        assert len(container.streams) == 5

    def test_summary(self) -> None:
        blob, base = make_synthetic_container()
        container = parse_wd3(blob, base)
        summary = container.summary()
        assert "WD3 v1" in summary
        assert "streams" in summary

    def test_structure_overlap_raises(self) -> None:
        blob, base = make_synthetic_container()
        data = bytearray(blob)
        struct.pack_into("<I", data, 0x2C, 0x10)
        with pytest.raises(ValueError, match="overlap"):
            parse_wd3(bytes(data), base)

    def test_total_size_exceeds_data_raises(self) -> None:
        blob, base = make_synthetic_container()
        data = bytearray(blob)
        struct.pack_into("<I", data, 4, len(data) + 100)
        with pytest.raises(ValueError, match="exceeds"):
            parse_wd3(bytes(data), base)


class TestDecodeInstruction:
    def test_known_opcode(self) -> None:
        data = bytes([0] * 8 + [0x10] + [0] * 7)
        instr = decode_instruction(data, 0)
        assert instr is not None
        assert instr.opcode_name == "pppColor"
        assert not instr.is_alpha
        assert len(instr.operands) > 0

    def test_alpha_selector(self) -> None:
        data = bytes([0] * 8 + [0x41] + [0] * 7)
        instr = decode_instruction(data, 0)
        assert instr is not None
        assert instr.is_alpha
        assert "ALPHA" in instr.opcode_name

    def test_unknown_opcode(self) -> None:
        data = bytes([0] * 8 + [0xFF] + [0] * 7)
        instr = decode_instruction(data, 0)
        assert instr is not None
        assert "UNKNOWN" in instr.opcode_name

    def test_out_of_bounds_returns_none(self) -> None:
        assert decode_instruction(b"\x00" * 10, 5) is None


class TestDisassembleStream:
    def test_empty_stream(self) -> None:
        assert disassemble_stream(b"", 0, 0) == []

    def test_single_instruction(self) -> None:
        data = bytes([0] * 8 + [0x00] + [0] * 7) + b"\x00" * 16
        instrs = disassemble_stream(data, 0, 32)
        assert len(instrs) == 1
        assert instrs[0].opcode_name == "pppKeThRes32x4"

    def test_multiple_instructions(self) -> None:
        data = (
            bytes([0] * 8 + [0x10] + [0] * 7) +
            bytes([0] * 8 + [0x0D] + [0] * 7) +
            b"\x00" * 16
        )
        instrs = disassemble_stream(data, 0, 48)
        assert len(instrs) == 2
        assert instrs[0].opcode_name == "pppColor"
        assert instrs[1].opcode_name == "pppPoint"

    def test_blob_base_offset(self) -> None:
        instr = bytes([0] * 8 + [0x10] + [0] * 7)
        data = b"\xCC" * 32 + instr + b"\x00"
        instrs = disassemble_stream(data, 32, 18, blob_base=32)
        assert len(instrs) == 1
        assert instrs[0].offset == 0


class TestDisassembleWd3:
    def test_disassembles_all_streams(self) -> None:
        blob, base = make_synthetic_container(stream_count=2, body_size=128)
        container = parse_wd3(blob, base)
        instr_data = bytes([0] * 8 + [0x10] + [0] * 7) * 3
        blob2 = bytearray(blob)
        body_start_abs = base + container.streams[0].start_offset
        blob2[body_start_abs : body_start_abs + len(instr_data)] = instr_data
        container2 = parse_wd3(bytes(blob2), base)
        disassemble_wd3(container2, bytes(blob2))
        total_instrs = sum(len(s.instructions) for s in container2.streams)
        assert total_instrs > 0
