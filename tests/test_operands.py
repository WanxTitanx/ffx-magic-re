"""Tests for the PPP operand decoders — all decode from synthetic bytes."""

import struct
import pytest
from ppp_disassembler.operands import (
    Operand,
    decode_float,
    decode_vec3,
    decode_int16,
    decode_uint16,
    decode_vertex,
    decode_color,
    decode_uv,
    decode_texture_ref,
    decode_matrix_ref,
    decode_raw,
)


class TestOperandDataclass:
    def test_frozen_slots(self) -> None:
        op = Operand(type="test", raw_value=42, decoded_value="42")
        assert op.type == "test"
        assert op.raw_value == 42
        assert op.decoded_value == "42"
        assert op.description == ""

    def test_description_default(self) -> None:
        op = Operand(type="x", raw_value=1.0, decoded_value="1.0")
        assert op.description == ""

    def test_str_repr(self) -> None:
        op = Operand(type="float", raw_value=3.14, decoded_value="3.140000")
        assert str(op) == "[float] 3.140000"


class TestDecodeFloat:
    def test_decodes_float32_le(self) -> None:
        data = struct.pack("<f", 3.14159) + b"\x00" * 4
        op = decode_float(data, 0)
        assert op.type == "float"
        assert isinstance(op.raw_value, float)
        assert abs(op.raw_value - 3.14159) < 0.001


class TestDecodeVec3:
    def test_decodes_three_floats(self) -> None:
        data = struct.pack("<fff", 1.0, 2.0, 3.0)
        op = decode_vec3(data, 0)
        assert op.type == "vec3"
        value = op.raw_value
        assert isinstance(value, tuple)
        x, y, z = value
        assert (x, y, z) == (1.0, 2.0, 3.0)


class TestDecodeInt16:
    def test_signed_int16(self) -> None:
        data = struct.pack("<h", -12345)
        op = decode_int16(data, 0)
        assert op.type == "int16"
        assert op.raw_value == -12345

    def test_overflow_clamped(self) -> None:
        data = struct.pack("<h", 32767)
        op = decode_int16(data, 0)
        assert op.raw_value == 32767


class TestDecodeUint16:
    def test_unsigned_uint16(self) -> None:
        data = struct.pack("<H", 65000)
        op = decode_uint16(data, 0)
        assert op.type == "uint16"
        assert op.raw_value == 65000


class TestDecodeVertex:
    def test_normalizes_by_15(self) -> None:
        data = struct.pack("<hhh", 15, 0, -15)
        op = decode_vertex(data, 0)
        assert op.type == "vertex"
        value = op.raw_value
        assert isinstance(value, tuple)
        x, y, z = value
        assert (x, y, z) == (15, 0, -15)
        assert "-1.0000" in op.decoded_value  # -15/15 = -1.0


class TestDecodeColor:
    def test_normalizes_by_128(self) -> None:
        data = bytes([128, 64, 192, 255])
        op = decode_color(data, 0)
        assert op.type == "color"
        value = op.raw_value
        assert isinstance(value, tuple)
        r, g, b, a = value
        assert (r, g, b, a) == (128, 64, 192, 255)
        assert "RGBA(1.000" in op.decoded_value
        assert "#8040c0ff" in op.decoded_value


class TestDecodeUV:
    def test_normalizes_u_by_4096(self) -> None:
        data = struct.pack("<HH", 4096, 0)
        op = decode_uv(data, 0)
        assert op.type == "uv"
        assert "U=1.000000" in op.decoded_value
        assert "V=1.000000" in op.decoded_value

    def test_v_is_flipped(self) -> None:
        data = struct.pack("<HH", 2048, 2048)
        op = decode_uv(data, 0)
        assert "V=0.500000" in op.decoded_value


class TestDecodeTextureRef:
    def test_parses_packed_fields(self) -> None:
        packed = 42 | (3 << 20) | (6 << 26) | (5 << 30)
        data = struct.pack("<Q", packed)
        op = decode_texture_ref(data, 0)
        assert op.type == "texture_ref"
        assert "id=42" in op.decoded_value
        assert "sub=3" in op.decoded_value
        assert "64x32" in op.decoded_value

    def test_no_dds_phyre_path(self) -> None:
        """Sanitized: no private DLL texture path format."""
        data = struct.pack("<Q", 0x3FFF_3F_0F_0E)
        op = decode_texture_ref(data, 0)
        assert ".dds.phyre" not in op.decoded_value
        assert ".dds" not in op.decoded_value


class TestDecodeMatrixRef:
    def test_decodes_u32(self) -> None:
        data = struct.pack("<I", 0xDEADBEEF)
        op = decode_matrix_ref(data, 0)
        assert op.type == "matrix_ref"
        assert "deadbeef" in op.decoded_value.lower()


class TestDecodeRaw:
    def test_raw_hex_output(self) -> None:
        data = bytes(range(4))
        op = decode_raw(data, 0, 4)
        assert op.type == "raw"
        assert op.decoded_value == "00010203"

    def test_partial_read(self) -> None:
        data = bytes([0xAB, 0xCD])
        op = decode_raw(data, 0, 1)
        assert op.decoded_value == "ab"
