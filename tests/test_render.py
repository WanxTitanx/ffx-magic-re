"""Tests for PPP render/visualization."""

from ppp_disassembler.render import (
    hex_dump,
    format_hex_dump,
    render_vertex_grid,
    render_triangle,
    render_sprite_reference,
    summarize_stream,
)


class TestHexDump:
    def test_hex_dump_empty(self) -> None:
        assert hex_dump(b"") == ""

    def test_hex_dump_short(self) -> None:
        data = b"\x00\x01\x02\x03"
        result = format_hex_dump(data)
        assert len(result) == 1
        assert "000000" in result[0]

    def test_hex_dump_annotates_known_opcode(self) -> None:
        data = bytes([0x10]) + b"\x00" * 15
        result = format_hex_dump(data, annotate_opcodes=True)
        assert result[0].startswith(">")

    def test_hex_dump_no_annotation_when_disabled(self) -> None:
        data = bytes([0x10]) + b"\x00" * 15
        result = format_hex_dump(data, annotate_opcodes=False)
        assert result[0].startswith(" ")

    def test_hex_dump_multi_line(self) -> None:
        data = bytes(range(32))
        result = format_hex_dump(data)
        assert len(result) == 2


class TestRenderVertexGrid:
    def test_empty_vertices(self) -> None:
        result = render_vertex_grid([])
        assert "none" in result

    def test_single_vertex(self) -> None:
        result = render_vertex_grid([(0.0, 0.0)], width=10, height=5)
        assert "*" in result
        assert "x:[0.0,0.0]" in result


class TestRenderTriangle:
    def test_triangle_string(self) -> None:
        result = render_triangle((0, 0), (1, 0), (0, 1))
        assert "Tri:" in result
        assert "v0(" in result

    def test_triangle_with_color(self) -> None:
        result = render_triangle((0, 0), (1, 0), (0, 1),
                                 color=(255, 0, 0, 255))
        assert "RGBA" in result


class TestRenderSpriteReference:
    def test_basic_sprite(self) -> None:
        result = render_sprite_reference(42, 3, 64, 32)
        assert "id=42" in result
        assert "subtype=3" in result

    def test_with_vertices_colors_uvs(self) -> None:
        result = render_sprite_reference(
            1, 0, 16, 16,
            vertices=[(0.0, 0.0), (1.0, 0.0)],
            colors=[(255, 0, 0, 255)],
            uvs=[(0.0, 0.0), (1.0, 1.0)],
        )
        assert "Vertices" in result
        assert "Colors" in result
        assert "UVs" in result


class TestSummarizeStream:
    def test_empty_stream(self) -> None:
        result = summarize_stream([], stream_index=2)
        assert "Stream 2" in result
        assert "0 instructions" in result

    def test_less_than_max(self) -> None:
        from ppp_disassembler import Instruction
        instrs = [
            Instruction(opcode_byte=0x10, opcode_name="pppColor",
                        stream_index=0, offset=0, raw_bytes=b"\x00" * 16)
            for _ in range(3)
        ]
        result = summarize_stream(instrs, max_instructions=20)
        assert "truncated" not in result

    def test_truncation(self) -> None:
        from ppp_disassembler import Instruction
        instrs = [
            Instruction(opcode_byte=0x00, opcode_name="test",
                        stream_index=0, offset=i, raw_bytes=b"\x00" * 16)
            for i in range(25)
        ]
        result = summarize_stream(instrs, max_instructions=10)
        assert "truncated" in result
        assert "15 more" in result

    def test_unknown_opcode_renders_as_unknown(self) -> None:
        from ppp_disassembler import Instruction
        instrs = [
            Instruction(opcode_byte=0xFF, opcode_name="UNKNOWN_0xff",
                        stream_index=0, offset=0, raw_bytes=b"\xFF" * 16)
        ]
        result = summarize_stream(instrs)
        assert "UNKNOWN_ff" in result
