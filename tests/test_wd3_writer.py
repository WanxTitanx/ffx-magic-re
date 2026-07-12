"""Tests for WD3 structure/blob serialization."""

import struct
import pytest
from ppp_disassembler.wd3_writer import serialize_wd3_structure, Wd3StructureError
from ppp_disassembler.wd3_blob_writer import serialize_wd3_blob, Wd3Blob
from ppp_disassembler.stream import StreamInfo
from ppp_disassembler.core import parse_wd3, WD3Container
from tests.conftest import FakeContainer, make_synthetic_container


class TestSerializeWd3Structure:
    def test_roundtrip_1_stream(self) -> None:
        fc = FakeContainer.from_synthetic(stream_count=1, body_size=128)
        result = serialize_wd3_structure(fc)
        assert result[:4] == b"WD3\x01"
        (ts,) = struct.unpack_from("<I", result, 4)
        assert ts == fc.total_size

    def test_roundtrip_5_streams(self) -> None:
        fc = FakeContainer.from_synthetic(stream_count=5, body_size=256)
        result = serialize_wd3_structure(fc)
        (cnt,) = struct.unpack_from("<H", result, 8)  # stream_count at +8
        assert cnt == 5

    def test_wd3_magic_at_start(self) -> None:
        fc = FakeContainer.from_synthetic(stream_count=1, body_size=64)
        result = serialize_wd3_structure(fc)
        assert result[:3] == b"WD3"

    def test_stream_count_mismatch_raises(self) -> None:
        fc = FakeContainer.from_synthetic(stream_count=3)
        fc.streams.pop()
        with pytest.raises(Wd3StructureError):
            serialize_wd3_structure(fc)

    def test_header_offset_mismatch_raises(self) -> None:
        fc = FakeContainer.from_synthetic(stream_count=2)
        fc.stream_header_offsets.pop()
        with pytest.raises(Wd3StructureError):
            serialize_wd3_structure(fc)


class TestSerializeWd3Blob:
    def test_full_blob_roundtrip(self) -> None:
        fc = FakeContainer.from_synthetic(stream_count=1, body_size=64)
        result = serialize_wd3_blob(fc)
        assert len(result) == fc.total_size
        assert result[:4] == b"WD3\x01"

    def test_5_stream_blob(self) -> None:
        fc = FakeContainer.from_synthetic(stream_count=5, body_size=128)
        result = serialize_wd3_blob(fc)
        assert len(result) == fc.total_size

    def test_size_mismatch_raises(self) -> None:
        fc = FakeContainer.from_synthetic(stream_count=1, body_size=64)
        fc.total_size = 9999
        with pytest.raises(Wd3StructureError):
            serialize_wd3_blob(fc)

    # ---- Parse → serialize → re-parse roundtrip ----

    def test_parse_serialize_byte_exact(self) -> None:
        """parse_wd3 → serialize_wd3_blob must produce byte-identical output."""
        blob, base = make_synthetic_container(stream_count=1, body_size=128)
        container = parse_wd3(blob, base)
        result = serialize_wd3_blob(container)
        assert result == blob[: container.total_size]

    def test_parse_serialize_5_streams_byte_exact(self) -> None:
        blob, base = make_synthetic_container(stream_count=5, body_size=256)
        container = parse_wd3(blob, base)
        result = serialize_wd3_blob(container)
        assert result == blob[: container.total_size]

    def test_parse_serialize_reparse_fields_match(self) -> None:
        """parse → serialize → re-parse: every field on the second parse must match the first."""
        blob, base = make_synthetic_container(stream_count=3, body_size=192)
        c1 = parse_wd3(blob, base)
        serialized = serialize_wd3_blob(c1)
        c2 = parse_wd3(serialized, 0)
        assert c2.version == c1.version
        assert c2.total_size == c1.total_size
        assert c2.stream_count == c1.stream_count
        assert c2.stream_header_offsets == c1.stream_header_offsets
        assert c2.pointer_table_gap == c1.pointer_table_gap
        assert c2.post_prefix_gap == c1.post_prefix_gap
        assert c2.body == c1.body
        assert len(c2.streams) == len(c1.streams)
        for s1, s2 in zip(c1.streams, c2.streams):
            assert s1.start_offset == s2.start_offset
            assert s1.end_offset == s2.end_offset
            assert s1.size == s2.size
            assert abs(s1.scale - s2.scale) < 0.001

    # ---- FakeContainer must match parse_wd3 output ----

    def test_fake_container_matches_parsed(self) -> None:
        """FakeContainer.from_synthetic must produce the same fields as parse_wd3."""
        blob, base = make_synthetic_container(stream_count=2, body_size=128)
        real = parse_wd3(blob, base)
        fake = FakeContainer.from_synthetic(stream_count=2, body_size=128)
        assert fake.total_size == real.total_size
        assert fake.stream_count == real.stream_count
        assert fake.stream_header_offsets == real.stream_header_offsets
        assert fake.pointer_table_gap == real.pointer_table_gap
        assert fake.post_prefix_gap == real.post_prefix_gap
        assert len(fake.body) == len(real.body)
        for sf, sr in zip(fake.streams, real.streams):
            assert sf.start_offset == sr.start_offset
            assert sf.end_offset == sr.end_offset
