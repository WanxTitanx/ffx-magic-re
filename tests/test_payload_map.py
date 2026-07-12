"""Tests for payload layout and ownership-span computation."""

from dataclasses import dataclass, field
import pytest
from ppp_disassembler.payload_map import (
    compute_payload_layout,
    compute_ownership_spans,
    PayloadLayout,
    OwnershipSpan,
    PayloadMapError,
)
from ppp_disassembler.stream import StreamInfo


@dataclass
class FakePayload:
    total_size: int = 0
    stream_header_offsets: list[int] = field(default_factory=list)
    streams: list[StreamInfo] = field(default_factory=list)


class TestPayloadLayout:
    def test_compute_layout(self) -> None:
        streams = [
            StreamInfo(index=0, start_offset=150, end_offset=200, size=50,
                       scale=4.0, packed1=0, packed2=0),
        ]
        container = FakePayload(
            total_size=200,
            stream_header_offsets=[64, 96],
            streams=streams,
        )
        layout = compute_payload_layout(container)
        assert isinstance(layout, PayloadLayout)
        assert layout.prefix == (0, 128)
        assert layout.body == (150, 200)
        assert layout.total_size == 200

    def test_empty_streams_raises(self) -> None:
        with pytest.raises(PayloadMapError):
            compute_payload_layout(FakePayload())

    def test_overlap_raises(self) -> None:
        streams = [
            StreamInfo(index=0, start_offset=50, end_offset=100, size=50,
                       scale=4.0, packed1=0, packed2=0),
        ]
        container = FakePayload(
            total_size=200, stream_header_offsets=[32], streams=streams,
        )
        with pytest.raises(PayloadMapError, match="overlap"):
            compute_payload_layout(container)

    def test_stream_outside_body_raises(self) -> None:
        """Stream end_offset exceeds total_size."""
        streams = [
            StreamInfo(index=0, start_offset=100, end_offset=250, size=150,
                       scale=4.0, packed1=0, packed2=0),
        ]
        container = FakePayload(
            total_size=200, stream_header_offsets=[48], streams=streams,
        )
        with pytest.raises(PayloadMapError, match="outside"):
            compute_payload_layout(container)


class TestOwnershipSpans:
    def test_single_stream_owns_all(self) -> None:
        streams = [
            StreamInfo(index=0, start_offset=100, end_offset=200, size=100,
                       scale=4.0, packed1=0, packed2=0),
        ]
        container = FakePayload(
            total_size=200, stream_header_offsets=[48], streams=streams,
        )
        spans = compute_ownership_spans(container)
        assert len(spans) == 1
        assert spans[0].owners == (0,)

    def test_two_streams_overlap(self) -> None:
        """Body start must be after end of the largest stream header (112)."""
        streams = [
            StreamInfo(index=0, start_offset=120, end_offset=180, size=60,
                       scale=4.0, packed1=0, packed2=0),
            StreamInfo(index=1, start_offset=150, end_offset=200, size=50,
                       scale=4.0, packed1=0, packed2=0),
        ]
        container = FakePayload(
            total_size=200, stream_header_offsets=[48, 80], streams=streams,
        )
        spans = compute_ownership_spans(container)
        assert len(spans) >= 2
        assert spans[0].owners == (0,)
        assert spans[-1].owners == (1,)

    def test_orphan_interval_raises(self) -> None:
        """150-160 gap owned by neither stream 0 (ends 150) nor stream 1 (starts 160)."""
        streams = [
            StreamInfo(index=0, start_offset=120, end_offset=150, size=30,
                       scale=4.0, packed1=0, packed2=0),
            StreamInfo(index=1, start_offset=160, end_offset=200, size=40,
                       scale=4.0, packed1=0, packed2=0),
        ]
        container = FakePayload(
            total_size=200, stream_header_offsets=[48, 80], streams=streams,
        )
        with pytest.raises(PayloadMapError, match="orphan"):
            compute_ownership_spans(container)
