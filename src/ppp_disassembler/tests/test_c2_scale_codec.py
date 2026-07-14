"""TDD tests for the C2 SCALE-family authoring-payload codec.

RAW AUTHORING CODEC ONLY — NOT a runtime 16-byte slot record editor.
These tests validate lossless parse/serialize of the raw 12-byte payload
as three 32-bit little-endian words. The bridge to the runtime 16B record
is separately gated and out of scope.

Uses synthetic fixtures inline — no game data.
"""
from __future__ import annotations

import struct

import pytest

from ..c2_scale_codec import (
    SCALE_PAYLOAD_SIZE,
    ScalePayload,
    ScalePayloadSizeError,
    parse_scale_payload,
    serialize_scale_payload,
)


class TestScalePayloadParseSerialize:
    @pytest.mark.parametrize("raw", [
        b"\x00" * 12,
        b"\xFF" * 12,
        b"\x00\x00\x48\x42\x00\x00\x48\x42\x00\x00\x48\x42",
        b"\xCD\xCC\x4C\x3F\xCD\xCC\x4C\x3F\xCD\xCC\x4C\x3F",
        b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C",
    ])
    def test_roundtrip(self, raw: bytes) -> None:
        payload = parse_scale_payload(raw)
        assert serialize_scale_payload(payload) == raw

    def test_parse_fields(self) -> None:
        raw = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C"
        payload = parse_scale_payload(raw)
        assert payload.w0 == 0x04030201
        assert payload.w1 == 0x08070605
        assert payload.w2 == 0x0C0B0A09

    def test_serialize_from_fields(self) -> None:
        payload = ScalePayload(w0=0x04030201, w1=0x08070605, w2=0x0C0B0A09)
        assert serialize_scale_payload(payload) == b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C"


class TestScalePayloadSize:
    def test_wrong_size_raises(self) -> None:
        with pytest.raises(ScalePayloadSizeError):
            parse_scale_payload(b"\x00" * 11)
        with pytest.raises(ScalePayloadSizeError):
            parse_scale_payload(b"\x00" * 13)

    def test_payload_size_constant(self) -> None:
        assert SCALE_PAYLOAD_SIZE == 12
