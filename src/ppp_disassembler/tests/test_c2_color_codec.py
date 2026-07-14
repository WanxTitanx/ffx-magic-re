"""TDD tests for the C2 COLOR-family authoring-payload codec.

RAW AUTHORING CODEC ONLY — NOT a runtime 16-byte slot record editor.
These tests validate lossless parse/serialize of the raw 8-byte payload
as four 16-bit little-endian words. The bridge to the runtime 16B record
is separately gated and out of scope.

Uses synthetic fixtures inline — no game data.
"""
from __future__ import annotations

import struct

import pytest

from ..c2_color_codec import (
    COLOR_PAYLOAD_SIZE,
    ColorPayload,
    ColorPayloadSizeError,
    parse_color_payload,
    serialize_color_payload,
)


class TestColorPayloadParseSerialize:
    """Round-trip parse → serialize must be byte-identical."""

    @pytest.mark.parametrize("raw", [
        b"\x00\x00\x00\x00\x00\x00\x00\x00",
        b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
        b"\x01\x02\x03\x04\x05\x06\x07\x08",
        b"\xCD\xCC\x4C\x3F\xCD\xCC\x4C\x3F",
        b"\x00\x40\x00\x00\x00\x00\x00\x00",
        b"\xAB\xCD\xEF\x01\x23\x45\x67\x89",
    ])
    def test_roundtrip(self, raw: bytes) -> None:
        payload = parse_color_payload(raw)
        assert serialize_color_payload(payload) == raw

    def test_parse_fields(self) -> None:
        raw = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        payload = parse_color_payload(raw)
        assert payload.w0 == 0x0201
        assert payload.w1 == 0x0403
        assert payload.w2 == 0x0605
        assert payload.w3 == 0x0807

    def test_serialize_from_fields(self) -> None:
        payload = ColorPayload(w0=0x0201, w1=0x0403, w2=0x0605, w3=0x0807)
        assert serialize_color_payload(payload) == b"\x01\x02\x03\x04\x05\x06\x07\x08"


class TestColorPayloadSize:
    def test_wrong_size_raises(self) -> None:
        with pytest.raises(ColorPayloadSizeError):
            parse_color_payload(b"\x00" * 7)
        with pytest.raises(ColorPayloadSizeError):
            parse_color_payload(b"\x00" * 9)

    def test_payload_size_constant(self) -> None:
        assert COLOR_PAYLOAD_SIZE == 8


class TestColorPayloadImmutable:
    def test_frozen(self) -> None:
        payload = parse_color_payload(b"\x00" * 8)
        with pytest.raises(Exception):
            payload.w0 = 1  # type: ignore[misc]
