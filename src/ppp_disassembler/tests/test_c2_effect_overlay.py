"""TDD tests for the C2 same-size overlay codec.

Uses synthetic data — no game data.
"""
from __future__ import annotations

import hashlib

import pytest

from ..c2_effect_overlay import (
    PeDataSection,
    apply_overlay,
    compute_sha256,
    verify_overlay,
)
from ..c2_effect_overlay import OverlayMapping


def _make_section(data: bytes) -> PeDataSection:
    return PeDataSection(raw_ptr=0, raw_size=len(data), virtual_size=len(data), bytes=data)


class TestOverlayRoundTrip:
    def test_apply_then_verify(self) -> None:
        original_data = b"\x00" * 256
        section = PeDataSection(raw_ptr=0, raw_size=len(original_data), virtual_size=len(original_data), bytes=original_data)
        payload = b"\xDE\xAD\xBE\xEF" * 4
        data_offset = 64
        current_range = original_data[data_offset:data_offset+len(payload)]
        orig_sha = compute_sha256(current_range)
        dll_bytes = b"\x00" * 512
        # The DLL's .data section IS the original data
        dll_with_data = bytearray(dll_bytes)
        dll_with_data[:len(original_data)] = original_data
        dll_bytes = bytes(dll_with_data)
        mapping = OverlayMapping(
            effect_id=0,
            source_sha256=orig_sha,
            data_offset=data_offset,
            size_bytes=len(payload),
            dll_sha256=hashlib.sha256(dll_bytes).hexdigest(),
            data_section_size=len(original_data),
        )
        patched = apply_overlay(
            dll_bytes=dll_bytes,
            data_section=section,
            mapping=mapping,
            replacement=payload,
            expected_current_sha256=orig_sha,
        )
        patched_sha = compute_sha256(payload)
        assert verify_overlay(patched, section, mapping, patched_sha)

    def test_identity_patch(self) -> None:
        original_data = b"\x01" * 64
        section = _make_section(original_data)
        payload = b"\x01" * 64
        data_offset = 0
        orig_sha = compute_sha256(original_data)
        dll_bytes = bytearray(b"\x00" * 512)
        dll_bytes[:len(original_data)] = original_data
        dll_bytes = bytes(dll_bytes)
        mapping = OverlayMapping(
            effect_id=0,
            source_sha256=orig_sha,
            data_offset=data_offset,
            size_bytes=len(payload),
            dll_sha256=hashlib.sha256(dll_bytes).hexdigest(),
            data_section_size=len(original_data),
        )
        patched = apply_overlay(
            dll_bytes=dll_bytes,
            data_section=section,
            mapping=mapping,
            replacement=payload,
            expected_current_sha256=orig_sha,
        )
        patched_sha = compute_sha256(payload)
        assert verify_overlay(patched, section, mapping, patched_sha)
