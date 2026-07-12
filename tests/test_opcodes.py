"""Tests for the ppp_disassembler opcodes module — sanitized opcode table."""

import pytest
from ppp_disassembler.opcodes import (
    OPCODES,
    ALPHA_FUNCTIONS,
    OpcodeEntry,
    AlphaEntry,
    lookup_opcode,
    is_known_opcode,
    is_alpha_selector,
)


class TestOpcodeEntry:
    def test_frozen_dataclass(self) -> None:
        entry = OpcodeEntry(
            index=0, opcode_byte=0x00, name="pppKeThRes32x4",
            category="thread_resolution", n_operands=0,
            total_size=1, median_size=1, size_range="1-1",
        )
        assert entry.index == 0
        assert entry.opcode_byte == 0x00
        assert entry.name == "pppKeThRes32x4"

    def test_hex_byte_property(self) -> None:
        entry = OpcodeEntry(
            index=5, opcode_byte=0x05, name="pppAngAccele",
            category="angular_accel", n_operands=1,
            total_size=2, median_size=2, size_range="1-234",
        )
        assert entry.hex_byte == "0x05"

    def test_operand_types_default_empty(self) -> None:
        entry = OpcodeEntry(
            index=0, opcode_byte=0x00, name="test",
            category="test", n_operands=0,
            total_size=1, median_size=1, size_range="1-1",
        )
        assert entry.operand_types == ()


class TestAlphaEntry:
    def test_frozen_dataclass(self) -> None:
        ae = AlphaEntry(opcode_byte=0x41, alpha_mult=256, description="alpha=1.0 (full)")
        assert ae.opcode_byte == 0x41
        assert ae.alpha_mult == 256
        assert ae.hex_byte == "0x41"


class TestOPCODES:
    def test_contains_all_known_opcodes(self) -> None:
        """All 36 opcodes from 0x00 to 0x23 should be present."""
        for byte in range(0x00, 0x24):
            assert byte in OPCODES, f"Missing opcode byte 0x{byte:02x}"
        assert len(OPCODES) == 36

    def test_opcode_metadata(self) -> None:
        """Spot-check known entries."""
        entry = OPCODES[0x00]
        assert entry.name == "pppKeThRes32x4"
        assert entry.category == "thread_resolution"
        assert entry.n_operands == 0

        entry = OPCODES[0x0D]
        assert entry.name == "pppPoint"
        assert entry.category == "point"

        entry = OPCODES[0x10]
        assert entry.name == "pppColor"
        assert entry.category == "color"

        entry = OPCODES[0x1E]
        assert entry.name == "pppDrawShape"
        assert entry.category == "draw_shape"

    def test_no_rva_or_host_context_fields(self) -> None:
        """Sanitized: no handler_RVA, host_context, or DLL-specific fields."""
        entry = OPCODES[0x00]
        for attr in ("handler_rva_m86", "handler_rva_m87", "host_context_offset"):
            assert not hasattr(entry, attr), f"Field {attr} must not exist"


class TestALPHA_FUNCTIONS:
    def test_known_selectors(self) -> None:
        assert 0x41 in ALPHA_FUNCTIONS
        assert 0x42 in ALPHA_FUNCTIONS
        assert 0x44 in ALPHA_FUNCTIONS
        assert 0x46 in ALPHA_FUNCTIONS
        assert 0x48 in ALPHA_FUNCTIONS
        assert 0x88 in ALPHA_FUNCTIONS

    def test_alpha_mult_values(self) -> None:
        assert ALPHA_FUNCTIONS[0x41].alpha_mult == 256  # full
        assert ALPHA_FUNCTIONS[0x42].alpha_mult == 16
        assert ALPHA_FUNCTIONS[0x46].alpha_mult == 32
        assert ALPHA_FUNCTIONS[0x48].alpha_mult == 2
        assert ALPHA_FUNCTIONS[0x88].alpha_mult == 512
        assert ALPHA_FUNCTIONS[0x44].alpha_mult == 0  # invalid


class TestLookupOpcode:
    def test_known_opcode_returns_entry(self) -> None:
        entry = lookup_opcode(0x00)
        assert isinstance(entry, OpcodeEntry)
        assert entry.name == "pppKeThRes32x4"

    def test_alpha_selector_raises(self) -> None:
        with pytest.raises(KeyError, match="alpha function"):
            lookup_opcode(0x41)

    def test_unknown_opcode_raises(self) -> None:
        with pytest.raises(KeyError, match="Unknown"):
            lookup_opcode(0xFF)

    def test_last_opcode(self) -> None:
        entry = lookup_opcode(0x23)
        assert entry.name == "pppKeBornRnd3"


class TestIsKnownOpcode:
    def test_returns_true_for_known(self) -> None:
        assert is_known_opcode(0x00)
        assert is_known_opcode(0x23)

    def test_returns_false_for_unknown(self) -> None:
        assert not is_known_opcode(0x41)
        assert not is_known_opcode(0xFF)


class TestIsAlphaSelector:
    def test_returns_true_for_alpha_bytes(self) -> None:
        assert is_alpha_selector(0x41)
        assert is_alpha_selector(0x88)

    def test_returns_false_for_opcode_bytes(self) -> None:
        assert not is_alpha_selector(0x00)
        assert not is_alpha_selector(0xFF)
