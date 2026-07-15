from __future__ import annotations

import hashlib
import struct

import pytest

from ppp_disassembler.useful_ppp_candidates import (
    NonBehavioralColorFamilyError,
    UsefulPppFamilySpec,
    select_useful_ppp_candidates,
)


def _fixture_data(*, callback_relative: int = 0x120) -> bytes:
    data = bytearray(0x240)
    _ = struct.pack_into("<H", data, 6, 1)
    for offset, relative in ((16, 0x20), (20, 0x24), (24, 0x28), (28, 0x2C)):
        _ = struct.pack_into("<I", data, offset, relative)
    _ = struct.pack_into("<I", data, 0x20, 0x40)

    section = 0x40
    _ = struct.pack_into("<I", data, section, 0x1C0)
    _ = struct.pack_into("<I", data, section + 8, 0x100)
    _ = struct.pack_into("<I", data, section + 12, 0x108)
    program = section + 16
    _ = struct.pack_into("<h", data, program + 38, 1)
    slot = program + 40
    _ = struct.pack_into("<IHHII", data, slot, 6, 0x10, 0, callback_relative, 0x140)

    record = bytes.fromhex(
        "112233445566778800000000000000000000803f000000400000404000008040"
    )
    record_offset = section + 0x120
    data[record_offset:record_offset + len(record)] = record
    return bytes(data)


def _scl_move_spec() -> UsefulPppFamilySpec:
    return UsefulPppFamilySpec(
        opcode_name="pppSclMove",
        handler_index=6,
        raw_payload_width=24,
        runtime_operand_offset=8,
        runtime_operand_width=16,
    )


def test_select_accepts_non_header_sclmove_callback() -> None:
    data = _fixture_data()

    report = select_useful_ppp_candidates(data, _scl_move_spec())

    assert not report.rejections
    assert len(report.candidates) == 1
    candidate = report.candidates[0]
    assert candidate.callback_record_offset == 0x160
    assert candidate.raw_payload_offset == 0x168
    assert candidate.runtime_operand_offset == 0x170
    assert candidate.runtime_operand_width == 16
    assert candidate.record_sha256 == hashlib.sha256(data[0x160:0x180]).hexdigest()


def test_select_rejects_callback_overlapping_program_structure() -> None:
    data = _fixture_data(callback_relative=0x20)

    report = select_useful_ppp_candidates(data, _scl_move_spec())

    assert not report.candidates
    assert len(report.rejections) == 1
    assert report.rejections[0].reason == "structural_overlap"


def test_select_rejects_pppcolor_by_project_policy() -> None:
    with pytest.raises(NonBehavioralColorFamilyError):
        _ = UsefulPppFamilySpec(
            opcode_name="pppColor",
            handler_index=11,
            raw_payload_width=8,
            runtime_operand_offset=0,
            runtime_operand_width=8,
        )


def test_spec_rejects_runtime_window_outside_raw_payload() -> None:
    with pytest.raises(ValueError, match="runtime operand window"):
        _ = UsefulPppFamilySpec(
            opcode_name="pppSclMove",
            handler_index=6,
            raw_payload_width=24,
            runtime_operand_offset=16,
            runtime_operand_width=16,
        )
