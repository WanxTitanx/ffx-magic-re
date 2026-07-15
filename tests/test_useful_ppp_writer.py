from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import pytest

from ppp_disassembler.useful_ppp_candidates import UsefulPppFamilySpec, select_useful_ppp_candidates
from ppp_disassembler.useful_ppp_writer import (
    apply_vector,
    apply_scl_move,
    dry_run_vector,
    dry_run_scl_move,
    restore_vector,
    restore_scl_move,
)


def _build_pe(data: bytes) -> bytes:
    raw_size = (len(data) + 511) // 512 * 512
    dos = bytearray(0x80)
    dos[:2] = b"MZ"
    _ = struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0)
    optional = bytearray(0xE0)
    header = struct.pack("<8sIIIIIIHHI", b".data\0\0\0", len(data), 0x1000, raw_size, 0x200, 0, 0, 0, 0, 0)
    result = bytearray(dos)
    result.extend(b"PE\0\0" + coff + optional + header)
    result.extend(b"\0" * (0x200 - len(result)))
    result.extend(data)
    result.extend(b"\0" * (raw_size - len(data)))
    return bytes(result)


def _fixture() -> tuple[bytes, bytes]:
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
    _ = struct.pack_into("<IHHII", data, program + 40, 6, 0x10, 0, 0x120, 0x140)
    record = bytes.fromhex("112233445566778800000000000000000000803f000000400000404000008040")
    data[section + 0x120:section + 0x120 + len(record)] = record
    return _build_pe(bytes(data)), record


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _spec() -> UsefulPppFamilySpec:
    return UsefulPppFamilySpec("pppSclMove", 6, 24, 8, 16)


def test_dry_run_scl_move_confines_diff_to_runtime_window(tmp_path: Path) -> None:
    dll, record = _fixture()
    target = tmp_path / "magic_0069.dll"
    _ = target.write_bytes(dll)
    report = select_useful_ppp_candidates(dll[0x200:], _spec())
    candidate = report.candidates[0]

    result = dry_run_scl_move(target, candidate, _sha(record), bytes.fromhex("0000803f0000a0400000c0400000e040"))

    assert set(result.changed_offsets).issubset(set(range(0x170, 0x180)))
    assert result.changed_offsets
    assert result.record_sha256 != _sha(record)
    assert result.backup_path is None
    assert target.read_bytes() == dll


def test_apply_and_restore_scl_move_are_byte_idempotent(tmp_path: Path) -> None:
    dll, record = _fixture()
    target = tmp_path / "magic_0069.dll"
    _ = target.write_bytes(dll)
    candidate = select_useful_ppp_candidates(dll[0x200:], _spec()).candidates[0]
    replacement = bytes.fromhex("0000803f0000a0400000c0400000e040")

    result = apply_scl_move(target, candidate, _sha(record), replacement)
    _ = restore_scl_move(target, result, _sha(record))

    assert target.read_bytes() == dll


def test_writer_rejects_payload_with_wrong_width(tmp_path: Path) -> None:
    dll, record = _fixture()
    target = tmp_path / "magic_0069.dll"
    _ = target.write_bytes(dll)
    candidate = select_useful_ppp_candidates(dll[0x200:], _spec()).candidates[0]

    with pytest.raises(ValueError, match="16 bytes"):
        _ = dry_run_scl_move(target, candidate, _sha(record), b"\0" * 12)


def test_restore_rejects_changed_patched_record(tmp_path: Path) -> None:
    dll, record = _fixture()
    target = tmp_path / "magic_0069.dll"
    _ = target.write_bytes(dll)
    candidate = select_useful_ppp_candidates(dll[0x200:], _spec()).candidates[0]
    result = apply_scl_move(target, candidate, _sha(record), bytes.fromhex("0000803f0000a0400000c0400000e040"))
    mutated = bytearray(target.read_bytes())
    mutated[0x200 + candidate.runtime_operand_offset] ^= 0x01
    _ = target.write_bytes(mutated)

    with pytest.raises(ValueError, match="patched pppSclMove"):
        _ = restore_scl_move(target, result, _sha(record))


@pytest.mark.parametrize(("opcode_name", "handler_index"), (("pppSclAccele", 2), ("pppAngMove", 6)))
def test_vector_writer_supports_next_u1_families(tmp_path: Path, opcode_name: str, handler_index: int) -> None:
    dll, _ = _fixture()
    target = tmp_path / "magic_0073.dll"
    _ = target.write_bytes(dll)
    mutable_data = bytearray(dll[0x200:])
    _ = struct.pack_into("<I", mutable_data, 0x40 + 16 + 40, handler_index)
    data = bytes(mutable_data)
    dll = _build_pe(data)
    _ = target.write_bytes(dll)
    spec = UsefulPppFamilySpec(opcode_name, handler_index, 24, 8, 16)
    candidate = select_useful_ppp_candidates(data, spec).candidates[0]
    current_record = data[candidate.callback_record_offset:candidate.callback_record_offset + 32]
    replacement = bytes.fromhex("0000803f0000a0400000c0400000e040")

    dry = dry_run_vector(target, candidate, _sha(current_record), replacement)
    applied = apply_vector(target, candidate, _sha(current_record), replacement)
    _ = restore_vector(target, applied, _sha(current_record))

    assert dry.record_sha256 != _sha(current_record)
    assert target.read_bytes() == dll
