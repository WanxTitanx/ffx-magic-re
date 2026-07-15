"""TDD contract for the structurally-proven C2-B pppColor callback writer.

All fixtures are synthetic PE files. No game DLL is opened or modified.
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import pytest

from .. import c2_b_writer as writer
from .. import c2_b_cli as cli
from ..c2_color_codec import ColorPayload, serialize_color_payload


def _build_minimal_pe(data_section_bytes: bytes) -> bytes:
    raw_size = (len(data_section_bytes) + 511) // 512 * 512
    dos = bytearray(0x80)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0)
    optional = bytearray(0xE0)
    section_header = struct.pack(
        "<8sIIIIIIHHI",
        b".data\0\0\0",
        len(data_section_bytes),
        0x1000,
        raw_size,
        0x200,
        0,
        0,
        0,
        0,
        0,
    )
    output = bytearray(dos)
    output[0x80:0x80] = b"PE\0\0" + coff + bytes(optional) + section_header
    output.extend(b"\0" * (0x200 - len(output)))
    output.extend(data_section_bytes)
    output.extend(b"\0" * (raw_size - len(data_section_bytes)))
    return bytes(output)


def _fixture_dll(*, handler_index: int = 11, callback_relative: int = 0x120) -> tuple[bytes, bytes]:
    data = bytearray(0x240)
    struct.pack_into("<H", data, 6, 1)
    for offset, relative in ((16, 0x20), (20, 0x24), (24, 0x28), (28, 0x2C)):
        struct.pack_into("<I", data, offset, relative)
    struct.pack_into("<I", data, 0x20, 0x40)

    section = 0x40
    struct.pack_into("<I", data, section, 0x1C0)
    struct.pack_into("<I", data, section + 8, 0x100)
    struct.pack_into("<I", data, section + 12, 0x108)
    program = section + 16
    struct.pack_into("<h", data, program + 38, 1)
    slot = program + 40
    struct.pack_into("<IHHII", data, slot, handler_index, 0x10, 0, callback_relative, 0x140)

    record_offset = section + callback_relative
    record = bytes.fromhex("0000000000000000004000400030000000e00100000000000000000000000000")
    data[record_offset:record_offset + len(record)] = record
    return _build_minimal_pe(bytes(data)), record


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_verify_accepts_pppcolor_callback_record(tmp_path: Path) -> None:
    dll, record = _fixture_dll()
    target = tmp_path / "sample.dll"
    target.write_bytes(dll)

    verified = writer.verify_callback_record(
        target_path=target,
        data_offset=0x160,
        expected_record_sha256=_sha(record),
    )

    assert verified.handler_table_index == 11
    assert verified.primary_callback_relative == 0x120
    assert verified.data_offset == 0x160


def test_verify_rejects_callback_record_not_owned_by_pppcolor(tmp_path: Path) -> None:
    dll, record = _fixture_dll(handler_index=10)
    target = tmp_path / "sample.dll"
    target.write_bytes(dll)

    with pytest.raises(ValueError, match="pppColor"):
        writer.verify_callback_record(
            target_path=target,
            data_offset=0x160,
            expected_record_sha256=_sha(record),
        )


def test_apply_changes_only_the_eight_color_bytes_and_creates_backup(tmp_path: Path) -> None:
    dll, record = _fixture_dll()
    target = tmp_path / "sample.dll"
    target.write_bytes(dll)
    replacement = ColorPayload(1, 2, 3, 4)

    result = writer.apply_callback_color(
        target_path=target,
        data_offset=0x160,
        expected_record_sha256=_sha(record),
        replacement=replacement,
    )

    assert result.backup_path is not None
    assert result.backup_path.read_bytes() == dll
    assert set(result.changed_offsets).issubset(set(range(0x200 + 0x168, 0x200 + 0x170)))
    patched = target.read_bytes()
    assert patched[0x200 + 0x168:0x200 + 0x170] == serialize_color_payload(replacement)
    assert patched[:0x200 + 0x168] == dll[:0x200 + 0x168]
    assert patched[0x200 + 0x170:] == dll[0x200 + 0x170:]


def test_dry_run_never_writes_or_creates_backup(tmp_path: Path) -> None:
    dll, record = _fixture_dll()
    target = tmp_path / "sample.dll"
    target.write_bytes(dll)

    result = writer.dry_run_callback_color(
        target_path=target,
        data_offset=0x160,
        expected_record_sha256=_sha(record),
        replacement=ColorPayload(1, 2, 3, 4),
    )

    assert result.backup_path is None
    assert target.read_bytes() == dll
    assert set(result.changed_offsets).issubset(set(range(0x200 + 0x168, 0x200 + 0x170)))


def test_restore_requires_patched_record_hash_and_returns_original_bytes(tmp_path: Path) -> None:
    dll, record = _fixture_dll()
    target = tmp_path / "sample.dll"
    target.write_bytes(dll)
    applied = writer.apply_callback_color(
        target_path=target,
        data_offset=0x160,
        expected_record_sha256=_sha(record),
        replacement=ColorPayload(1, 2, 3, 4),
    )

    with pytest.raises(writer.ExpectedRecordHashMismatchError):
        writer.restore_callback_color(
            target_path=target,
            data_offset=0x160,
            expected_patched_record_sha256=_sha(b"wrong"),
            expected_original_record_sha256=_sha(record),
        )

    restored = writer.restore_callback_color(
        target_path=target,
        data_offset=0x160,
        expected_patched_record_sha256=applied.record_sha256,
        expected_original_record_sha256=_sha(record),
    )

    assert restored.restored is True
    assert target.read_bytes() == dll


def test_restore_rejects_backup_with_unexpected_original_record(tmp_path: Path) -> None:
    dll, record = _fixture_dll()
    target = tmp_path / "sample.dll"
    target.write_bytes(dll)
    applied = writer.apply_callback_color(
        target_path=target,
        data_offset=0x160,
        expected_record_sha256=_sha(record),
        replacement=ColorPayload(1, 2, 3, 4),
    )
    backup = target.with_suffix(".dll.c2b.bak")
    corrupted = bytearray(backup.read_bytes())
    corrupted[0x200 + 0x168] ^= 0xFF
    backup.write_bytes(corrupted)

    with pytest.raises(writer.ExpectedRecordHashMismatchError):
        writer.restore_callback_color(
            target_path=target,
            data_offset=0x160,
            expected_patched_record_sha256=applied.record_sha256,
            expected_original_record_sha256=_sha(record),
        )


def test_cli_dry_run_reports_confined_change_without_writing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dll, record = _fixture_dll()
    target = tmp_path / "sample.dll"
    target.write_bytes(dll)

    exit_code = cli.main(
        [
            "dry-run",
            str(target),
            "--data-offset",
            "0x160",
            "--expected-record-sha256",
            _sha(record),
            "--words",
            "1,2,3,4",
        ]
    )

    result = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert result["restored"] is False
    assert result["backup_path"] is None
    assert target.read_bytes() == dll


def test_cli_apply_then_restore_roundtrips(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    dll, record = _fixture_dll()
    target = tmp_path / "sample.dll"
    target.write_bytes(dll)
    apply_code = cli.main(
        [
            "apply", str(target), "--data-offset", "0x160",
            "--expected-record-sha256", _sha(record), "--words", "1,2,3,4",
        ]
    )
    apply_result = json.loads(capsys.readouterr().out)
    restore_code = cli.main(
        [
            "restore", str(target), "--data-offset", "0x160",
            "--expected-patched-record-sha256", apply_result["record_sha256"],
            "--expected-original-record-sha256", _sha(record),
        ]
    )
    restore_result = json.loads(capsys.readouterr().out)

    assert apply_code == 0
    assert restore_code == 0
    assert restore_result["restored"] is True
    assert target.read_bytes() == dll
