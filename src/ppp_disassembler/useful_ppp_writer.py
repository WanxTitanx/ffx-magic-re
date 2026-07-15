from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import c2_effect_overlay as overlay
from .useful_ppp_candidates import UsefulPppCandidate


_SUPPORTED_VECTOR_FAMILIES = frozenset({"pppSclMove", "pppSclAccele", "pppAngMove"})


class ExpectedSclMoveRecordHashMismatchError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SclMoveMutationResult:
    backup_path: Path | None
    changed_offsets: tuple[int, ...]
    record_sha256: str
    callback_record_offset: int
    restored: bool


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _backup_path(target_path: Path) -> Path:
    return target_path.with_suffix(".dll.sclmove.bak")


def _write_atomically(path: Path, data: bytes) -> None:
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False) as temporary:
        _ = temporary.write(data)
        temporary_path = Path(temporary.name)
    try:
        _ = os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _window(candidate: UsefulPppCandidate) -> tuple[int, int]:
    if candidate.opcode_name not in _SUPPORTED_VECTOR_FAMILIES:
        raise ValueError("unsupported useful PPP vector family")
    start = candidate.runtime_operand_offset
    end = start + candidate.runtime_operand_width
    if candidate.runtime_operand_width != 16:
        raise ValueError("pppSclMove runtime window must be 16 bytes")
    return start, end


def _validate_target(target_path: Path, candidate: UsefulPppCandidate, expected_record_sha256: str) -> tuple[bytes, int, int, int]:
    dll = target_path.read_bytes()
    section = overlay.parse_pe_data_section(dll)
    if section is None:
        raise ValueError("target DLL has no readable .data section")
    record_start = candidate.callback_record_offset
    record_end = record_start + 32
    current_record = section.bytes[record_start:record_end]
    if _sha256(current_record) != expected_record_sha256:
        raise ExpectedSclMoveRecordHashMismatchError("pppSclMove callback record hash mismatch")
    window_start, window_end = _window(candidate)
    if window_start < record_start or window_end > record_end:
        raise ValueError("pppSclMove runtime window is outside callback record")
    return dll, section.raw_ptr, record_start, record_end


def _patched_bytes(target_path: Path, candidate: UsefulPppCandidate, expected_record_sha256: str, replacement: bytes) -> tuple[bytes, tuple[int, ...], str]:
    if len(replacement) != 16:
        raise ValueError("pppSclMove replacement must be exactly 16 bytes")
    dll, raw_ptr, record_start, record_end = _validate_target(target_path, candidate, expected_record_sha256)
    window_start, window_end = _window(candidate)
    file_start = raw_ptr + window_start
    file_end = raw_ptr + window_end
    patched = bytearray(dll)
    patched[file_start:file_end] = replacement
    changed = tuple(index for index, (before, after) in enumerate(zip(dll, patched)) if before != after)
    if not set(changed).issubset(set(range(file_start, file_end))):
        raise RuntimeError("pppSclMove patch changed bytes outside runtime window")
    patched_section = overlay.parse_pe_data_section(bytes(patched))
    if patched_section is None:
        raise RuntimeError("patched DLL lost its .data section")
    return bytes(patched), tuple(index - raw_ptr for index in changed), _sha256(patched_section.bytes[record_start:record_end])


def dry_run_vector(target_path: Path, candidate: UsefulPppCandidate, expected_record_sha256: str, replacement: bytes) -> SclMoveMutationResult:
    _, changed, patched_hash = _patched_bytes(target_path, candidate, expected_record_sha256, replacement)
    return SclMoveMutationResult(None, changed, patched_hash, candidate.callback_record_offset, False)


def apply_vector(target_path: Path, candidate: UsefulPppCandidate, expected_record_sha256: str, replacement: bytes) -> SclMoveMutationResult:
    original = target_path.read_bytes()
    patched, changed, patched_hash = _patched_bytes(target_path, candidate, expected_record_sha256, replacement)
    backup = _backup_path(target_path)
    if backup.exists() and backup.read_bytes() != original:
        raise ValueError("pppSclMove backup exists with different bytes")
    if not backup.exists():
        _write_atomically(backup, original)
    _write_atomically(target_path, patched)
    return SclMoveMutationResult(backup, changed, patched_hash, candidate.callback_record_offset, False)


def restore_vector(target_path: Path, result: SclMoveMutationResult, expected_original_record_sha256: str) -> SclMoveMutationResult:
    if result.backup_path is None or not result.backup_path.exists():
        raise ValueError("pppSclMove backup is missing")
    current = target_path.read_bytes()
    backup = result.backup_path.read_bytes()
    section = overlay.parse_pe_data_section(current)
    original_section = overlay.parse_pe_data_section(backup)
    if section is None or original_section is None:
        raise ValueError("backup or target has no readable .data section")
    record_start = result.callback_record_offset
    current_record = section.bytes[record_start:record_start + 32]
    if _sha256(current_record) != result.record_sha256:
        raise ExpectedSclMoveRecordHashMismatchError("patched pppSclMove callback record hash mismatch")
    if _sha256(original_section.bytes[record_start:record_start + 32]) != expected_original_record_sha256:
        raise ExpectedSclMoveRecordHashMismatchError("pppSclMove backup record hash mismatch")
    _write_atomically(target_path, backup)
    return SclMoveMutationResult(result.backup_path, result.changed_offsets, expected_original_record_sha256, record_start, True)


dry_run_scl_move = dry_run_vector
apply_scl_move = apply_vector
restore_scl_move = restore_vector
