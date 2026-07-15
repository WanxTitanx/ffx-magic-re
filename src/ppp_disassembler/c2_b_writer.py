from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import c2_effect_overlay as overlay
from .c2_color_codec import COLOR_PAYLOAD_SIZE, ColorPayload, serialize_color_payload
from .layer_c_resource import find_ppp_resource_roots, iter_ppp_slots


PPP_COLOR_HANDLER_INDEX = 11
PPP_COLOR_RECORD_SIZE = 32
PPP_COLOR_PAYLOAD_OFFSET = 8


class ExpectedRecordHashMismatchError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CallbackRecord:
    data_offset: int
    handler_table_index: int
    primary_callback_relative: int
    record_sha256: str


@dataclass(frozen=True, slots=True)
class CallbackMutationResult:
    backup_path: Path | None
    changed_offsets: tuple[int, ...]
    record_sha256: str
    restored: bool


def _backup_path(target_path: Path) -> Path:
    return target_path.with_suffix(".dll.c2b.bak")


def _write_atomically(path: Path, data: bytes) -> None:
    with tempfile.NamedTemporaryFile(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as temporary:
        temporary.write(data)
        temporary_path = Path(temporary.name)
    try:
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _ensure_backup(target_path: Path, original_dll: bytes) -> Path:
    backup_path = _backup_path(target_path)
    if backup_path.exists():
        if backup_path.read_bytes() != original_dll:
            raise ValueError(f"backup exists with different bytes: {backup_path}")
        return backup_path
    _write_atomically(backup_path, original_dll)
    return backup_path


def _data_section(dll_bytes: bytes) -> overlay.PeDataSection:
    section = overlay.parse_pe_data_section(dll_bytes)
    if section is None:
        raise ValueError("target DLL has no readable .data section")
    return section


def _record_slice(section: overlay.PeDataSection, data_offset: int) -> slice:
    end = data_offset + PPP_COLOR_RECORD_SIZE
    if data_offset < 0 or end > len(section.bytes):
        raise ValueError("pppColor callback record is outside .data")
    return slice(data_offset, end)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _owned_callback_record(section: overlay.PeDataSection, data_offset: int) -> tuple[int, int]:
    owners: list[tuple[int, int]] = []
    for root in find_ppp_resource_roots(section.bytes):
        for record in iter_ppp_slots(section.bytes, root):
            slot = record.slot
            source_offset = record.section_offset + slot.primary_callback_relative
            if source_offset == data_offset:
                owners.append((slot.handler_table_index, slot.primary_callback_relative))
    if len(owners) != 1:
        raise ValueError("pppColor callback record must have exactly one PPP slot owner")
    handler_index, callback_relative = owners[0]
    if handler_index != PPP_COLOR_HANDLER_INDEX:
        raise ValueError("callback record is not owned by pppColor handler index 11")
    return handler_index, callback_relative


def verify_callback_record(
    *,
    target_path: Path,
    data_offset: int,
    expected_record_sha256: str,
) -> CallbackRecord:
    dll_bytes = target_path.read_bytes()
    section = _data_section(dll_bytes)
    record_bytes = section.bytes[_record_slice(section, data_offset)]
    record_hash = _sha256(record_bytes)
    if record_hash != expected_record_sha256:
        raise ExpectedRecordHashMismatchError("pppColor callback record hash mismatch")
    handler_index, callback_relative = _owned_callback_record(section, data_offset)
    return CallbackRecord(
        data_offset=data_offset,
        handler_table_index=handler_index,
        primary_callback_relative=callback_relative,
        record_sha256=record_hash,
    )


def _patched_dll(
    *,
    dll_bytes: bytes,
    data_offset: int,
    expected_record_sha256: str,
    replacement: ColorPayload,
) -> tuple[bytes, CallbackRecord]:
    section = _data_section(dll_bytes)
    record_bytes = section.bytes[_record_slice(section, data_offset)]
    record_hash = _sha256(record_bytes)
    if record_hash != expected_record_sha256:
        raise ExpectedRecordHashMismatchError("pppColor callback record hash mismatch")
    handler_index, callback_relative = _owned_callback_record(section, data_offset)
    patched = bytearray(dll_bytes)
    payload_start = section.raw_ptr + data_offset + PPP_COLOR_PAYLOAD_OFFSET
    payload_end = payload_start + COLOR_PAYLOAD_SIZE
    patched[payload_start:payload_end] = serialize_color_payload(replacement)
    changed = tuple(
        offset for offset, (before, after) in enumerate(zip(dll_bytes, patched)) if before != after
    )
    expected_changed = set(range(payload_start, payload_end))
    if not set(changed).issubset(expected_changed):
        raise RuntimeError("pppColor patch changed bytes outside the payload")
    patched_section = _data_section(bytes(patched))
    patched_hash = _sha256(patched_section.bytes[_record_slice(patched_section, data_offset)])
    return bytes(patched), CallbackRecord(
        data_offset=data_offset,
        handler_table_index=handler_index,
        primary_callback_relative=callback_relative,
        record_sha256=patched_hash,
    )


def dry_run_callback_color(
    *,
    target_path: Path,
    data_offset: int,
    expected_record_sha256: str,
    replacement: ColorPayload,
) -> CallbackMutationResult:
    dll_bytes = target_path.read_bytes()
    patched, record = _patched_dll(
        dll_bytes=dll_bytes,
        data_offset=data_offset,
        expected_record_sha256=expected_record_sha256,
        replacement=replacement,
    )
    changed = tuple(offset for offset, (before, after) in enumerate(zip(dll_bytes, patched)) if before != after)
    return CallbackMutationResult(None, changed, record.record_sha256, False)


def apply_callback_color(
    *,
    target_path: Path,
    data_offset: int,
    expected_record_sha256: str,
    replacement: ColorPayload,
) -> CallbackMutationResult:
    dll_bytes = target_path.read_bytes()
    patched, record = _patched_dll(
        dll_bytes=dll_bytes,
        data_offset=data_offset,
        expected_record_sha256=expected_record_sha256,
        replacement=replacement,
    )
    backup_path = _ensure_backup(target_path, dll_bytes)
    changed = tuple(offset for offset, (before, after) in enumerate(zip(dll_bytes, patched)) if before != after)
    _write_atomically(target_path, patched)
    return CallbackMutationResult(backup_path, changed, record.record_sha256, False)


def restore_callback_color(
    *,
    target_path: Path,
    data_offset: int,
    expected_patched_record_sha256: str,
    expected_original_record_sha256: str,
) -> CallbackMutationResult:
    current_dll = target_path.read_bytes()
    section = _data_section(current_dll)
    current_record = section.bytes[_record_slice(section, data_offset)]
    if _sha256(current_record) != expected_patched_record_sha256:
        raise ExpectedRecordHashMismatchError("patched pppColor callback record hash mismatch")
    backup_path = _backup_path(target_path)
    if not backup_path.exists():
        raise FileNotFoundError(f"C2-B backup not found: {backup_path}")
    original_dll = backup_path.read_bytes()
    original_section = _data_section(original_dll)
    _owned_callback_record(original_section, data_offset)
    restored_record = original_section.bytes[_record_slice(original_section, data_offset)]
    if _sha256(restored_record) != expected_original_record_sha256:
        raise ExpectedRecordHashMismatchError("original pppColor callback record hash mismatch")
    payload_start = section.raw_ptr + data_offset + PPP_COLOR_PAYLOAD_OFFSET
    payload_end = payload_start + COLOR_PAYLOAD_SIZE
    restored = bytearray(current_dll)
    original_payload_start = original_section.raw_ptr + data_offset + PPP_COLOR_PAYLOAD_OFFSET
    restored[payload_start:payload_end] = original_dll[original_payload_start:original_payload_start + COLOR_PAYLOAD_SIZE]
    changed = tuple(offset for offset, (before, after) in enumerate(zip(current_dll, restored)) if before != after)
    if not set(changed).issubset(set(range(payload_start, payload_end))):
        raise RuntimeError("pppColor restore changed bytes outside the payload")
    _write_atomically(target_path, bytes(restored))
    return CallbackMutationResult(backup_path, changed, _sha256(restored_record), True)
