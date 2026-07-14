"""C2 full-effect overlay codec — strictly bounded same-size overlay.

Scope (locked by ``SCOPE``):

* Recognise a candidate ONLY where the complete ``eff`` byte sequence is
  exactly contained in a PE ``.data`` section, at a single unique offset.
* Produce a typed ``OverlayMapping`` (effect ID, data offset, source
  hash, size, host DLL hash, section size).
* Apply a same-length replacement only after verifying the current target
  range hashes to the expected source hash (the original eff bytes).
* Reject grow / shrink, missing ``.data`` section, mismatched expected
  original, repeated occurrences, and arbitrary partial-prefix patches.

BLOCKED (declared in ``BLOCKED_CAPABILITIES``):

* C2 operand semantic compiler
* C3 resize / new effect generation
* arbitrary magic generation

This module never mutates DLLs on disk; every mutator returns new bytes.
"""

from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

# ---------------------------------------------------------------------------
# Scope banner (asserted by tests; do not weaken)
# ---------------------------------------------------------------------------

SCOPE: Final[str] = "full_resource_overlay_only"

BLOCKED_CAPABILITIES: Final[tuple[str, ...]] = (
    "C2_OPERAND_SEMANTIC_CODEC",
    "C3_RESIZE_OR_NEW_GENERATION",
    "ARBITRARY_MAGIC_GENERATION",
)

_CHUNK_BYTES = 64 * 1024


# ---------------------------------------------------------------------------
# Typed errors
# ---------------------------------------------------------------------------


class OverlayError(Exception):
    """Base for all overlay codec failures."""


class OverlaySizeMismatchError(OverlayError):
    """Replacement length != mapping size (grow/shrink attempted)."""


class OverlayHashMismatchError(OverlayError):
    """Current target range hash != expected hash (target was mutated)."""


class OverlayPayloadMismatchError(OverlayError):
    """Supplied canonical payload hash != mapping source hash."""


class OverlaySectionMissingError(OverlayError):
    """PE has no ``.data`` section to operate on."""


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PeDataSection:
    """One ``.data`` section parsed out of a PE binary.

    ``raw_ptr`` is the file offset where the section's raw bytes begin;
    ``bytes`` is the section payload (length == ``raw_size`` from the
    section header, truncated to the file end if the header overstates).
    """

    raw_ptr: int
    raw_size: int
    virtual_size: int
    bytes: bytes


@dataclass(frozen=True, slots=True)
class OverlayMapping:
    """Typed mapping of one effect resource into one host DLL ``.data``.

    All fields are immutable and hashable. ``source_sha256`` is the hash
    of the canonical ``eff`` bytes; ``data_offset`` is the offset within
    the ``.data`` section where the whole resource sits.
    """

    effect_id: str
    source_sha256: str
    data_offset: int
    size_bytes: int
    dll_sha256: str
    data_section_size: int


_RejectReason = Literal[
    "zero_width_source",
    "source_larger_than_section",
    "not_embedded",
    "multiple_occurrences",
]


@dataclass(frozen=True, slots=True)
class OverlayProbeResult:
    """Outcome of a whole-blob embed probe.

    ``mapping`` is non-None iff exactly one unique offset holds the full
    eff bytes. ``occurrence_offsets`` always reports every exact
    whole-blob offset found (empty on rejection by absence or size).
    ``rejected_reason`` is None on success, otherwise one of the
    ``_RejectReason`` literals explaining why no mapping was produced.
    """

    mapping: OverlayMapping | None
    occurrence_offsets: tuple[int, ...]
    rejected_reason: str | None


# ---------------------------------------------------------------------------
# PE parsing
# ---------------------------------------------------------------------------


def parse_pe_data_section(dll_bytes: bytes) -> PeDataSection | None:
    """Extract the ``.data`` section from a PE DLL.

    Returns ``None`` when the PE signature is missing, the section table
    is out of bounds, or no ``.data`` section exists. When the section
    header's raw size would extend past EOF, the returned bytes are
    truncated to what is actually present.
    """
    if len(dll_bytes) < 0x3C + 4:
        return None
    pe_offset = struct.unpack_from("<I", dll_bytes, 0x3C)[0]
    if pe_offset + 6 > len(dll_bytes):
        return None
    if dll_bytes[pe_offset:pe_offset + 2] != b"PE":
        return None
    num_sections = struct.unpack_from("<H", dll_bytes, pe_offset + 6)[0]
    opt_hdr_size = struct.unpack_from("<H", dll_bytes, pe_offset + 20)[0]
    section_table_start = pe_offset + 24 + opt_hdr_size
    for i in range(num_sections):
        off = section_table_start + i * 40
        if off + 40 > len(dll_bytes):
            return None
        name_raw = dll_bytes[off:off + 8]
        name = name_raw.rstrip(b"\x00").decode("ascii", errors="replace")
        if name != ".data":
            continue
        virtual_size = struct.unpack_from("<I", dll_bytes, off + 8)[0]
        raw_size = struct.unpack_from("<I", dll_bytes, off + 16)[0]
        raw_ptr = struct.unpack_from("<I", dll_bytes, off + 20)[0]
        end = raw_ptr + raw_size
        if end > len(dll_bytes):
            return PeDataSection(
                raw_ptr=raw_ptr,
                raw_size=len(dll_bytes) - raw_ptr,
                virtual_size=virtual_size,
                bytes=dll_bytes[raw_ptr:],
            )
        return PeDataSection(
            raw_ptr=raw_ptr,
            raw_size=raw_size,
            virtual_size=virtual_size,
            bytes=dll_bytes[raw_ptr:end],
        )
    return None


# ---------------------------------------------------------------------------
# Effect-ID parsing
# ---------------------------------------------------------------------------


_EFF_ID_RE = re.compile(r"(?:eff_|magic_)(\d{4})")


def parse_effect_id(path: Path) -> str:
    """Extract the 4-digit effect ID from an ``eff_NNNN.bin`` or
    ``magic_NNNN.dll`` filename. Returns ``""`` when no ID is present."""
    m = _EFF_ID_RE.search(path.name)
    if m is None:
        return ""
    return m.group(1)


def compute_sha256(data: bytes) -> str:
    """SHA-256 over an in-memory byte string."""
    return hashlib.sha256(data).hexdigest()


def compute_sha256_file(path: Path) -> str:
    """Streaming SHA-256 over the exact bytes of *path*."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------


def _find_whole_blob_offsets(needle: bytes, haystack: bytes) -> tuple[int, ...]:
    """Every offset where the full *needle* appears in *haystack*."""
    if not needle or len(needle) > len(haystack):
        return ()
    offsets: list[int] = []
    start = 0
    while True:
        idx = haystack.find(needle, start)
        if idx < 0:
            break
        offsets.append(idx)
        start = idx + 1
    return tuple(offsets)


def probe_overlay(
    *,
    eff_bytes: bytes,
    data_section: PeDataSection,
    effect_id: str,
    source_sha256: str,
    dll_sha256: str,
) -> OverlayProbeResult:
    """Probe *data_section* for the complete *eff_bytes*.

    A mapping is produced only when the full eff byte sequence is
    exactly contained at a single unique offset. Zero-width sources,
    sources larger than the section, absent sources, and repeated
    occurrences are all rejected with an explicit ``rejected_reason``.
    """
    if len(eff_bytes) == 0:
        return OverlayProbeResult(
            mapping=None,
            occurrence_offsets=(),
            rejected_reason="zero_width_source",
        )
    if len(eff_bytes) > len(data_section.bytes):
        return OverlayProbeResult(
            mapping=None,
            occurrence_offsets=(),
            rejected_reason="source_larger_than_section",
        )

    offsets = _find_whole_blob_offsets(eff_bytes, data_section.bytes)
    if len(offsets) == 0:
        return OverlayProbeResult(
            mapping=None,
            occurrence_offsets=(),
            rejected_reason="not_embedded",
        )
    if len(offsets) > 1:
        return OverlayProbeResult(
            mapping=None,
            occurrence_offsets=offsets,
            rejected_reason="multiple_occurrences",
        )

    off = offsets[0]
    mapping = OverlayMapping(
        effect_id=effect_id,
        source_sha256=source_sha256,
        data_offset=off,
        size_bytes=len(eff_bytes),
        dll_sha256=dll_sha256,
        data_section_size=data_section.raw_size,
    )
    return OverlayProbeResult(
        mapping=mapping,
        occurrence_offsets=(off,),
        rejected_reason=None,
    )


# ---------------------------------------------------------------------------
# Apply / restore / verify
# ---------------------------------------------------------------------------


def _check_size(replacement: bytes, mapping: OverlayMapping) -> None:
    if len(replacement) != mapping.size_bytes:
        raise OverlaySizeMismatchError(
            f"replacement length {len(replacement)} != mapping size "
            f"{mapping.size_bytes} (effect {mapping.effect_id}); grow/shrink "
            f"is outside the C2 overlay codec scope"
        )


def _check_current_hash(
    dll_bytes: bytes,
    data_section: PeDataSection,
    mapping: OverlayMapping,
    expected_current_sha256: str,
) -> None:
    start = data_section.raw_ptr + mapping.data_offset
    end = start + mapping.size_bytes
    current = dll_bytes[start:end]
    if compute_sha256(current) != expected_current_sha256:
        raise OverlayHashMismatchError(
            f"current target range hash != expected for effect "
            f"{mapping.effect_id}; target was mutated or mapping is stale"
        )


def _replace_range(
    dll_bytes: bytes,
    data_section: PeDataSection,
    mapping: OverlayMapping,
    new_bytes: bytes,
) -> bytes:
    start = data_section.raw_ptr + mapping.data_offset
    end = start + mapping.size_bytes
    out = bytearray(dll_bytes)
    out[start:end] = new_bytes
    return bytes(out)


def apply_overlay(
    *,
    dll_bytes: bytes,
    data_section: PeDataSection,
    mapping: OverlayMapping,
    replacement: bytes,
    expected_current_sha256: str,
) -> bytes:
    """Apply a same-length replacement at the mapped offset.

    Raises ``OverlaySizeMismatchError`` if *replacement* length differs
    from the mapping size (no grow/shrink), and
    ``OverlayHashMismatchError`` if the current target range does not
    hash to *expected_current_sha256* (the target was mutated or the
    mapping is stale).
    """
    _check_size(replacement, mapping)
    _check_current_hash(dll_bytes, data_section, mapping, expected_current_sha256)
    return _replace_range(dll_bytes, data_section, mapping, replacement)


def restore_overlay(
    *,
    dll_bytes: bytes,
    data_section: PeDataSection,
    mapping: OverlayMapping,
    original_eff_bytes: bytes,
    expected_current_sha256: str,
) -> bytes:
    """Restore the canonical original at the mapped offset.

    *original_eff_bytes* must hash to ``mapping.source_sha256`` (the
    canonical original), otherwise ``OverlayPayloadMismatchError`` is
    raised — the codec refuses to write an unverified "original".
    """
    if compute_sha256(original_eff_bytes) != mapping.source_sha256:
        raise OverlayPayloadMismatchError(
            f"supplied original does not hash to mapping source_sha256 "
            f"for effect {mapping.effect_id}; refusing to write unverified "
            f"original"
        )
    _check_size(original_eff_bytes, mapping)
    _check_current_hash(dll_bytes, data_section, mapping, expected_current_sha256)
    return _replace_range(dll_bytes, data_section, mapping, original_eff_bytes)


def verify_overlay(
    dll_bytes: bytes,
    data_section: PeDataSection,
    mapping: OverlayMapping,
    expected_sha256: str,
) -> bool:
    """Return ``True`` iff the current mapped range hashes to
    *expected_sha256*."""
    start = data_section.raw_ptr + mapping.data_offset
    end = start + mapping.size_bytes
    current = dll_bytes[start:end]
    return compute_sha256(current) == expected_sha256


# ---------------------------------------------------------------------------
# Serialization (JSON-compatible)
# ---------------------------------------------------------------------------


def serialize_mapping(mapping: OverlayMapping) -> dict[str, object]:
    return {
        "effect_id": mapping.effect_id,
        "source_sha256": mapping.source_sha256,
        "data_offset": mapping.data_offset,
        "data_offset_hex": hex(mapping.data_offset),
        "size_bytes": mapping.size_bytes,
        "dll_sha256": mapping.dll_sha256,
        "data_section_size": mapping.data_section_size,
    }


def serialize_probe_result(result: OverlayProbeResult) -> dict[str, object]:
    return {
        "mapping": (
            serialize_mapping(result.mapping) if result.mapping is not None else None
        ),
        "occurrence_offsets": list(result.occurrence_offsets),
        "occurrence_offsets_hex": [hex(o) for o in result.occurrence_offsets],
        "rejected_reason": result.rejected_reason,
    }
