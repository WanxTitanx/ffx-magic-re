"""T2.1 — Yonishi ``.h`` dispatch-table parser and PC-correlation report.

Wave 1 / T2.1 deliverable. Parses the 120 PS2 authoring-source ``.h``
files in ``D:\\FFX Extracted\\FFX\\ffx_ps2\\ffx\\yonishi_data`` and emits a
reproducible catalog split into two clearly-labelled sections:

* ``source_proved`` — facts proven by reading the actual C source.
  The 10-field / 40B / 9-slot per-row layout, the opcode names, and
  which slots are zero vs nonzero are read straight from
  ``{ PPMPN("..."), (void *)S1, ..., (void *)S9 },`` initializers.

* ``pc_correlation_gated`` — facts about how the PS2 slots *might*
  map to PC dispatch fields. The PC ``.rdata`` dispatch table is
  0x28 (40) bytes too, but only three function slots at ``+0x04``,
  ``+0x08``, ``+0x0C`` are exercised; the remaining 24 bytes are
  reserved zeros. Whether PS2 slot 1 corresponds to PC ``+0x04``,
  slot 2 to ``+0x08``, etc. is **not** semantically proven
  (``docs/reverse/magic_dlls/HANDLER_TABLE_LAYOUT.md`` §3, §8).
  Every field-mapping claim is therefore marked ``gated``.

The parser is pure regex over the source text. It does not invoke a
C preprocessor and does not resolve function addresses. It emits the
raw tokens from the source so that zero (``"0"``) and nonzero
(symbolic) expressions are preserved losslessly.

No import from any C1 module — this module is a standalone reader
that lives under ``scripts/ppp_disassembler/`` only for repo hygiene.
"""

from __future__ import annotations

# ``dict[str, object]`` avoids the invariant-container problem a
# recursive ``JsonValue`` union would create with ``list[str]`` etc.
# Fixed-shape structures use ``TypedDict``.

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, TypedDict


# ---------------------------------------------------------------------------
# Type definitions
# ---------------------------------------------------------------------------


class EntryDict(TypedDict):
    opcode_name: str
    main_handler: str
    secondary: str
    draw_handler: str
    unused_0_4: list[str]
    con_callback: str
    con_callback2: str
    des_callback: str
    slots: list[str]
    nonzero_slot_count: int
    raw_offset_in_file: int


class HCatalogFileEntry(TypedDict):
    file: str
    size: int
    opcode_count: int


class HCatalogJson(TypedDict):
    total_files: int
    total_opcode_entries: int
    unique_opcodes: int
    opcode_frequency: dict[str, int]
    files: list[HCatalogFileEntry]


class CrossRefJson(TypedDict):
    ps2_count: int
    exe_count: int
    in_both: list[str]
    only_ps2: list[str]
    only_exe: list[str]
    match_pct_ps2: int
    match_pct_exe: int


class CatalogBody(TypedDict):
    deterministic_body: dict[str, dict[str, object]]


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

ENTRY_STRUCT_BYTES: Final[int] = 40
FIELD_COUNT: Final[int] = 10  # name + 9 function slots
FUNCTION_SLOT_COUNT: Final[int] = 9


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class HDispatchParseError(Exception):
    """Typed error for ``.h`` dispatch-table parsing failures."""


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HDispatchEntry:
    """One ``{ PPMPN("name"), (void *)S1, ..., (void *)S9 },`` row.

    Each function slot preserves the raw source token: ``"0"`` when
    the source writes ``(void *)0``, or the bare C identifier (e.g.
    ``"pppAccele"``) when nonzero. This is lossless with respect to
    the original C initializer and lets downstream code distinguish
    zero from nonzero without parsing again.
    """

    opcode_name: str
    main_handler: str        # slot 1 (source field index 1)
    secondary: str           # slot 2
    draw_handler: str        # slot 3
    unused_0_4: tuple[str, str, str]  # slots 4-6 (reserved in PC)
    con_callback: str        # slot 7
    con_callback2: str       # slot 8
    des_callback: str        # slot 9
    raw_offset_in_file: int  # byte offset of PPMPN in source text

    @property
    def slots(self) -> tuple[str, ...]:
        """All nine function slots in source order (slot 1..9)."""
        return (
            self.main_handler,
            self.secondary,
            self.draw_handler,
            *self.unused_0_4,
            self.con_callback,
            self.con_callback2,
            self.des_callback,
        )

    @property
    def nonzero_slot_count(self) -> int:
        return sum(1 for s in self.slots if s != "0")


@dataclass(frozen=True, slots=True)
class HFile:
    """One parsed ``.h`` dispatch file."""

    path: Path
    entries: tuple[HDispatchEntry, ...]
    parse_warns: tuple[str, ...]


# ---------------------------------------------------------------------------
# Internal regexes
# ---------------------------------------------------------------------------


_PPMPN_NAME_RE = re.compile(
    r'PPMPN\s*\(\s*"([^"]+)"\s*\)',
)

# After PPMPN, the remaining text is: `, (void *)TOKEN` (×9, last
# may end with `}`). The token is either `0` or a C identifier.
# Each slot match starts by consuming the comma separator.
# Trailing whitespace belongs to the NEXT slot's leading `\s*,`
# (or to the closing brace), so the lookahead only PEEKS for it.
_VOID_PTR_SLOT_RE = re.compile(
    r'\s*,\s*\(\s*void\s*\*\s*\)\s*([^,)}]+?)(?=\s*[,}])',
)

# Array body: `pppProg NAME[]={...};`. Non-greedy body capture.
_ARRAY_BODY_RE = re.compile(
    r'\bpppProg\s+(\w+)\s*\[\s*\]\s*=\s*\{(.*?)\}\s*;',
    re.DOTALL,
)


# ---------------------------------------------------------------------------
# Core parsing
# ---------------------------------------------------------------------------


def parse_h_text(text: str, *, source_label: str = "<text>") -> HFile:
    """Parse C initializer text and return ``HFile``.

    Comments (``// ...`` and ``/* ... */``) are replaced with spaces
    of equal length so that ``raw_offset_in_file`` matches the byte
    position in the original text.
    """
    sanitized = _strip_comments_preserving_offsets(text)

    entries: list[HDispatchEntry] = []
    warns: list[str] = []

    array_matches = list(_ARRAY_BODY_RE.finditer(sanitized))
    if not array_matches:
        warns.append(f"{source_label}: no pppProg array found")
        return HFile(
            path=Path(source_label),
            entries=tuple(entries),
            parse_warns=tuple(warns),
        )

    if len(array_matches) > 1:
        names = [m.group(1) for m in array_matches]
        warns.append(
            f"{source_label}: {len(array_matches)} arrays found "
            f"(names={names}); parsed all entries"
        )

    for arr_m in array_matches:
        body = arr_m.group(2)
        body_offset = arr_m.start(2)

        for ppmpn_m in _PPMPN_NAME_RE.finditer(body):
            name = ppmpn_m.group(1)
            scan_pos = ppmpn_m.end()
            slots: list[str] = []
            for _ in range(FUNCTION_SLOT_COUNT):
                slot_m = _VOID_PTR_SLOT_RE.match(body, scan_pos)
                if slot_m is None:
                    break
                slots.append(slot_m.group(1).strip())
                scan_pos = slot_m.end()

            if len(slots) != FUNCTION_SLOT_COUNT:
                raise HDispatchParseError(
                    f"{source_label}: row for {name!r} at body offset "
                    f"{ppmpn_m.start()} has {len(slots)} slots, "
                    f"expected {FUNCTION_SLOT_COUNT}"
                )

            entries.append(HDispatchEntry(
                opcode_name=name,
                main_handler=slots[0],
                secondary=slots[1],
                draw_handler=slots[2],
                unused_0_4=(slots[3], slots[4], slots[5]),
                con_callback=slots[6],
                con_callback2=slots[7],
                des_callback=slots[8],
                raw_offset_in_file=body_offset + ppmpn_m.start(),
            ))

    if not entries:
        warns.append(f"{source_label}: array found but no entries parsed")

    return HFile(
        path=Path(source_label),
        entries=tuple(entries),
        parse_warns=tuple(warns),
    )


def parse_h_file(path: Path) -> HFile:
    """Read and parse a ``.h`` dispatch file from disk."""
    text = path.read_text(encoding="utf-8", errors="surrogateescape")
    return parse_h_text(text, source_label=str(path))


# ---------------------------------------------------------------------------
# Comment handling
# ---------------------------------------------------------------------------


_LINE_COMMENT_RE = re.compile(r'//[^\n]*')
_BLOCK_COMMENT_RE = re.compile(r'/\*.*?\*/', re.DOTALL)


def _strip_comments_preserving_offsets(text: str) -> str:
    """Replace comments with equal-length whitespace.

    Keeps every character's byte position so that offsets returned
    by the row parser line up with the original source.
    """
    def _spacer(match: re.Match[str]) -> str:
        return " " * len(match.group(0))

    out = _LINE_COMMENT_RE.sub(_spacer, text)
    out = _BLOCK_COMMENT_RE.sub(_spacer, out)
    return out


# ---------------------------------------------------------------------------
# Typed JSON loaders
# ---------------------------------------------------------------------------


def _load_h_catalog(path: Path) -> HCatalogJson:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_cross_ref(path: Path) -> CrossRefJson:
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Catalog builder (real corpus)
# ---------------------------------------------------------------------------


def build_catalog(yonishi_root: Path, repo_root: Path) -> CatalogBody:
    """Parse all 120 catalogued ``.h`` files and emit a deterministic catalog.

    The catalog separates ``source_proved`` (proved by the PS2 source)
    from ``pc_correlation_gated`` (PC dispatch comparison, where every
    field-mapping claim is gated per ``HANDLER_TABLE_LAYOUT.md`` §3, §8).
    """
    h_catalog_path = repo_root / "work" / "layer_c" / "h_catalog.json"
    cross_ref_path = repo_root / "work" / "layer_c" / "cross_ref_ps2_exe.json"

    h_catalog = _load_h_catalog(h_catalog_path)
    cross_ref = _load_cross_ref(cross_ref_path)

    files_section: list[dict[str, object]] = []
    parsed_names: set[str] = set()
    total_entries = 0

    for finfo in h_catalog["files"]:
        rel = finfo["file"].replace("\\", "/")
        abs_path = yonishi_root / rel
        hf = parse_h_file(abs_path)

        sha = hashlib.sha256(abs_path.read_bytes()).hexdigest()
        nonzero_total = sum(e.nonzero_slot_count for e in hf.entries)
        slot_hist: dict[str, int] = {}
        for e in hf.entries:
            for i, s in enumerate(e.slots, start=1):
                key = f"slot_{i}_nonzero"
                if s != "0":
                    slot_hist[key] = slot_hist.get(key, 0) + 1

        files_section.append({
            "source_path": str(abs_path),
            "catalog_rel": finfo["file"],
            "sha256": sha,
            "size_bytes": abs_path.stat().st_size,
            "entries": [entry_to_dict(e) for e in hf.entries],
            "parse_warns": list(hf.parse_warns),
            "nonzero_slot_total": nonzero_total,
            "slot_nonzero_histogram": slot_hist,
        })

        for e in hf.entries:
            parsed_names.add(e.opcode_name)
        total_entries += len(hf.entries)

    in_both = set(cross_ref["in_both"])
    source_in_pc = sorted(parsed_names & in_both)
    source_only = sorted(parsed_names - in_both)

    source_proved: dict[str, object] = {
        "evidence": "PS2 authoring source .h C initializer (Yonishi data)",
        "entry_struct_bytes": ENTRY_STRUCT_BYTES,
        "field_count": FIELD_COUNT,
        "function_slot_count": FUNCTION_SLOT_COUNT,
        "files_parsed": len(files_section),
        "entries_total": total_entries,
        "unique_opcodes": len(parsed_names),
        "source_opcode_names_sorted": sorted(parsed_names),
        "files": files_section,
    }

    pc_correlation_gated: dict[str, object] = {
        "evidence": "docs/reverse/magic_dlls/HANDLER_TABLE_LAYOUT.md §3 §8",
        "field_mapping_status": "gated",
        "evidence_note": (
            "PC dispatch table is 0x28 (40) bytes with three function "
            "slots at +0x04/+0x08/+0x0C and 24 bytes of reserved zeros. "
            "Whether PS2 source slots 1..3 correspond to PC +0x04/+0x08/+0x0C "
            "is not yet semantically proven; HANDLER_TABLE_LAYOUT.md §3 §8."
        ),
        "pc_dispatch_slots": ["+0x04", "+0x08", "+0x0C"],
        "pc_reserved_bytes": "0x10..0x27 (24 bytes, currently zeros in PC)",
        "pc_catalog_source": "work/layer_c/cross_ref_ps2_exe.json",
        "pc_exe_opcode_count": int(cross_ref["exe_count"]),
        "pc_ps2_opcode_count": int(cross_ref["ps2_count"]),
        "source_opcodes_in_pc_count": len(source_in_pc),
        "source_opcodes_in_pc_pct": float(cross_ref["match_pct_ps2"]),
        "source_opcodes_in_pc_sorted": source_in_pc,
        "source_opcodes_missing_in_pc_sorted": source_only,
        "pc_opcodes_missing_in_source_sorted": sorted(
            set(cross_ref["only_exe"]),
        ),
    }

    return {
        "deterministic_body": {
            "source_proved": source_proved,
            "pc_correlation_gated": pc_correlation_gated,
        }
    }


def build_catalog_from_synthetic() -> CatalogBody:
    """Small self-contained catalog for unit tests of the catalog shape.

    Reads two in-memory snippets via :func:`parse_h_text` so the
    SOURCE_PROVED / PC_CORRELATION_GATED structure is exercised
    without touching the filesystem.
    """
    text_a = (
        'static pppProg pppProgTbl_A[]={\n'
        '  { PPMPN("pppDummy"), '
        '(void *)0, (void *)0, (void *)0, (void *)0, (void *)0, '
        '(void *)0, (void *)0, (void *)0, (void *)0 },\n'
        '  { PPMPN("pppAccele"), '
        '(void *)0, (void *)pppAccele, (void *)0, (void *)0, (void *)0, (void *)0, '
        '(void *)pppAcceleCon, (void *)pppAcceleCon, (void *)0 },\n'
        '};\n'
    )
    text_b = (
        'static pppProg pppProgTbl_B[]={\n'
        '  { PPMPN("pppDrawMdl"), '
        '(void *)0, (void *)0, (void *)pppDrawMdl, (void *)0, (void *)0, '
        '(void *)0, (void *)0, (void *)0, (void *)0 },\n'
        '};\n'
    )

    parsed_names: set[str] = set()
    files_section: list[dict[str, object]] = []
    entries_total = 0
    for label, text in (("a.h", text_a), ("b.h", text_b)):
        hf = parse_h_text(text, source_label=label)
        for e in hf.entries:
            parsed_names.add(e.opcode_name)
        entries_total += len(hf.entries)
        files_section.append({
            "source_path": label,
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "entries": [entry_to_dict(e) for e in hf.entries],
            "parse_warns": list(hf.parse_warns),
        })

    source_proved: dict[str, object] = {
        "evidence": "PS2 authoring source .h C initializer",
        "entry_struct_bytes": ENTRY_STRUCT_BYTES,
        "field_count": FIELD_COUNT,
        "function_slot_count": FUNCTION_SLOT_COUNT,
        "files_parsed": len(files_section),
        "entries_total": entries_total,
        "unique_opcodes": len(parsed_names),
        "source_opcode_names_sorted": sorted(parsed_names),
        "files": files_section,
    }

    pc_correlation_gated: dict[str, object] = {
        "evidence": "docs/reverse/magic_dlls/HANDLER_TABLE_LAYOUT.md §3 §8",
        "field_mapping_status": "gated",
        "evidence_note": (
            "PC dispatch table is 0x28 (40) bytes with three function "
            "slots at +0x04/+0x08/+0x0C and 24 bytes of reserved zeros. "
            "PS2 slot -> PC field mapping is not proven."
        ),
        "pc_dispatch_slots": ["+0x04", "+0x08", "+0x0C"],
        "pc_reserved_bytes": "0x10..0x27 (24 bytes)",
        "pc_catalog_source": "synthetic (not loaded)",
        "pc_exe_opcode_count": 0,
        "pc_ps2_opcode_count": 0,
        "source_opcodes_in_pc_count": 0,
        "source_opcodes_in_pc_pct": 0.0,
        "source_opcodes_in_pc_sorted": [],
        "source_opcodes_missing_in_pc_sorted": sorted(parsed_names),
        "pc_opcodes_missing_in_source_sorted": [],
    }

    return {
        "deterministic_body": {
            "source_proved": source_proved,
            "pc_correlation_gated": pc_correlation_gated,
        }
    }


def entry_to_dict(entry: HDispatchEntry) -> EntryDict:
    """Lossless JSON view of one parsed row."""
    return {
        "opcode_name": entry.opcode_name,
        "main_handler": entry.main_handler,
        "secondary": entry.secondary,
        "draw_handler": entry.draw_handler,
        "unused_0_4": list(entry.unused_0_4),
        "con_callback": entry.con_callback,
        "con_callback2": entry.con_callback2,
        "des_callback": entry.des_callback,
        "slots": list(entry.slots),
        "nonzero_slot_count": entry.nonzero_slot_count,
        "raw_offset_in_file": entry.raw_offset_in_file,
    }


def catalog_sha256(catalog: Mapping[str, object]) -> str:
    """Stable SHA-256 of the deterministic body (sorted keys, no ws)."""
    body: object = catalog.get("deterministic_body", catalog)
    encoded = json.dumps(body, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
