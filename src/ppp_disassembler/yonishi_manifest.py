"""T0.6.1 — Build `work/layer_c/yonishi_manifest.json` from external corpus.

The manifest is the single source of truth for Layer C Wave 1+. It records:

* SHA-256 of every `.par` (10) and `.pdt` (11) under the Yonishi root.
* Aggregate `.par` statistics: TIME-block count (3,808), operand-width
  histogram, opcode-spelling set (55).
* `.h` dispatch counts (120 / 4,218 / 153) loaded from `h_catalog.json`
  (already validated under Wave 0).
* Relocation sample for `eff_0148.bin` loaded from `relocation_map_0148.json`.

Counts that come from existing artifacts are NOT recomputed from the
filesystem — those numbers were validated against the locked baseline and
must stay bit-for-bit identical.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from . import par_fixture_snapshot as pfs


_TIME_HEADER_RE = re.compile(rb"^\[TIME\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$")
_HEX_LINE_RE = re.compile(rb"^(?:[0-9a-fA-F]{2}\s+)*[0-9a-fA-F]{2}\s*$")
_AT_OPCODE_RE = re.compile(rb"^@([A-Za-z0-9_]+)\s+\d+\s*$")
_NEW_BLOCK_RE = re.compile(rb"^(?:\[|@)")

TIME_HEADER_FORMAT = "[TIME <frame:int> <unk:int> <unk:int> <unk:int>"


class YonishiManifestError(Exception):
    """Typed error for manifest construction failures."""


@dataclass(frozen=True, slots=True)
class ParFileStats:
    """Per-file `.par` statistics."""

    path: Path
    time_blocks: int
    operand_widths: tuple[int, ...]
    spellings: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CorpusAggregate:
    """Aggregates across the 10 `.par` files."""

    time_blocks_total: int
    block_width_histogram: dict[int, int]
    widths_observed_bytes: tuple[int, ...]
    spellings_total: int
    spellings_top: tuple[tuple[str, int], ...]


def scan_par_files(yonishi_root: Path) -> tuple[Path, ...]:
    """All `.par` files under `yonishi_root`, sorted deterministically."""

    return tuple(sorted(yonishi_root.rglob("*.par")))


def scan_pdt_files(yonishi_root: Path) -> tuple[Path, ...]:
    """All `.pdt` files under `yonishi_root`, sorted deterministically."""

    return tuple(sorted(yonishi_root.rglob("*.pdt")))


def parse_par_file(path: Path) -> ParFileStats:
    """Read `path` as bytes and derive its TIME-block + spelling statistics."""

    raw = path.read_bytes()
    lines = raw.split(b"\n")

    time_blocks = 0
    operand_widths: list[int] = []
    spellings: list[str] = []

    in_operand = False
    operand_bytes = 0

    def _flush_operand() -> None:
        nonlocal in_operand, operand_bytes
        if in_operand:
            operand_widths.append(operand_bytes)
            in_operand = False
            operand_bytes = 0

    for line in lines:
        stripped = line.rstrip(b"\r")
        if _TIME_HEADER_RE.match(stripped):
            _flush_operand()
            time_blocks += 1
            in_operand = True
            operand_bytes = 0
            continue
        if in_operand:
            if _HEX_LINE_RE.match(stripped.lstrip()):
                pairs = stripped.split()
                operand_bytes += len(pairs)
                continue
            _flush_operand()
        at_match = _AT_OPCODE_RE.match(stripped)
        if at_match:
            spellings.append(at_match.group(1).decode("ascii"))

    _flush_operand()

    return ParFileStats(
        path=path,
        time_blocks=time_blocks,
        operand_widths=tuple(operand_widths),
        spellings=tuple(spellings),
    )


def count_time_blocks(path: Path) -> int:
    """Total `[TIME ...]` header count in `path`."""

    raw = path.read_bytes()
    return sum(
        1
        for line in raw.split(b"\n")
        if _TIME_HEADER_RE.match(line.rstrip(b"\r"))
    )


def collect_spellings(paths: Sequence[Path]) -> set[str]:
    """Set of distinct `@OPCODE` spellings across all `paths`."""

    spellings: set[str] = set()
    for path in paths:
        raw = path.read_bytes()
        for line in raw.split(b"\n"):
            match = _AT_OPCODE_RE.match(line.rstrip(b"\r"))
            if match:
                spellings.add(match.group(1).decode("ascii"))
    return spellings


def compute_block_width_histogram(paths: Sequence[Path]) -> dict[int, int]:
    """Operand-width histogram (in bytes) across all `paths`."""

    counter: Counter[int] = Counter()
    for path in paths:
        stats = parse_par_file(path)
        counter.update(stats.operand_widths)
    return dict(counter)


def _aggregate_corpus(paths: Sequence[Path]) -> CorpusAggregate:
    time_blocks_total = 0
    width_counter: Counter[int] = Counter()
    spelling_counter: Counter[str] = Counter()
    for path in paths:
        stats = parse_par_file(path)
        time_blocks_total += stats.time_blocks
        width_counter.update(stats.operand_widths)
        spelling_counter.update(stats.spellings)

    widths_observed = tuple(sorted(width_counter.keys()))
    spellings_top = tuple(spelling_counter.most_common(10))
    return CorpusAggregate(
        time_blocks_total=time_blocks_total,
        block_width_histogram=dict(width_counter),
        widths_observed_bytes=widths_observed,
        spellings_total=len(spelling_counter),
        spellings_top=spellings_top,
    )


def _sha_list(paths: Sequence[Path]) -> list[str]:
    return [pfs.compute_sha256(p) for p in paths]


def _json_int(value: object, context: str) -> int:
    """Coerce a JSON-loaded value to int via isinstance narrowing."""
    if isinstance(value, (int, float, str)):
        return int(value)
    raise YonishiManifestError(
        f"{context}: expected int/float/str, got {type(value).__name__}",
    )


def _build_relocation_summary(
    relocation_map: dict[str, object],
) -> dict[str, object]:
    ps2_offset = _json_int(
        relocation_map["ps2_offset_in_pc"],
        "relocation_map_0148.json: ps2_offset_in_pc",
    )
    delta_raw = relocation_map.get("delta_distribution")
    if not isinstance(delta_raw, dict):
        raise YonishiManifestError(
            "relocation_map_0148.json: delta_distribution is not an object",
        )
    delta_counts: dict[str, int] = {}
    for raw_key, raw_value in delta_raw.items():
        if not isinstance(raw_key, str):
            raise YonishiManifestError(
                "relocation_map_0148.json: delta_distribution key is not a string",
            )
        delta_counts[raw_key] = _json_int(
            raw_value,
            f"relocation_map_0148.json: delta_distribution[{raw_key}]",
        )
    sorted_items = sorted(
        delta_counts.items(),
        key=lambda kv: kv[1],
        reverse=True,
    )
    top_delta, top_delta_count = sorted_items[0]
    return {
        "ps2_offset_in_pc_hex": hex(ps2_offset),
        "pointer_relocations": _json_int(
            relocation_map["pointer_relocations"],
            "relocation_map_0148.json: pointer_relocations",
        ),
        "non_pointer_mismatches": _json_int(
            relocation_map["non_pointer_mismatches"],
            "relocation_map_0148.json: non_pointer_mismatches",
        ),
        "top_delta": top_delta,
        "top_delta_count": top_delta_count,
    }


def build_yonishi_manifest(
    yonishi_root: Path,
    repo_root: Path,
    *,
    captured_at: str | None = None,
) -> dict[str, object]:
    """Construct the manifest as a plain dict ready for JSON serialization."""

    from datetime import datetime, timezone

    captured = captured_at or datetime.now(timezone.utc).isoformat(
        timespec="seconds",
    )

    par_paths = scan_par_files(yonishi_root)
    pdt_paths = scan_pdt_files(yonishi_root)
    par_shas = _sha_list(par_paths)
    pdt_shas = _sha_list(pdt_paths)

    corpus = _aggregate_corpus(par_paths)

    h_catalog_path = repo_root / "work" / "layer_c" / "h_catalog.json"
    reloc_path = repo_root / "work" / "layer_c" / "relocation_map_0148.json"

    try:
        h_catalog = json.loads(h_catalog_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise YonishiManifestError(
            f"h_catalog.json missing: {h_catalog_path}",
        ) from exc
    try:
        relocation_map = json.loads(reloc_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise YonishiManifestError(
            f"relocation_map_0148.json missing: {reloc_path}",
        ) from exc

    relocation_summary = _build_relocation_summary(relocation_map)

    return {
        "captured_at": captured,
        "yonishi_root": str(yonishi_root),
        "par_files": par_shas,
        "pdt_files": pdt_shas,
        "time_blocks_total": corpus.time_blocks_total,
        "widths_observed_bytes": list(corpus.widths_observed_bytes),
        "block_width_histogram": {
            str(k): corpus.block_width_histogram[k]
            for k in sorted(corpus.block_width_histogram)
        },
        "spellings_total": corpus.spellings_total,
        "spellings_top": [
            [spelling, count] for spelling, count in corpus.spellings_top
        ],
        "time_header_format": TIME_HEADER_FORMAT,
        "h_files": int(h_catalog["total_files"]),
        "h_entries_total": int(h_catalog["total_opcode_entries"]),
        "h_unique_opcodes": int(h_catalog["unique_opcodes"]),
        "relocation_0148": relocation_summary,
    }


def _merge_par_fixtures(
    manifest: dict[str, object],
    output: Path,
) -> dict[str, object]:
    if not output.exists():
        return manifest
    try:
        old_raw: object = json.loads(output.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return manifest
    if not isinstance(old_raw, dict):
        return manifest
    raw_fixtures: object = old_raw.get("par_fixtures")
    if raw_fixtures is None:
        return manifest
    rebuilt: dict[str, object] = {}
    for key, value in manifest.items():
        rebuilt[key] = value
        if key == "par_files":
            rebuilt["par_fixtures"] = raw_fixtures
    if "par_fixtures" not in rebuilt:
        rebuilt["par_fixtures"] = raw_fixtures
    return rebuilt


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="yonishi_manifest",
        description="Build yonishi_manifest.json from the external Yonishi corpus.",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path("."),
        help="repository root containing work/layer_c/ (default: current directory)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="output path (default: <repo-root>/work/layer_c/yonishi_manifest.json)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    output: Path = (
        args.output
        if args.output is not None
        else args.repo_root / "work" / "layer_c" / "yonishi_manifest.json"
    )

    try:
        manifest = build_yonishi_manifest(
            pfs.YONISHI_ROOT_DEFAULT,
            args.repo_root,
        )
    except YonishiManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    manifest = _merge_par_fixtures(manifest, output)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(manifest, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
