"""Manifest-driven one-way sync preview for the public repository.

This module NEVER copies files. It only validates a review manifest
and prints a preview of what a future sync would do.

Requires both ``--manifest`` and ``--dry-run`` to operate.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path


_SUPPORTED_VERSION: int = 1


@dataclass(frozen=True, slots=True)
class SyncEntry:
    """A single sync operation described by the manifest."""

    source: str
    destination: str
    review: str


@dataclass(frozen=True, slots=True)
class SyncManifest:
    """Parsed and validated sync manifest."""

    version: int
    source_root: str
    entries: tuple[SyncEntry, ...]


class ManifestError(ValueError):
    """Raised when a manifest is missing required fields or malformed."""


def load_manifest(path: Path) -> SyncManifest:
    """Load and validate a manifest file.

    Raises ManifestError on any structural problem.
    Never reads, stats, or accesses the source repository.
    """
    if not path.is_file():
        raise ManifestError(f"manifest file not found: {path}")

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManifestError(f"cannot read manifest: {exc}") from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"invalid JSON in manifest: {exc}") from exc

    if not isinstance(data, dict):
        raise ManifestError("manifest root must be a JSON object")

    version = data.get("version")
    if not isinstance(version, int):
        raise ManifestError("manifest missing integer 'version' field")
    if version != _SUPPORTED_VERSION:
        raise ManifestError(
            f"unsupported manifest version {version}; "
            + f"expected {_SUPPORTED_VERSION}"
        )

    source_root = data.get("source_root")
    if not isinstance(source_root, str) or not source_root.strip():
        raise ManifestError(
            "manifest missing non-empty 'source_root' string"
        )

    raw_entries = data.get("entries")
    if not isinstance(raw_entries, list) or len(raw_entries) == 0:
        raise ManifestError("manifest must contain at least one entry")

    entries: list[SyncEntry] = []
    for i, item in enumerate(raw_entries):
        if not isinstance(item, dict):
            raise ManifestError(f"entry {i} is not a JSON object")
        source = item.get("source")
        dest = item.get("destination")
        review = item.get("review")
        if not isinstance(source, str) or not source.strip():
            raise ManifestError(
                f"entry {i} missing non-empty 'source'"
            )
        if not isinstance(dest, str) or not dest.strip():
            raise ManifestError(
                f"entry {i} missing non-empty 'destination'"
            )
        if not isinstance(review, str) or not review.strip():
            raise ManifestError(
                f"entry {i} missing non-empty 'review'"
            )
        entries.append(SyncEntry(source=source, destination=dest, review=review))

    return SyncManifest(
        version=version,
        source_root=source_root,
        entries=tuple(entries),
    )


def preview_sync(manifest: SyncManifest) -> list[str]:
    """Return preview lines for a manifest — never touches the filesystem."""
    lines: list[str] = [
        "=== DRY-RUN PREVIEW (no files will be copied) ===",
        f"source_root: {manifest.source_root}",
        f"entries: {len(manifest.entries)}",
        "",
    ]
    for i, entry in enumerate(manifest.entries):
        lines.extend([
            f"  [{i + 1}] {entry.source}",
            f"      -> {entry.destination}",
            f"      review: {entry.review}",
        ])
    lines.extend([
        "",
        "=== END PREVIEW — review each entry before any real sync ===",
    ])
    return lines


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Requires both ``--manifest`` and ``--dry-run``.
    Without either, prints usage error and returns non-zero.
    """
    parser = argparse.ArgumentParser(
        prog="sync_from_private",
        description=(
            "Manifest-driven one-way sync PREVIEW. "
            "Never copies files. Requires --dry-run."
        ),
    )
    parser.add_argument(
        "--manifest",
        type=str,
        help="path to the review manifest JSON file",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="required: only preview, never copy",
    )

    args = parser.parse_args(argv)

    if not args.dry_run:
        print(
            "error: --dry-run is required; this tool is preview-only",
            file=sys.stderr,
        )
        return 1

    if not args.manifest:
        print(
            "error: --manifest <path> is required",
            file=sys.stderr,
        )
        return 1

    manifest_path = Path(args.manifest)
    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    for line in preview_sync(manifest):
        print(line)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))