"""Tests for ffx_magic_re.sync — manifest validation and dry-run preview."""
from __future__ import annotations

import json
import pytest
from pathlib import Path

from ffx_magic_re.sync import (
    SyncEntry,
    SyncManifest,
    ManifestError,
    load_manifest,
    preview_sync,
    main,
)


def _write_manifest(path: Path, data: dict) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _valid_manifest_data() -> dict:
    return {
        "version": 1,
        "source_root": "/private/repo",
        "entries": [
            {
                "source": "scripts/tool.py",
                "destination": "tools/tool.py",
                "review": "manually verified safe",
            },
        ],
    }


# ---------------------------------------------------------------------------
# Manifest loading
# ---------------------------------------------------------------------------

class TestLoadManifest:
    def test_valid_manifest_loads(self, tmp_path: Path) -> None:
        mp = _write_manifest(tmp_path / "manifest.json", _valid_manifest_data())
        manifest = load_manifest(mp)
        assert manifest.version == 1
        assert manifest.source_root == "/private/repo"
        assert len(manifest.entries) == 1
        assert manifest.entries[0].source == "scripts/tool.py"
        assert manifest.entries[0].destination == "tools/tool.py"
        assert manifest.entries[0].review == "manually verified safe"

    def test_manifest_is_frozen(self, tmp_path: Path) -> None:
        mp = _write_manifest(tmp_path / "manifest.json", _valid_manifest_data())
        manifest = load_manifest(mp)
        with pytest.raises(AttributeError):
            manifest.version = 2

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ManifestError):
            load_manifest(tmp_path / "nonexistent.json")

    def test_invalid_json_raises(self, tmp_path: Path) -> None:
        (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
        with pytest.raises(ManifestError):
            load_manifest(tmp_path / "bad.json")

    def test_missing_version_raises(self, tmp_path: Path) -> None:
        data = _valid_manifest_data()
        del data["version"]
        mp = _write_manifest(tmp_path / "m.json", data)
        with pytest.raises(ManifestError):
            load_manifest(mp)

    def test_wrong_version_raises(self, tmp_path: Path) -> None:
        data = _valid_manifest_data()
        data["version"] = 99
        mp = _write_manifest(tmp_path / "m.json", data)
        with pytest.raises(ManifestError):
            load_manifest(mp)

    def test_missing_source_root_raises(self, tmp_path: Path) -> None:
        data = _valid_manifest_data()
        del data["source_root"]
        mp = _write_manifest(tmp_path / "m.json", data)
        with pytest.raises(ManifestError):
            load_manifest(mp)

    def test_empty_source_root_raises(self, tmp_path: Path) -> None:
        data = _valid_manifest_data()
        data["source_root"] = ""
        mp = _write_manifest(tmp_path / "m.json", data)
        with pytest.raises(ManifestError):
            load_manifest(mp)

    def test_empty_entries_raises(self, tmp_path: Path) -> None:
        data = _valid_manifest_data()
        data["entries"] = []
        mp = _write_manifest(tmp_path / "m.json", data)
        with pytest.raises(ManifestError):
            load_manifest(mp)

    def test_entry_missing_source_raises(self, tmp_path: Path) -> None:
        data = _valid_manifest_data()
        del data["entries"][0]["source"]
        mp = _write_manifest(tmp_path / "m.json", data)
        with pytest.raises(ManifestError):
            load_manifest(mp)

    def test_entry_missing_destination_raises(self, tmp_path: Path) -> None:
        data = _valid_manifest_data()
        del data["entries"][0]["destination"]
        mp = _write_manifest(tmp_path / "m.json", data)
        with pytest.raises(ManifestError):
            load_manifest(mp)

    def test_entry_missing_review_raises(self, tmp_path: Path) -> None:
        data = _valid_manifest_data()
        del data["entries"][0]["review"]
        mp = _write_manifest(tmp_path / "m.json", data)
        with pytest.raises(ManifestError):
            load_manifest(mp)


# ---------------------------------------------------------------------------
# Preview
# ---------------------------------------------------------------------------

class TestPreviewSync:
    def test_preview_returns_lines(self) -> None:
        manifest = SyncManifest(
            version=1,
            source_root="/private",
            entries=(
                SyncEntry(
                    source="a.py",
                    destination="b.py",
                    review="ok",
                ),
            ),
        )
        lines = preview_sync(manifest)
        assert len(lines) >= 1
        joined = "\n".join(lines)
        assert "a.py" in joined
        assert "b.py" in joined

    def test_preview_mentions_dry_run(self) -> None:
        manifest = SyncManifest(
            version=1,
            source_root="/private",
            entries=(
                SyncEntry(source="a.py", destination="b.py", review="ok"),
            ),
        )
        lines = preview_sync(manifest)
        joined = "\n".join(lines).lower()
        assert "dry" in joined or "preview" in joined

    def test_preview_multiple_entries(self) -> None:
        manifest = SyncManifest(
            version=1,
            source_root="/private",
            entries=(
                SyncEntry(source="a.py", destination="x/a.py", review="1"),
                SyncEntry(source="b.py", destination="x/b.py", review="2"),
                SyncEntry(source="c.py", destination="x/c.py", review="3"),
            ),
        )
        lines = preview_sync(manifest)
        joined = "\n".join(lines)
        assert "a.py" in joined
        assert "b.py" in joined
        assert "c.py" in joined


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class TestSyncCLI:
    def test_no_args_returns_error(self) -> None:
        rc = main([])
        assert rc != 0

    def test_no_manifest_returns_error(self) -> None:
        rc = main(["--dry-run"])
        assert rc != 0

    def test_no_dry_run_returns_error(self, tmp_path: Path) -> None:
        mp = _write_manifest(tmp_path / "m.json", _valid_manifest_data())
        rc = main(["--manifest", str(mp)])
        assert rc != 0

    def test_valid_manifest_dry_run_succeeds(self, tmp_path: Path) -> None:
        mp = _write_manifest(tmp_path / "m.json", _valid_manifest_data())
        rc = main(["--manifest", str(mp), "--dry-run"])
        assert rc == 0

    def test_invalid_manifest_returns_error(self, tmp_path: Path) -> None:
        (tmp_path / "bad.json").write_text("{bad", encoding="utf-8")
        rc = main(["--manifest", str(tmp_path / "bad.json"), "--dry-run"])
        assert rc != 0


# ---------------------------------------------------------------------------
# Tracked example manifest — repo must ship a working example
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent
_EXAMPLE_MANIFEST = _REPO_ROOT / "examples" / "sync_manifest.json"


class TestTrackedExampleManifest:
    """The repo must ship a tracked example manifest usable with --dry-run."""

    def test_example_manifest_file_exists(self) -> None:
        assert _EXAMPLE_MANIFEST.is_file(), (
            f"missing tracked example manifest: {_EXAMPLE_MANIFEST}"
        )

    def test_example_manifest_loads_valid(self) -> None:
        manifest = load_manifest(_EXAMPLE_MANIFEST)
        assert manifest.version == 1
        assert len(manifest.entries) >= 1

    def test_example_manifest_dry_run_succeeds(self) -> None:
        rc = main(["--manifest", str(_EXAMPLE_MANIFEST), "--dry-run"])
        assert rc == 0

    def test_example_manifest_no_private_paths(self) -> None:
        raw = _EXAMPLE_MANIFEST.read_text(encoding="utf-8")
        assert "wande" not in raw.lower(), (
            "example manifest must not contain private usernames"
        )


# ---------------------------------------------------------------------------
# Path contract — docs and CLI must point at the tracked example location
# ---------------------------------------------------------------------------

_TRACKED_EXAMPLE_REL = "examples/sync_manifest.json"
_BROKEN_ROOT_EXAMPLE = "sync_manifest.example.json"

_DOC_FILES = (
    _REPO_ROOT / "README.md",
    _REPO_ROOT / "PUBLIC_UPSTREAM.md",
)

# Tracked text files scanned for the stale root-level manifest reference.
# Skips binary/VCS/cache dirs that rglob would otherwise traverse.
_STALE_REF_SKIP_DIRS = frozenset({
    ".git", "__pycache__", ".pytest_cache", "dist", "build",
    ".eggs", ".mypy_cache", ".ruff_cache",
})

# This test file legitimately names the stale path to encode the contract,
# so it is exempt from the stale-reference scan (mirrors the guard's
# text_marker_allowlist philosophy for policy files).
_STALE_REF_SKIP_FILES = frozenset({"tests/test_sync.py"})


class TestTrackedExamplePathContract:
    """Docs, CLI, and the tracked file must agree on the example location.

    Guards against drift where a doc or invocation points at a
    nonexistent root-level ``sync_manifest.example.json`` while the real
    tracked file lives under ``examples/``.
    """

    def test_tracked_relative_path_is_examples_subdir(self) -> None:
        assert _EXAMPLE_MANIFEST == _REPO_ROOT / _TRACKED_EXAMPLE_REL
        assert _EXAMPLE_MANIFEST.relative_to(_REPO_ROOT).as_posix() == (
            _TRACKED_EXAMPLE_REL
        )

    def test_readme_references_tracked_example_path(self) -> None:
        text = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")
        assert _TRACKED_EXAMPLE_REL in text, (
            "README.md must reference the tracked example manifest at "
            f"{_TRACKED_EXAMPLE_REL}"
        )

    def test_public_upstream_references_tracked_example_path(self) -> None:
        text = (_REPO_ROOT / "PUBLIC_UPSTREAM.md").read_text(encoding="utf-8")
        assert _TRACKED_EXAMPLE_REL in text, (
            "PUBLIC_UPSTREAM.md must reference the tracked example manifest "
            f"at {_TRACKED_EXAMPLE_REL}"
        )

    def test_no_doc_references_stale_root_example(self) -> None:
        for doc in _DOC_FILES:
            text = doc.read_text(encoding="utf-8")
            assert _BROKEN_ROOT_EXAMPLE not in text, (
                f"{doc.name} references nonexistent root-level "
                f"{_BROKEN_ROOT_EXAMPLE}"
            )

    def test_no_tracked_file_references_stale_root_example(self) -> None:
        offenders: list[str] = []
        for path in sorted(_REPO_ROOT.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(_REPO_ROOT)
            rel_posix = rel.as_posix()
            if any(part in _STALE_REF_SKIP_DIRS for part in rel.parts):
                continue
            if rel_posix.endswith(".egg-info"):
                continue
            if rel_posix in _STALE_REF_SKIP_FILES:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            if _BROKEN_ROOT_EXAMPLE in text:
                offenders.append(rel_posix)
        assert offenders == [], (
            "files reference nonexistent root-level "
            f"{_BROKEN_ROOT_EXAMPLE}: {offenders}"
        )
