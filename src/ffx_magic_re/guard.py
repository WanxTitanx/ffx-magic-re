"""Public repository tree guard — leak detection for safe publication.

This module is importable and also provides a CLI entry point.
It uses only the Python standard library.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

class ViolationKind(Enum):
    """Categories of guard violations."""

    FORBIDDEN_EXTENSION = auto()
    FORBIDDEN_DIRECTORY = auto()
    FORBIDDEN_TEXT_MARKER = auto()
    WINDOWS_PRIVATE_PATH = auto()
    LIKELY_CREDENTIAL = auto()
    OVERSIZED_FILE = auto()


@dataclass(frozen=True, slots=True)
class Violation:
    """A single detected policy violation."""

    kind: ViolationKind
    path: str
    detail: str


@dataclass(frozen=True, slots=True)
class GuardPolicy:
    """Immutable policy configuration for the tree scanner."""

    forbidden_extensions: frozenset[str]
    forbidden_directories: frozenset[str]
    forbidden_text_markers: frozenset[str]
    text_marker_allowlist: frozenset[str]
    private_path_patterns: tuple[re.Pattern[str], ...]
    credential_regex: re.Pattern[str]
    max_file_bytes: int


# ---------------------------------------------------------------------------
# Default policy
# ---------------------------------------------------------------------------

_FORBIDDEN_EXTENSIONS: frozenset[str] = frozenset({
    ".dll", ".exe", ".bin", ".i64", ".idb",
    ".id0", ".id1", ".id2", ".nam", ".til",
    ".phyre", ".tm2", ".dds", ".wav", ".fsb", ".png",
})

_FORBIDDEN_DIRECTORIES: frozenset[str] = frozenset({
    "tools", "ExternalLibs", "ffx_reconstructed",
    "docs/reverse", "mods", "work", "backups",
    "compiled_magic", "compiled_test", "textures",
})

_FORBIDDEN_TEXT_MARKERS: frozenset[str] = frozenset({
    "Hex-Rays",
    "Auto-decompiled by",
    "Generated from IDA database",
})

_TEXT_MARKER_ALLOWLIST: frozenset[str] = frozenset({
    "README.md",
    "PUBLIC_UPSTREAM.md",
    "CONTRIBUTING.md",
    "scripts/verify_public_tree.py",
    "scripts/sync_from_private.py",
    "src/ffx_magic_re/guard.py",
    "src/ffx_magic_re/__init__.py",
    "src/ffx_magic_re/sync.py",
    "tests/test_guard.py",
    "tests/test_verify_cli.py",
    "tests/test_sync.py",
    ".gitignore",
    ".github/workflows/ci.yml",
    "pyproject.toml",
})

_PRIVATE_USER: str = "wande"

_PRIVATE_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(rf"[A-Za-z]:[\\/]Users[\\/]{_PRIVATE_USER}", re.IGNORECASE),
    re.compile(rf"/Users/{_PRIVATE_USER}/"),
)

_CREDENTIAL_PATTERN: str = (
    r"(?:password|passwd|pwd|api[_-]?key|secret|token|"
    r"access[_-]?key|private[_-]?key)"
    r"\s*[:=]\s*"
    r"""[""'][^""']{3,}[""']"""
)

_CREDENTIAL_REGEX: re.Pattern[str] = re.compile(
    _CREDENTIAL_PATTERN, re.IGNORECASE,
)

_MAX_FILE_BYTES: int = 256 * 1024  # 256 KiB


def default_policy() -> GuardPolicy:
    """Return the default guard policy."""
    return GuardPolicy(
        forbidden_extensions=_FORBIDDEN_EXTENSIONS,
        forbidden_directories=_FORBIDDEN_DIRECTORIES,
        forbidden_text_markers=_FORBIDDEN_TEXT_MARKERS,
        text_marker_allowlist=_TEXT_MARKER_ALLOWLIST,
        private_path_patterns=_PRIVATE_PATH_PATTERNS,
        credential_regex=_CREDENTIAL_REGEX,
        max_file_bytes=_MAX_FILE_BYTES,
    )


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

_SKIP_DIRS: frozenset[str] = frozenset({
    ".git", "__pycache__", ".pytest_cache",
    "build", "dist", ".eggs", ".mypy_cache",
    ".ruff_cache", "htmlcov", ".coverage", ".tox",
})

_SKIP_DIR_SUFFIXES: frozenset[str] = frozenset({".egg-info"})


def _should_skip(rel: Path) -> bool:
    """Check if any path component matches a skip dir or suffix."""
    for part in rel.parts:
        if part in _SKIP_DIRS:
            return True
        for suffix in _SKIP_DIR_SUFFIXES:
            if part.endswith(suffix):
                return True
    return False


def _is_in_forbidden_dir(
    rel: Path, forbidden_dirs: frozenset[str]
) -> str | None:
    """Return the matched forbidden directory path, or None.

    Handles both simple names (``tools``) at any depth and
    multi-segment path prefixes (``docs/reverse``).
    """
    for parent in rel.parents:
        parent_posix = parent.as_posix()
        if parent_posix in forbidden_dirs:
            return parent_posix
    for parent in rel.parents:
        if parent.name in forbidden_dirs:
            return parent.name
    return None


def _scan_text_content(
    raw: bytes, rel_str: str, policy: GuardPolicy,
    skip_text_markers: bool = False,
) -> list[Violation]:
    """Scan decoded file content for text-based violations.

    When *skip_text_markers* is True, forbidden-text-marker checks are
    skipped (intended for allowlisted policy/guard files that necessarily
    document marker patterns). Private-path and credential checks always
    run regardless.
    """
    violations: list[Violation] = []
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")

    if not skip_text_markers:
        for marker in policy.forbidden_text_markers:
            if marker in text:
                violations.append(Violation(
                    kind=ViolationKind.FORBIDDEN_TEXT_MARKER,
                    path=rel_str,
                    detail=f"contains forbidden text marker: {marker!r}",
                ))

    for pattern in policy.private_path_patterns:
        if pattern.search(text):
            violations.append(Violation(
                kind=ViolationKind.WINDOWS_PRIVATE_PATH,
                path=rel_str,
                detail="contains hardcoded private filesystem path",
            ))
            break

    if policy.credential_regex.search(text):
        violations.append(Violation(
            kind=ViolationKind.LIKELY_CREDENTIAL,
            path=rel_str,
            detail="contains likely credential assignment",
        ))

    return violations


def scan_tree(root: Path, policy: GuardPolicy) -> list[Violation]:
    """Scan a directory tree and return all violations found.

    Traverses every file under *root*, skipping ``.git`` and cache dirs.
    """
    violations: list[Violation] = []
    if not root.is_dir():
        return violations

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue

        rel = path.relative_to(root)
        rel_str = rel.as_posix()

        if _should_skip(rel):
            continue

        ext = path.suffix.lower()
        if ext in policy.forbidden_extensions:
            violations.append(Violation(
                kind=ViolationKind.FORBIDDEN_EXTENSION,
                path=rel_str,
                detail=f"forbidden extension {ext!r}",
            ))
            continue

        matched_dir = _is_in_forbidden_dir(rel, policy.forbidden_directories)
        if matched_dir is not None:
            violations.append(Violation(
                kind=ViolationKind.FORBIDDEN_DIRECTORY,
                path=rel_str,
                detail=f"inside forbidden directory {matched_dir!r}",
            ))

        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        if size > policy.max_file_bytes:
            violations.append(Violation(
                kind=ViolationKind.OVERSIZED_FILE,
                path=rel_str,
                detail=(
                    f"file is {size} bytes "
                    f"(limit {policy.max_file_bytes})"
                ),
            ))

        try:
            raw = path.read_bytes()
        except OSError:
            continue

        skip_text_markers = rel_str in policy.text_marker_allowlist
        violations.extend(
            _scan_text_content(raw, rel_str, policy, skip_text_markers)
        )

    return violations


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def format_violations(violations: list[Violation]) -> list[str]:
    """Format violations into human-readable lines."""
    lines: list[str] = []
    for v in violations:
        lines.append(
            f"[{v.kind.name}] {v.path}: {v.detail}"
        )
    return lines


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """CLI entry point — exits 0 on clean tree, 1 on violations."""
    args = sys.argv[1:] if argv is None else argv
    root = Path(args[0]) if args else Path.cwd()

    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2

    policy = default_policy()
    violations = scan_tree(root, policy)

    if violations:
        print(
            f"FOUND {len(violations)} violation(s):",
            file=sys.stderr,
        )
        for line in format_violations(violations):
            print(line, file=sys.stderr)
        return 1

    print(f"OK: no violations found in {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))