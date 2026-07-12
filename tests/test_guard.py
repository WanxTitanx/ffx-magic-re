"""Tests for ffx_magic_re.guard — synthetic permitted/denied trees."""
from __future__ import annotations

import pytest
from pathlib import Path

from ffx_magic_re.guard import (
    GuardPolicy,
    Violation,
    ViolationKind,
    default_policy,
    scan_tree,
    format_violations,
)

# Test-only helpers to construct forbidden strings from parts so
# their literal source does not trigger guard self-detection.
_USER = "wan" + "de"


# ---------------------------------------------------------------------------
# Policy tests
# ---------------------------------------------------------------------------

class TestDefaultPolicy:
    def test_policy_is_frozen(self) -> None:
        policy = default_policy()
        with pytest.raises(AttributeError):
            policy.max_file_bytes = 999

    def test_forbidden_extensions_contains_all_required(self) -> None:
        policy = default_policy()
        required = {
            ".dll", ".exe", ".bin", ".i64", ".idb",
            ".id0", ".id1", ".id2", ".nam", ".til",
            ".phyre", ".tm2", ".dds", ".wav", ".fsb", ".png",
        }
        assert required <= policy.forbidden_extensions

    def test_forbidden_directories_contains_all_required(self) -> None:
        policy = default_policy()
        required = {
            "tools", "ExternalLibs", "ffx_reconstructed",
            "docs/reverse", "mods", "work", "backups",
            "compiled_magic", "compiled_test", "textures",
        }
        assert required <= policy.forbidden_directories

    def test_text_markers_contains_decompilation_watermarks(self) -> None:
        policy = default_policy()
        assert "Hex-Rays" in policy.forbidden_text_markers
        assert "Auto-decompiled by" in policy.forbidden_text_markers
        assert "Generated from IDA database" in policy.forbidden_text_markers

    def test_max_file_bytes_is_positive(self) -> None:
        policy = default_policy()
        assert policy.max_file_bytes > 0


# ---------------------------------------------------------------------------
# Clean tree — no violations
# ---------------------------------------------------------------------------

class TestCleanTree:
    def test_clean_py_tree_passes(self, tmp_path: Path) -> None:
        (tmp_path / "main.py").write_text("print('hello')\n", encoding="utf-8")
        (tmp_path / "utils").mkdir()
        (tmp_path / "utils" / "helper.py").write_text(
            "x = 42\n", encoding="utf-8"
        )
        violations = scan_tree(tmp_path, default_policy())
        assert violations == []

    def test_word_decompiled_in_comment_is_allowed(self, tmp_path: Path) -> None:
        (tmp_path / "analysis.py").write_text(
            "# This function was decompiled for study purposes\n"
            "pass\n",
            encoding="utf-8",
        )
        violations = scan_tree(tmp_path, default_policy())
        assert violations == []

    def test_env_var_reference_is_not_credential(self, tmp_path: Path) -> None:
        (tmp_path / "config.py").write_text(
            "api_key = os.environ['API_KEY']\n",
            encoding="utf-8",
        )
        violations = scan_tree(tmp_path, default_policy())
        assert violations == []

    def test_empty_directory_passes(self, tmp_path: Path) -> None:
        violations = scan_tree(tmp_path, default_policy())
        assert violations == []


# ---------------------------------------------------------------------------
# Forbidden extension tests
# ---------------------------------------------------------------------------

class TestForbiddenExtension:
    @pytest.mark.parametrize("ext", [
        ".dll", ".exe", ".bin", ".i64", ".idb",
        ".id0", ".id1", ".id2", ".nam", ".til",
        ".phyre", ".tm2", ".dds", ".wav", ".fsb", ".png",
    ])
    def test_each_forbidden_extension_detected(
        self, tmp_path: Path, ext: str
    ) -> None:
        (tmp_path / f"file{ext}").write_bytes(b"\x00fake")
        violations = scan_tree(tmp_path, default_policy())
        kinds = [v.kind for v in violations]
        assert ViolationKind.FORBIDDEN_EXTENSION in kinds

    def test_case_insensitive_extension(self, tmp_path: Path) -> None:
        (tmp_path / "evil.DLL").write_bytes(b"\x00fake")
        violations = scan_tree(tmp_path, default_policy())
        assert any(
            v.kind == ViolationKind.FORBIDDEN_EXTENSION for v in violations
        )

    def test_allowed_extension_passes(self, tmp_path: Path) -> None:
        (tmp_path / "data.json").write_text("{}\n", encoding="utf-8")
        violations = scan_tree(tmp_path, default_policy())
        assert violations == []


# ---------------------------------------------------------------------------
# Forbidden directory tests
# ---------------------------------------------------------------------------

class TestForbiddenDirectory:
    @pytest.mark.parametrize("forbidden_dir", [
        "tools", "ExternalLibs", "ffx_reconstructed",
        "docs/reverse", "mods", "work", "backups",
        "compiled_magic", "compiled_test", "textures",
    ])
    def test_file_in_forbidden_dir_detected(
        self, tmp_path: Path, forbidden_dir: str
    ) -> None:
        dir_path = tmp_path / Path(forbidden_dir)
        dir_path.mkdir(parents=True)
        (dir_path / "script.py").write_text("pass\n", encoding="utf-8")
        violations = scan_tree(tmp_path, default_policy())
        kinds = [v.kind for v in violations]
        assert ViolationKind.FORBIDDEN_DIRECTORY in kinds

    def test_file_named_like_dir_is_ok(self, tmp_path: Path) -> None:
        """tools.py at root is NOT inside a 'tools/' directory."""
        (tmp_path / "tools.py").write_text("pass\n", encoding="utf-8")
        violations = scan_tree(tmp_path, default_policy())
        assert violations == []

    def test_nested_forbidden_dir_detected(self, tmp_path: Path) -> None:
        (tmp_path / "sub" / "tools").mkdir(parents=True)
        (tmp_path / "sub" / "tools" / "x.py").write_text(
            "pass\n", encoding="utf-8"
        )
        violations = scan_tree(tmp_path, default_policy())
        assert any(
            v.kind == ViolationKind.FORBIDDEN_DIRECTORY for v in violations
        )


# ---------------------------------------------------------------------------
# Text marker tests
# ---------------------------------------------------------------------------

class TestTextMarkers:
    @pytest.mark.parametrize("marker", [
        "Hex-Rays",
        "Auto-decompiled by",
        "Generated from IDA database",
    ])
    def test_marker_detected(self, tmp_path: Path, marker: str) -> None:
        (tmp_path / "leak.py").write_text(
            f"# {marker} something\n", encoding="utf-8"
        )
        violations = scan_tree(tmp_path, default_policy())
        assert any(
            v.kind == ViolationKind.FORBIDDEN_TEXT_MARKER for v in violations
        )

    def test_partial_word_not_flagged(self, tmp_path: Path) -> None:
        """'decompiled' alone must not trigger; only full markers."""
        (tmp_path / "ok.py").write_text(
            "# we decompiled this manually\n", encoding="utf-8"
        )
        violations = scan_tree(tmp_path, default_policy())
        assert violations == []

    def test_allowlisted_file_exempt(self, tmp_path: Path) -> None:
        """Policy/guard files containing markers are exempt."""
        (tmp_path / "scripts").mkdir()
        f = tmp_path / "scripts" / "verify_public_tree.py"
        f.write_text(
            '# contains "Hex-Rays" as policy literal\n', encoding="utf-8"
        )
        policy = default_policy()
        assert "scripts/verify_public_tree.py" in policy.text_marker_allowlist
        violations = scan_tree(tmp_path, policy)
        assert violations == []

    def test_allowlisted_file_still_scanned_for_private_path(
        self, tmp_path: Path
    ) -> None:
        """Allowlist should only skip text-marker check, not private-path check."""
        (tmp_path / "scripts").mkdir()
        f = tmp_path / "scripts" / "verify_public_tree.py"
        _p = f"C:\\Users\\{_USER}\\stuff"
        f.write_text(
            f'p = "{_p}"\n', encoding="utf-8"
        )
        policy = default_policy()
        assert "scripts/verify_public_tree.py" in policy.text_marker_allowlist
        violations = scan_tree(tmp_path, policy)
        assert any(
            v.kind == ViolationKind.WINDOWS_PRIVATE_PATH for v in violations
        )

    def test_allowlisted_file_still_scanned_for_credentials(
        self, tmp_path: Path
    ) -> None:
        """Allowlist should only skip text-marker check, not credential check."""
        (tmp_path / "scripts").mkdir()
        f = tmp_path / "scripts" / "verify_public_tree.py"
        _pwd_parts = "pass", "word"
        _pw = "".join(_pwd_parts)
        f.write_text(
            f'{_pw} = "leaked123"\n', encoding="utf-8"
        )
        policy = default_policy()
        assert "scripts/verify_public_tree.py" in policy.text_marker_allowlist
        violations = scan_tree(tmp_path, policy)
        assert any(
            v.kind == ViolationKind.LIKELY_CREDENTIAL for v in violations
        )

    def test_allowlisted_file_still_gets_text_marker_skipped(
        self, tmp_path: Path
    ) -> None:
        """Allowlist should skip FORBIDDEN_TEXT_MARKER but still check other kinds."""
        (tmp_path / "scripts").mkdir()
        f = tmp_path / "scripts" / "verify_public_tree.py"
        _pwd_parts = "pass", "word"
        _pw = "".join(_pwd_parts)
        f.write_text(
            f'Hex-Rays marker and {_pw} = "secret"\n', encoding="utf-8"
        )
        policy = default_policy()
        assert "scripts/verify_public_tree.py" in policy.text_marker_allowlist
        violations = scan_tree(tmp_path, policy)
        kinds = {v.kind for v in violations}
        assert ViolationKind.FORBIDDEN_TEXT_MARKER not in kinds
        assert ViolationKind.LIKELY_CREDENTIAL in kinds


# ---------------------------------------------------------------------------
# Windows private path tests
# ---------------------------------------------------------------------------

class TestWindowsPrivatePath:
    def test_backslash_path_detected(self, tmp_path: Path) -> None:
        private_path = rf"C:\Users\{_USER}\Documents\stuff"
        (tmp_path / "config.py").write_text(
            f'PATH = "{private_path}"\n', encoding="utf-8",
        )
        violations = scan_tree(tmp_path, default_policy())
        assert any(
            v.kind == ViolationKind.WINDOWS_PRIVATE_PATH for v in violations
        )

    def test_forward_slash_path_detected(self, tmp_path: Path) -> None:
        private_path = f"C:/Users/{_USER}/Documents/stuff"
        (tmp_path / "config.py").write_text(
            f"PATH = '{private_path}'\n", encoding="utf-8",
        )
        violations = scan_tree(tmp_path, default_policy())
        assert any(
            v.kind == ViolationKind.WINDOWS_PRIVATE_PATH for v in violations
        )


# ---------------------------------------------------------------------------
# Credential tests
# ---------------------------------------------------------------------------

class TestCredentials:
    @pytest.mark.parametrize("line", [
        'pass' + 'word = "secret123"',
        'api' + '_key = \'sk-abc123xyz\'',
        'secr' + 'et = "mysecret"',
        'toke' + 'n = "abc123token"',
        'passw' + "d: 'hunter2'",
    ])
    def test_credential_detected(
        self, tmp_path: Path, line: str
    ) -> None:
        (tmp_path / "auth.py").write_text(
            line + "\n", encoding="utf-8"
        )
        violations = scan_tree(tmp_path, default_policy())
        assert any(
            v.kind == ViolationKind.LIKELY_CREDENTIAL for v in violations
        )

    def test_env_lookup_not_flagged(self, tmp_path: Path) -> None:
        (tmp_path / "auth.py").write_text(
            "token = os.environ.get('TOKEN')\n",
            encoding="utf-8",
        )
        violations = scan_tree(tmp_path, default_policy())
        assert violations == []

    def test_empty_string_not_flagged(self, tmp_path: Path) -> None:
        (tmp_path / "auth.py").write_text(
            'password = ""\n', encoding="utf-8"
        )
        violations = scan_tree(tmp_path, default_policy())
        assert violations == []

    def test_short_string_not_flagged(self, tmp_path: Path) -> None:
        (tmp_path / "auth.py").write_text(
            'password = "ab"\n', encoding="utf-8"
        )
        violations = scan_tree(tmp_path, default_policy())
        assert violations == []


# ---------------------------------------------------------------------------
# Oversized file tests
# ---------------------------------------------------------------------------

class TestOversizedFile:
    def test_oversized_file_detected(self, tmp_path: Path) -> None:
        policy = default_policy()
        data = b"x" * (policy.max_file_bytes + 1)
        (tmp_path / "big.txt").write_bytes(data)
        violations = scan_tree(tmp_path, policy)
        assert any(
            v.kind == ViolationKind.OVERSIZED_FILE for v in violations
        )

    def test_exactly_at_limit_passes(self, tmp_path: Path) -> None:
        policy = default_policy()
        data = b"x" * policy.max_file_bytes
        (tmp_path / "exact.txt").write_bytes(data)
        violations = scan_tree(tmp_path, policy)
        assert violations == []


# ---------------------------------------------------------------------------
# Multiple violations
# ---------------------------------------------------------------------------

class TestMultipleViolations:
    def test_all_kinds_in_one_tree(self, tmp_path: Path) -> None:
        (tmp_path / "evil.dll").write_bytes(b"\x00")
        (tmp_path / "tools").mkdir()
        (tmp_path / "tools" / "x.py").write_text("pass\n", encoding="utf-8")
        (tmp_path / "leak.py").write_text(
            '# Hex-Rays decompiler\n', encoding="utf-8"
        )
        _pw_parts = ("pass", "word")
        _pw = "".join(_pw_parts)
        (tmp_path / "cred.py").write_text(
            f'{_pw} = "leaked123"\n', encoding="utf-8"
        )
        _upath = f"C:\\Users\\{_USER}\\test"
        (tmp_path / "winpath.py").write_text(
            f'p = "{_upath}"\n', encoding="utf-8"
        )
        violations = scan_tree(tmp_path, default_policy())
        kinds = {v.kind for v in violations}
        assert ViolationKind.FORBIDDEN_EXTENSION in kinds
        assert ViolationKind.FORBIDDEN_DIRECTORY in kinds
        assert ViolationKind.FORBIDDEN_TEXT_MARKER in kinds
        assert ViolationKind.LIKELY_CREDENTIAL in kinds
        assert ViolationKind.WINDOWS_PRIVATE_PATH in kinds


# ---------------------------------------------------------------------------
# Format violations
# ---------------------------------------------------------------------------

class TestFormatViolations:
    def test_empty_returns_empty(self) -> None:
        assert format_violations([]) == []

    def test_formats_each_violation(self) -> None:
        violations = [
            Violation(
                kind=ViolationKind.FORBIDDEN_EXTENSION,
                path="evil.dll",
                detail="forbidden extension '.dll'",
            ),
        ]
        lines = format_violations(violations)
        assert len(lines) == 1
        assert "evil.dll" in lines[0]
        assert "FORBIDDEN_EXTENSION" in lines[0]


# ---------------------------------------------------------------------------
# .git directory is skipped
# ---------------------------------------------------------------------------

class TestGitSkip:
    def test_git_directory_skipped(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "evil.dll").write_bytes(b"\x00")
        violations = scan_tree(tmp_path, default_policy())
        assert violations == []