"""Tests for scripts/verify_public_tree.py CLI integration."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "verify_public_tree.py"


def _run_cli(root: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(_SCRIPT), str(root)],
        capture_output=True,
    )


class TestVerifyCLIClean:
    def test_clean_tree_exits_zero(self, tmp_path: Path) -> None:
        (tmp_path / "main.py").write_text("pass\n", encoding="utf-8")
        result = _run_cli(tmp_path)
        assert result.returncode == 0

    def test_stdout_contains_ok(self, tmp_path: Path) -> None:
        (tmp_path / "main.py").write_text("pass\n", encoding="utf-8")
        result = _run_cli(tmp_path)
        assert b"OK" in result.stdout or b"OK" in result.stderr


class TestVerifyCLIViolations:
    def test_forbidden_ext_exits_one(self, tmp_path: Path) -> None:
        (tmp_path / "evil.dll").write_bytes(b"\x00")
        result = _run_cli(tmp_path)
        assert result.returncode == 1

    def test_violation_in_stderr(self, tmp_path: Path) -> None:
        (tmp_path / "evil.exe").write_bytes(b"\x00")
        result = _run_cli(tmp_path)
        assert b"FORBIDDEN_EXTENSION" in result.stderr

    def test_text_marker_exits_one(self, tmp_path: Path) -> None:
        (tmp_path / "leak.py").write_text(
            "# Hex-Rays\n", encoding="utf-8"
        )
        result = _run_cli(tmp_path)
        assert result.returncode == 1

    def test_credential_exits_one(self, tmp_path: Path) -> None:
        _pwd_parts = "pass", "word"
        _pw = "".join(_pwd_parts)
        (tmp_path / "auth.py").write_text(
            f'{_pw} = "secret123"\n', encoding="utf-8"
        )
        result = _run_cli(tmp_path)
        assert result.returncode == 1


class TestVerifyCLINoArgs:
    def test_no_args_uses_cwd(self, tmp_path: Path, monkeypatch) -> None:
        (tmp_path / "main.py").write_text("pass\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        result = subprocess.run(
            [sys.executable, str(_SCRIPT)],
            capture_output=True,
        )
        assert result.returncode == 0


# ---------------------------------------------------------------------------
# python -m ffx_magic_re.guard — must not emit RuntimeWarning
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent


class TestModuleRunNoRuntimeWarning:
    """python -m ffx_magic_re.guard must not emit RuntimeWarning.

    The package __init__ must not eagerly import guard, otherwise
    'python -m ffx_magic_re.guard' re-executes the module as __main__
    after it is already in sys.modules, triggering a RuntimeWarning.
    """

    def test_m_run_guard_no_runtime_warning(self, tmp_path: Path) -> None:
        (tmp_path / "main.py").write_text("pass\n", encoding="utf-8")
        env = dict(os.environ)
        pythonpath = str(_REPO_ROOT / "src")
        existing = env.get("PYTHONPATH", "")
        if existing:
            pythonpath = pythonpath + os.pathsep + existing
        env["PYTHONPATH"] = pythonpath
        result = subprocess.run(
            [
                sys.executable, "-W", "error::RuntimeWarning",
                "-m", "ffx_magic_re.guard", str(tmp_path),
            ],
            capture_output=True,
            env=env,
        )
        assert result.returncode == 0, (
            f"exit={result.returncode}\n"
            f"stdout={result.stdout.decode(errors='replace')}\n"
            f"stderr={result.stderr.decode(errors='replace')}"
        )