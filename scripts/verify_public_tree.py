#!/usr/bin/env python3
"""Public repository tree guard CLI.

Run before any commit or push to verify no forbidden content
has leaked into the public tree.

Usage:
    python scripts/verify_public_tree.py [root_dir]

Exit codes:
    0 — no violations found
    1 — violations found
    2 — bad arguments
"""
from __future__ import annotations

import sys
from pathlib import Path

_src = Path(__file__).resolve().parent.parent / "src"
if _src.is_dir():
    sys.path.insert(0, str(_src))

from ffx_magic_re.guard import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))