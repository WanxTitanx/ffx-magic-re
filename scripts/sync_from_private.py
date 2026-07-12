#!/usr/bin/env python3
"""Manifest-driven one-way sync preview CLI.

This tool NEVER copies files. It only validates a review manifest
and prints a preview of what a future sync would do.

Usage:
    python scripts/sync_from_private.py --manifest <path> --dry-run

Without --dry-run or --manifest, the tool refuses to operate.
"""
from __future__ import annotations

import sys
from pathlib import Path

_src = Path(__file__).resolve().parent.parent / "src"
if _src.is_dir():
    sys.path.insert(0, str(_src))

from ffx_magic_re.sync import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))