from __future__ import annotations

import argparse
import json
from pathlib import Path

from .c2_b_writer import (
    CallbackMutationResult,
    apply_callback_color,
    dry_run_callback_color,
    restore_callback_color,
)
from .c2_color_codec import ColorPayload


def _parse_offset(text: str) -> int:
    return int(text, 0)


def _parse_words(text: str) -> ColorPayload:
    parts = text.split(",")
    if len(parts) != 4:
        raise argparse.ArgumentTypeError("--words requires four comma-separated u16 values")
    try:
        words = tuple(int(part, 0) for part in parts)
    except ValueError as error:
        raise argparse.ArgumentTypeError("--words values must be integers") from error
    if any(word < 0 or word > 0xFFFF for word in words):
        raise argparse.ArgumentTypeError("--words values must be u16")
    return ColorPayload(*words)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="c2-b")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("dry-run", "apply"):
        command = commands.add_parser(name)
        command.add_argument("target_dll", type=Path)
        command.add_argument("--data-offset", required=True, type=_parse_offset)
        command.add_argument("--expected-record-sha256", required=True)
        command.add_argument("--words", required=True, type=_parse_words)
    restore = commands.add_parser("restore")
    restore.add_argument("target_dll", type=Path)
    restore.add_argument("--data-offset", required=True, type=_parse_offset)
    restore.add_argument("--expected-patched-record-sha256", required=True)
    restore.add_argument("--expected-original-record-sha256", required=True)
    return parser


def _result_json(result: CallbackMutationResult) -> str:
    return json.dumps(
        {
            "backup_path": str(result.backup_path) if result.backup_path else None,
            "changed_offsets": list(result.changed_offsets),
            "record_sha256": result.record_sha256,
            "restored": result.restored,
        },
        sort_keys=True,
    )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "dry-run":
        result = dry_run_callback_color(
            target_path=args.target_dll,
            data_offset=args.data_offset,
            expected_record_sha256=args.expected_record_sha256,
            replacement=args.words,
        )
    elif args.command == "apply":
        result = apply_callback_color(
            target_path=args.target_dll,
            data_offset=args.data_offset,
            expected_record_sha256=args.expected_record_sha256,
            replacement=args.words,
        )
    else:
        result = restore_callback_color(
            target_path=args.target_dll,
            data_offset=args.data_offset,
            expected_patched_record_sha256=args.expected_patched_record_sha256,
            expected_original_record_sha256=args.expected_original_record_sha256,
        )
    print(_result_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
