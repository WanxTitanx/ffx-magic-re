# Public Upstream Policy

This document defines the policy, format, and workflow for publishing
research findings from private analysis into the `ffx-magic-re` public
repository.

## Purpose

The public repository publishes **original research methodology, structural
analysis results, and reproducibility guides** only. It never contains:

- Game binaries, executables, or DLL files
- Extracted assets, textures, sounds, or models
- Decompiled, disassembled, or reverse-translated source code
- Hex dumps or raw byte data from game files
- Absolute private filesystem paths
- Credentials or API keys

## Sync Preview Workflow

All publication from private repositories goes through a deterministic
manifest-based preview before any copy operation:

1. The private repo maintains a review manifest JSON file listing each
   candidate entry with its source, destination, and human review note.
2. The public-side tool `sync_from_private.py` (in `scripts/`) loads the
   manifest, validates its structure, and prints a dry-run preview.
   It **never copies files** — the `--dry-run` flag is mandatory.
3. A human reviews the printed preview and copies entries manually only
   after verifying no forbidden content would be published.

### Example manifest

A complete, validated example is tracked at
[`examples/sync_manifest.json`](examples/sync_manifest.json).
Copy it, edit the `source_root` and entries for your private layout,
then run the dry-run preview:

```bash
python scripts/sync_from_private.py \
  --manifest examples/sync_manifest.json --dry-run
```

## Guard Verification

Before every commit, run the tree guard:

```bash
python scripts/verify_public_tree.py .
```

This scans all tracked and untracked files for:

| Check | What it catches |
|---|---|
| Forbidden extensions | `.dll`, `.exe`, `.bin`, `.i64`, `.idb`, `.phyre`, `.dds`, `.png`, etc. |
| Forbidden directories | `tools/`, `ExternalLibs/`, `ffx_reconstructed/`, `docs/reverse/`, etc. |
| Text markers | `Hex-Rays`, `Auto-decompiled by`, `Generated from IDA database` |
| Private paths | `C:\Users\...`, `/Users/...` |
| Credentials | `password = "**"`, `api_key = '**'`, `token = "**"` |
| Oversized files | Files exceeding 256 KiB |

The guard policy is defined in `src/ffx_magic_re/guard.py`. Allowlisted
files (guard, sync, policy, tests) are exempt from text-marker scanning
only — all other checks still apply to them.

## Versioning

The public repository maintains its **own independent version number**
(`__version__ = "0.1.0"` in both `src/ffx_magic_re/__init__.py` and
`src/ppp_disassembler/__init__.py`), separate from any private
development or integration repository. This is a policy requirement:
public versions must never be confused with private build numbers.

## Commit History Convention

Public history should consist of two logical commit groups:

1. **Package**: The toolkit source, tests, project configuration,
   guard/sync tools, and build artifacts (CI, LICENSE, README).
2. **Evidence and documentation**: Research methodology documents,
   reproducibility guides, status matrix, and all supporting material.

This separation keeps the package self-contained and makes it easy to
review what changed between releases.

## Contributing

See `CONTRIBUTING.md` for the contribution workflow and legal
requirements. All contributions are subject to the same content
policy: no game assets, no decompiled code, no private paths.
