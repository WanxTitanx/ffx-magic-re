# ffx-magic-re

Structural reverse-engineering research for the magic effect plugin system of
Final Fantasy X HD Remaster. Provides a **public toolkit** (`ppp_disassembler`)
for WD3 container parsing and structural analysis, plus **safety guard tools**
(`ffx_magic_re`) for validating public repository content.

This repository publishes **original research methodology, structural analysis
results, and reproducibility guides**. It does not redistribute any game
content, binaries, assets, or copyrighted material.

---

## Installation

Requires Python 3.12+.

```bash
# Install from source (editable, recommended for development)
pip install -e .

# Install with dev dependencies (for running tests)
pip install -e ".[dev]"
```

---

## Tests

```bash
pip install -e ".[dev]"
pytest -q            # 199+ tests, no output noise
pytest -v            # verbose, per-test names
pytest --tb=long     # full tracebacks on failure
```

No test warnings expected. All tests use **synthetic fixtures** — no game data
is bundled or required.

---

## CLI: verify-public-tree (content guard)

Before committing or pushing to any public branch, run the leak guard:

```bash
verify-public-tree .            # scan current directory
verify-public-tree /path/to/repo
python scripts/verify_public_tree.py .
```

Exit codes:

| Code | Meaning |
|------|---------|
| 0    | No violations — tree is safe |
| 1    | Violations found (see stderr) |
| 2    | Bad arguments |

The guard checks:

| Check | Example trigger |
|---|---|
| Forbidden extensions | `.dll`, `.exe`, `.bin`, `.i64`, `.phyre`, `.png` |
| Forbidden directories | `tools/`, `ExternalLibs/`, `ffx_reconstructed/` |
| Text markers (decompiler watermarks) | `Hex-Rays`, `Auto-decompiled by` |
| Private filesystem paths | `C:\Users\...` or `/Users/...` |
| Credential-like assignments | `password = "**"` |
| Oversized files | > 256 KiB |

Allowlisted files (guard, sync, policy, tests) skip text-marker scanning
only — all other checks still apply. See `src/ffx_magic_re/guard.py` for
the full policy definition.

---

## Python API

### WD3 container parsing

```python
from ppp_disassembler import parse_wd3, find_wd3_container

# Load data from any source (bytes must be provided by the caller)
with open("my_data.bin", "rb") as f:
    data = f.read()

# Find and parse a WD3 container
offset = find_wd3_container(data)
if offset >= 0:
    container = parse_wd3(data, offset)
    print(container.summary())
else:
    print("No WD3 container found")
```

### WD3 structural reconstruction (round-trip)

```python
from ppp_disassembler import serialize_wd3_blob

# Serialize a parsed container back to bytes
blob = serialize_wd3_blob(container)
assert blob == data[: container.total_size]  # byte-identical
```

### Instruction decoding

```python
from ppp_disassembler import disassemble_wd3

disassemble_wd3(container, data)
for stream in container.streams:
    for instr in stream.instructions:
        print(instr)
```

### Hex dump with opcode annotations

```python
from ppp_disassembler.render import hex_dump

print(hex_dump(data, offset=0x100, length=64, annotate_opcodes=True))
```

### Payload layout and ownership

```python
from ppp_disassembler import compute_payload_layout, compute_ownership_spans

layout = compute_payload_layout(container)
print(f"Prefix: {layout.prefix}, Body: {layout.body}")

spans = compute_ownership_spans(container)
for span in spans:
    print(f"  0x{span.start:x}-0x{span.end:x} owned by stream(s) {span.owners}")
```

### Tree guard (programmatic)

```python
from ffx_magic_re.guard import scan_tree, default_policy, format_violations
from pathlib import Path

policy = default_policy()
violations = scan_tree(Path("."), policy)
if violations:
    for line in format_violations(violations):
        print(line)
```

### Sync preview

```python
from ffx_magic_re.sync import load_manifest, preview_sync
from pathlib import Path

manifest = load_manifest(Path("examples/sync_manifest.json"))
for line in preview_sync(manifest):
    print(line)
```

---

## Capability boundaries

| Layer | Description | Status |
|-------|-------------|--------|
| **WD3 structural (A)** | Header, pointer table, and stream header reconstruction | Tested |
| **WD3 physical (B)** | Physical payload mapping of the container body | Tested |
| **C1 slot codec** | Typed slot encoding and decoding | Validated privately; public API planned |
| **C2 semantic assembly** | Callback payload semantics, operand interpretation | Research only |
| **C3 resize and growth** | Structural growth beyond original boundaries | Research only |
| **New effect generation** | Authoring entirely new visual effects | Research only |

See `docs/status.md` for the full capability matrix.

---

## What this project is not

- **Not affiliated with** Square Enix or any related entity.
- **Does not distribute** game executables, DLL files, assets, decompiled code,
  disassembly, hex dumps, or any copyrighted material.
- **Does not provide tools** for circumventing copy protection or DRM.
- **Makes no legal claims or warranties.** See `NOTICE.md` and `PROVENANCE.md`.

---

## Repository structure

```
ffx-magic-re/
  LICENSE              MIT license
  README.md            This file
  PUBLIC_UPSTREAM.md   Publication policy, sync workflow, and versioning
  CONTRIBUTING.md      Safe contribution guidelines
  PROVENANCE.md        Origin of all published material
  NOTICE.md            Trademarks, attributions, disclaimers
  CHANGELOG.md         Version history
  pyproject.toml       Build configuration
  .github/workflows/   CI (guard + test + build on 3.12/3.13)
  docs/
    research-scope.md  What is and is not in scope
    reproducibility.md How to verify findings on your own installation
    status.md          Current capability matrix
  scripts/
    verify_public_tree.py  CLI wrapper for the tree guard
    sync_from_private.py   Manifest-driven sync preview (dry-run only)
  src/
    ppp_disassembler/   WD3 container parser and analysis toolkit
    ffx_magic_re/       Guard and sync tools
  tests/               Test suite (199+ tests, all synthetic)
```

---

## Public and private versioning

This public repository maintains its **own independent version number**
(`__version__ = "0.1.0"` in both `src/ffx_magic_re/__init__.py` and
`src/ppp_disassembler/__init__.py`), separate from any private development
or integration repository. Public versions must never be confused with
private build numbers.

See `PUBLIC_UPSTREAM.md` for the full publication policy and sync workflow.

---

## License

MIT — see `LICENSE`. Trademarks are owned by their respective holders —
see `NOTICE.md`.
