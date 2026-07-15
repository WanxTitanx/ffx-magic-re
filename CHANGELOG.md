# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-07-15

### Added

- Structural candidate selector for useful behavior-oriented PPP families.
- Same-size, SHA-gated vector mutation helper limited to a proven 16-byte operand window.
- Synthetic tests covering structural rejection, bounded mutation, tamper-safe restore, and behavior-family selection.

### Notes

- This release contains no game assets, IDs, offsets, runtime captures, game paths, or installed-file tooling.
- Runtime attribution and in-game validation remain local research workflows.
## [0.2.0] - 2026-07-14

### Added

- C2-A raw authoring-payload codecs for COLOR (8B `<4H`) and SCALE (12B `<3I`) families.
- Same-size overlay codec (`c2_effect_overlay`) with SHA-256 verification and restore.
- Yonishi `.par` format parser (`yonishi_par`) — lossless parse/serialize of ASCII authoring files.
- Yonishi `.h` dispatch table parser (`yonishi_dispatch`) — 40-byte entry catalog.
- Yonishi manifest builder (`yonishi_manifest`) — corpus inventory tool.
- Synthetic test suites for all new codecs (22 tests, no game data).

### Changed

- Version bumped to `0.2.0`.
- `__init__.py` updated to export new codec modules.

### Notes

- C2-A codecs are **raw authoring-payload only**. They do not edit runtime 16-byte slot records.
- The bridge from authoring payload to runtime record (C2-B) is documented as research-only.
- No game files, DLLs, IDBs, or proprietary data are included.

## [0.1.0] - 2026-07-11

### Added

- Initial public release of the `ffx-magic-re` research documentation.
- `README.md` with project overview, capability boundaries, and legal notices.
- `CONTRIBUTING.md` defining the contributor workflow and content boundary rules.
- `PROVENANCE.md` documenting the origin and nature of all published material.
- `NOTICE.md` with trademark acknowledgments and disclaimers.
- `docs/research-scope.md` defining in-scope and out-of-scope research areas.
- `docs/reproducibility.md` describing how to verify findings on a lawful installation.
- `docs/status.md` with the current capability matrix and validation evidence.

### Notes

- This public repository maintains its own independent version history. The `0.1.0` tag reflects the first curated public release and is not derived from any private repository version.
- WD3 structural layers (A and B) are documented as tested and validated.
- The C1 slot codec is documented as validated privately, with public API exposure planned for a subsequent release.
- Semantic PPP assembly (C2), structural resize (C3), and new effect generation are documented as research-only at this time.

## 0.3.0 (2026-07-15)
- Add TDD-backed pppColor callback writer (C2-B/T3 offline) and CLI (dry-run / pply / estore).
- Add PPP slot/resource structural parser (Layer C1) reused by the writer for owner validation.
- All fixtures are synthetic; no game files, paths, IDs, hashes or runtime captures are published.

