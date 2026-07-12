# Contributing to ffx-magic-re

Thank you for your interest in contributing. This project lives or dies on a simple principle: **share knowledge, never share game content.** Please read this document in full before submitting anything.

## Prerequisites

You must:

1. **Own a lawful copy** of Final Fantasy X HD Remaster. All analysis you perform and contribute must be done on your own legally obtained installation.
2. **Understand the boundary.** Everything you submit to this repository must be original analysis, methodology, or structural summaries. Game-owned material of any kind is never accepted.
3. **Read `PROVENANCE.md`** to understand what counts as original research versus redistributed content.

## What you may submit

Contributions fall into these categories:

### Accepted

- **Structural summaries**: aggregate counts, field sizes, layout descriptions, format specifications expressed as original prose or schema definitions.
- **Sanitized hashes**: cryptographic hashes of files or regions you analyzed. Hashes are not the file itself.
- **Validation results**: pass or fail counts from running tests or checks against your local installation. Example: "52 of 52 structural reconstruction tests passed against my Steam installation."
- **Methodology documentation**: step-by-step guides describing how you performed analysis, written in your own words.
- **Test definitions**: structural assertions that verify format properties without embedding source data. Tests should reference offsets and sizes abstractly, not by including the bytes found at those offsets.
- **Tools and scripts**: original code you wrote that performs analysis, provided it does not embed or reproduce game-owned data.

### Never accepted

Do not submit, attach, reference by inclusion, or link to:

- Game executable files, DLL files, or any compiled binary from the game.
- Extracted or converted assets (textures, models, audio, animations).
- Memory dumps, hex dumps, or raw byte sequences from game files.
- Decompiled, disassembled, or reverse-translated code from game binaries.
- Pseudocode derived from game binaries.
- File samples, test fixtures containing real game data, or extracted text strings.
- Links to pirated copies, cracks, or circumvention tools.

Pull requests containing any of the above will be rejected and the content removed.

## Contribution workflow

1. **Analyze locally.** Run your tools against your own installation on your own machine.
2. **Sanitize your output.** Convert findings into structural summaries, counts, hashes, and methodology descriptions. Strip every byte of game-owned data.
3. **Write tests.** Express your structural assertions as tests that verify format properties without including the source bytes.
4. **Submit a pull request.** Include a summary of what you found, how you verified it, and which layer or capability it relates to.
5. **Respond to review.** Maintainers may ask you to clarify, restructure, or remove content that risks crossing the content boundary.

## Public and private repositories

This public repository (`ffx-magic-re`) maintains its own independent commit history and version numbering. A separate private integration repository exists for work that cannot be published due to content restrictions. The two repositories are not mirrors. Commits, versions, and content in this public repository are curated specifically for safe, legal publication.

Do not assume that features validated in private development are automatically available here. The `docs/status.md` file tracks what has been promoted to public visibility.

## Code style

- Write documentation in English.
- Keep prose concise and professional.
- Use tables for structured data like capability matrices.
- Prefer abstract descriptions over concrete values when documenting format layouts in public-facing material.
- Include validation evidence counts when claiming a result.

## Reporting issues

Open an issue for:

- Questions about methodology or reproducibility.
- Discrepancies between documented structure and your own analysis results.
- Suggestions for new research directions within scope.

Do not open issues containing game content. Describe what you found structurally, not what bytes you saw.
