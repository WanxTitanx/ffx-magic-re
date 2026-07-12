# Provenance

## Origin of published material

All documentation, methodology, structural summaries, and test definitions published in this repository are **original work** produced by the project contributors. No content has been copied, extracted, or derived in redistributable form from any game file.

## Research method

Analysis is performed by contributors on their own legally obtained copies of Final Fantasy X HD Remaster. The general workflow is:

1. A contributor installs and owns the game through legitimate channels.
2. The contributor runs analysis tools locally against their own installation.
3. Findings are converted into abstract structural descriptions: field layouts, size counts, dispatch table dimensions, encoding schemas.
4. These abstractions are documented in original prose and test definitions.
5. Raw game data never leaves the contributor's machine.

The repository publishes the resulting abstractions, not the source material they were derived from.

## What the repository contains

- Original format specifications written by contributors.
- Structural reconstruction tests that validate format properties.
- Aggregate statistics derived from analysis (counts, sizes, validation pass rates).
- Methodology guides for reproducing the analysis.
- Hashes used to identify which game versions were analyzed, without including the hashed content.

## What the repository does not contain

- Game binaries, DLL files, or executables.
- Game assets including textures, models, audio, or animation data.
- Decompiled, disassembled, or reverse-translated code.
- Hex dumps, memory dumps, or raw byte sequences.
- Extracted text strings or string tables from game files.
- Any copyrighted material owned by Square Enix or related parties.

## Version independence

This public repository maintains its own git history, commit sequence, and version tags. It is not a subset, export, or mirror of any private development repository. Content published here is curated and authored specifically for public release.

## Hashes and identifiers

Where the documentation references specific game versions for reproducibility, it uses cryptographic hashes of the analyzed files. These hashes are fingerprints that allow contributors to confirm they are analyzing the same game version. They are not the files themselves and cannot be used to reconstruct the original content.
