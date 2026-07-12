# Research Scope

## Purpose

This document defines what the `ffx-magic-re` project researches and, equally important, what it does not research or publish.

## In scope

### Structural format analysis

Understanding the binary layout of the magic effect plugin system. This includes:

- Container format structure: how effect data is organized within the plugin files.
- Dispatch table architecture: how the effect system routes calls to handlers.
- Slot encoding: how typed data slots are encoded within the container.
- Layer decomposition: the progressive analysis layers (A through C) that build understanding from raw structure toward semantic meaning.

### Methodology documentation

Documenting reproducible methods for analyzing the format. This includes:

- Step-by-step analysis procedures.
- Test definitions that validate structural properties.
- Abstract schema definitions for format components.

### Family classification

Categorizing plugins into structural families based on shared characteristics. This includes:

- Classification criteria expressed as abstract rules.
- Coverage statistics across analyzed corpora.
- Clone group identification (plugins sharing structural skeletons).

### Validation evidence

Publishing aggregate validation results. This includes:

- Test pass counts across analyzed corpora.
- Round-trip verification results.
- Structural fidelity metrics.

## Out of scope

### Content redistribution

The project does not publish, host, or link to:

- Game binaries or executables.
- DLL files or compiled plugins.
- Extracted assets of any kind.
- Decompiled, disassembled, or reverse-translated code.
- Hex dumps or raw byte data from game files.

### Circumvention

The project does not research or document methods for:

- Bypassing DRM or copy protection.
- Circumventing technical protection measures.
- Piracy or unauthorized distribution.

### Gameplay modification distribution

While the structural understanding gained through this research could inform modding efforts, this repository itself does not distribute mods, patches, or modified game files. Contributors interested in creating mods should do so independently, using their own lawful installations and respecting applicable terms of service.

### Semantic completion claims

The project does not claim to have fully decoded the meaning of every field in the format. Research-only layers (C2, C3, new effect generation) represent ongoing investigation, not completed work. The `docs/status.md` file is the authoritative source for what has been validated versus what remains research-only.

### Legal analysis

The project does not provide legal opinions on the legality of reverse engineering, modding, or any other activity. Contributors and users are responsible for understanding and complying with applicable laws in their jurisdictions.

## Boundary test

Before submitting any contribution, ask yourself:

1. Does my submission contain any byte sequence from a game file? If yes, do not submit.
2. Could someone reconstruct a game file from my submission? If yes, do not submit.
3. Is my contribution an original description, summary, or methodology? If yes, it is likely in scope.

When in doubt, open an issue describing what you want to contribute in abstract terms before preparing a pull request.
