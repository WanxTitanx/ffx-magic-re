# Reproducibility

## Principle

Every structural claim in this repository should be independently verifiable by any contributor who owns a lawful copy of the game. This document describes how to reproduce the published findings on your own installation.

## Prerequisites

- A legally obtained copy of Final Fantasy X HD Remaster, installed on your own machine.
- Familiarity with command-line tools and basic binary analysis concepts.
- Willingness to follow the content boundary rules in `CONTRIBUTING.md`.

## General workflow

### 1. Identify your game version

Compute a cryptographic hash of the files you intend to analyze. Compare these hashes against the versions referenced in `docs/status.md` to confirm you are analyzing the same release. Hashes identify versions without transmitting content.

### 2. Run structural analysis locally

Apply the documented structural analysis methods to your local installation. Each layer documented in this repository has a corresponding methodology description:

- **Layer A (WD3 structural)**: Verify header, pointer table, and stream header reconstruction against your installation. Confirm that the reconstruction produces a byte-identical output when compared to the original structure.
- **Layer B (WD3 physical)**: Verify the physical payload mapping covers every byte of the container body exactly once with the documented span count.
- **Layer C1 (slot codec)**: Verify slot encoding and decoding round-trips for the typed slot format.

### 3. Run validation tests

Execute the test suite against your local installation. Tests are designed to validate structural properties without embedding source data. Report your pass or fail counts.

### 4. Report results

Submit your validation results as aggregate statistics. For example:

> "Layer A reconstruction: 52 of 52 tests passed against my Steam installation."
> "Layer B payload map: 61 of 61 spans verified covering the full body."

Do not include the bytes, file contents, or any game-owned data in your report.

## Sanity checks

When reproducing structural analysis, apply these checks to confirm validity:

- **Round-trip identity**: Reconstructing a structure and comparing it back to the original should produce an identical result. Any difference indicates either a bug in the reconstruction logic or a misunderstanding of the format.
- **Full coverage**: Physical payload mappings should account for every byte in the target region exactly once. Gaps or overlaps indicate an incomplete model.
- **Corpus consistency**: Structural properties that hold across the full set of analyzed files are stronger evidence than properties observed in a single file. Report how many files your analysis covered.

## Reporting discrepancies

If your local analysis produces results that differ from the published findings:

1. Double-check that you are analyzing the same game version (compare hashes).
2. Verify that you are applying the documented methodology correctly.
3. Open an issue describing the discrepancy in structural terms. State which layer, what you expected, and what you observed as an aggregate result.

Do not include raw data in the issue. Describe the structural difference abstractly.

## What reproducibility does not mean

Reproducibility confirms that the documented structural model is consistent across installations and contributors. It does not guarantee that the model captures the full semantic meaning of every field. Research-only layers remain incomplete by definition, and validation of structural layers does not imply validation of semantic interpretation.
