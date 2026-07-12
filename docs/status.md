# Capability Status

This document tracks the maturity level of each research layer. It is the authoritative source for what has been validated versus what remains in research stage.

## Status definitions

| Status | Meaning |
|--------|---------|
| **Tested** | Structural work is implemented, tested with a full test suite, and validated against the game corpus. Round-trip identity is proven. |
| **Validated (private)** | Implementation exists and passes full validation, but the public API has not yet been released in this repository. Promotion to public is planned. |
| **Research only** | Investigation is ongoing. No validated implementation or writer exists. Findings are preliminary and should not be relied upon for correctness. |

## Capability matrix

### WD3 structural container

The WD3 container is the binary structure that holds magic effect data within the plugin files. Analysis proceeds in layers.

| Layer | Component | Status | Evidence |
|-------|-----------|--------|----------|
| A | Header and pointer table reconstruction | Tested | Full test suite passing. Reconstruction produces byte-identical output across the analyzed corpus without copying source bytes. |
| A | Stream header reconstruction | Tested | Full test suite passing. All stream headers correctly re-emitted. |
| A | Gap and reserved field preservation | Tested | Structural gaps and reserved fields preserved through reconstruction. |
| B | Physical payload mapping | Tested | Full test suite passing. Every byte of the container body accounted for exactly once. Span coverage is complete with no gaps or overlaps. |
| B | Container reconstruction without source template | Tested | Full reconstruction possible without receiving source bytes or using original data as a template. |

### PPP dispatch system

The PPP dispatch system is the mechanism by which the effect system routes execution to handlers within the container.

| Layer | Component | Status | Evidence |
|-------|-----------|--------|----------|
| C1 | Slot encoding and decoding | Validated (private) | Full test suite passing. Round-trip identity proven across the analyzed corpus. Public API exposure planned for a subsequent release. |
| C1 | Resource blob relocation | Validated (private) | Root, section, program, and slot traversal verified across the full corpus. |
| C2 | Callback payload semantics | Research only | Layout dimensions identified from reference material. Per-handler semantics, field meanings, and operand interpretation remain under investigation. No validated writer exists. |
| C2 | Handler dispatch table extraction | Research only | Dispatch table structure identified in reference material. Reproducible extraction per handler has not yet been proven. |
| C3 | Structural resize and growth | Research only | Depends on C2 completion. No validated implementation. No evidence that structural boundaries can be safely extended. |
| New effect generation | Authoring new effects from scratch | Research only | No validated pipeline exists. All claims about generating new magic effects are preliminary and unproven. |

## Family classification

Structural classification of the plugin corpus into families based on shared characteristics.

| Component | Status | Evidence |
|-----------|--------|----------|
| Family identification | Tested | Full corpus classified into four structural families. Classification criteria documented. |
| Clone group detection | Tested | Plugins sharing structural skeletons identified. Group membership verified through comparative analysis. |
| Color candidate scanning | Partial | Candidate data regions identified. Whether each candidate represents an active visual property is not fully proven. |

## Important caveats

- **Validated (private)** does not mean available in this public repository. It means the implementation exists and has passed validation in a private development context. Check this document for promotion status.
- **Tested** refers to structural correctness as verified by round-trip and coverage tests. It does not imply that the semantic meaning of all fields within the structure is fully understood.
- **Research only** findings are preliminary. They may be revised, retracted, or proven incorrect as investigation continues. Do not build tools or make decisions based on research-only layers without independent verification.
- The public repository version (`0.1.0`) is independent of any private development versioning. Feature availability here is curated separately.

## Versioning of this document

This document is updated whenever a layer changes status. The date of the most recent update should be visible in the git history of this file.
