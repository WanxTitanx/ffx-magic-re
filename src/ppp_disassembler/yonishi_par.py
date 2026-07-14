"""Wave 1 lossless .par parser/serializer.

The Yonishi ``.par`` files are ASCII text (CRLF) with a structured
format: section headers in ``[BRACKETS]``, ``@OPCODE <count>`` directives,
``[TIME frame unk unk unk`` headers, and hex-pair operand lines of
arbitrary width (0..88 bytes observed in the 10-file corpus).

This module guarantees:

* **Lossless round-trip.** ``serialize_par(parse_par(data)) == data`` for
  every valid ``.par`` file. The serializer re-emits preserved raw byte
  spans — it never regenerates text from semantic fields.
* **No fixed operand-width assumption.** Widths are measured from hex
  pairs in each ``[TIME]`` block, never assumed.
* **Preservation of everything**: CRLF, blank lines, unknown sections,
  unknown directives, malformed-but-preserved lines, comments, raw
  ``@OPCODE`` spelling, ``[TIME]`` headers.

Semantic projections (``opcode_blocks``, ``time_block_count``,
``spellings``, ``operand_width_histogram``) are read-only typed views
derived from the ordered node list. They are proven only where syntax
matches; anything ambiguous is preserved as raw bytes without
classification.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

# ---------------------------------------------------------------------------
# Typed error
# ---------------------------------------------------------------------------


class ParParseError(Exception):
    """Typed error for ``.par`` parse failures."""


# ---------------------------------------------------------------------------
# Line classification regexes (context-independent)
# ---------------------------------------------------------------------------

_TIME_HEADER_RE = re.compile(
    rb"^\[TIME\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$",
)
_AT_OPCODE_RE = re.compile(rb"^@([A-Za-z0-9_]+)\s+(\d+)\s*$")
_HEX_PAIR_RE = re.compile(rb"^(?:[0-9a-fA-F]{2}\s+)*[0-9a-fA-F]{2}\s*$")
_SECTION_OPEN_RE = re.compile(rb"^\[[A-Za-z0-9_]+\s*$")
_EQ_HEADER_RE = re.compile(rb"^\[[A-Za-z0-9_]+=")
_DIRECTIVE_RE = re.compile(rb"^\s*@")


LineKind = Literal[
    "time_header",
    "at_opcode",
    "section_open",
    "section_close",
    "eq_header",
    "hex_payload",
    "blank",
    "directive",
    "text",
]

EolKind = Literal["crlf", "lf", "mixed"]


# ---------------------------------------------------------------------------
# Frozen dataclasses (the AST/token model)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LineNode:
    """One physical line of a ``.par`` file, with exact raw bytes.

    ``raw`` includes the original line terminator (``\\r\\n``, ``\\n``,
    or ``b""`` for a final unterminated line). The serializer emits
    ``raw`` verbatim, guaranteeing lossless round-trip.
    """

    kind: LineKind
    raw: bytes
    line_no: int


@dataclass(frozen=True, slots=True)
class TimeBlock:
    """One ``[TIME frame unk unk unk`` header with its operand payload.

    ``operand_lines`` is the tuple of hex-payload ``LineNode`` objects
    immediately following the header (0 or more). ``operand_width_bytes``
    is the measured byte count (sum of hex pairs across all operand
    lines). No width is ever assumed.
    """

    header: LineNode
    operand_lines: tuple[LineNode, ...]
    frame: int
    unk1: int
    unk2: int
    unk3: int
    operand_width_bytes: int


@dataclass(frozen=True, slots=True)
class OpcodeBlock:
    """One ``@OPCODE <count>`` directive with its ``[TIME]`` blocks."""

    header: LineNode
    spelling: str
    declared_count: int
    time_blocks: tuple[TimeBlock, ...]


@dataclass(frozen=True, slots=True)
class ParDoc:
    """Parsed ``.par`` document — lossless model + read-only projections."""

    source_bytes: bytes
    nodes: tuple[LineNode, ...]
    opcode_blocks: tuple[OpcodeBlock, ...]
    time_block_count: int
    spellings: frozenset[str]
    operand_width_histogram: dict[int, int]
    eol_kind: EolKind


@dataclass(frozen=True, slots=True)
class CorpusStats:
    """Aggregate statistics across multiple ``ParDoc`` instances."""

    fixture_count: int
    time_blocks_total: int
    spellings_total: int
    widths_observed: tuple[int, ...]
    width_histogram: dict[int, int]
    total_bytes: int


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _split_lines(data: bytes) -> list[bytes]:
    """Split ``data`` on ``\\n``, preserving the terminator with each segment.

    This is the lossless line splitter: ``b"".join(result) == data``
    always holds. The final segment may lack a terminator if the source
    does not end with ``\\n``.
    """
    result: list[bytes] = []
    start = 0
    for i in range(len(data)):
        if data[i] == 0x0A:
            result.append(data[start : i + 1])
            start = i + 1
    if start < len(data):
        result.append(data[start:])
    return result


def _strip_terminator(raw: bytes) -> bytes:
    """Remove the trailing line terminator (``\\r\\n`` or ``\\n``)."""
    if raw.endswith(b"\r\n"):
        return raw[:-2]
    if raw.endswith(b"\n"):
        return raw[:-1]
    return raw


def _classify_line(content: bytes) -> LineKind:
    """Context-independent classification of a line's content.

    ``content`` is the line bytes WITHOUT the terminator (may still have
    a trailing ``\\r`` if EOL is bare-CR, though that is not observed in
    the corpus).
    """
    stripped = content.rstrip(b"\r")
    if stripped.strip() == b"":
        return "blank"
    if _TIME_HEADER_RE.match(stripped):
        return "time_header"
    if _AT_OPCODE_RE.match(stripped):
        return "at_opcode"
    if stripped == b"]":
        return "section_close"
    if _EQ_HEADER_RE.match(stripped):
        return "eq_header"
    if _SECTION_OPEN_RE.match(stripped):
        return "section_open"
    if _HEX_PAIR_RE.match(stripped.lstrip()):
        return "hex_payload"
    if _DIRECTIVE_RE.match(stripped):
        return "directive"
    return "text"


def _detect_eol_kind(data: bytes) -> EolKind:
    if not data:
        return "lf"
    has_crlf = b"\r\n" in data
    lf_only = data.count(b"\n") - data.count(b"\r\n")
    has_lf = lf_only > 0
    if has_crlf and has_lf:
        return "mixed"
    if has_crlf:
        return "crlf"
    return "lf"


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def parse_par(data: bytes) -> ParDoc:
    """Parse ``data`` into a lossless ``ParDoc``.

    Every byte of ``data`` is preserved in ``ParDoc.nodes`` as raw line
    spans. Semantic projections (opcode blocks, time blocks, spellings,
    width histogram) are derived from the ordered node list.
    """
    raw_lines = _split_lines(data)
    nodes: list[LineNode] = []
    for idx, raw in enumerate(raw_lines):
        content = _strip_terminator(raw)
        kind = _classify_line(content)
        nodes.append(
            LineNode(kind=kind, raw=raw, line_no=idx + 1),
        )

    opcode_blocks = _build_opcode_blocks(nodes)
    time_block_count = sum(
        len(block.time_blocks) for block in opcode_blocks
    )
    spellings = frozenset(
        block.spelling for block in opcode_blocks
    )
    width_counter: Counter[int] = Counter()
    for block in opcode_blocks:
        for tb in block.time_blocks:
            width_counter[tb.operand_width_bytes] += 1
    eol_kind = _detect_eol_kind(data)

    return ParDoc(
        source_bytes=data,
        nodes=tuple(nodes),
        opcode_blocks=tuple(opcode_blocks),
        time_block_count=time_block_count,
        spellings=spellings,
        operand_width_histogram=dict(width_counter),
        eol_kind=eol_kind,
    )


def _build_opcode_blocks(
    nodes: list[LineNode],
) -> list[OpcodeBlock]:
    """Walk ``nodes`` in order and build opcode-block projections.

    An opcode block starts at each ``at_opcode`` line and includes all
    subsequent ``[TIME]`` blocks (each with their hex-payload operands)
    until the next ``at_opcode``, ``section_open``, ``section_close``,
    or ``eq_header`` line.
    """
    blocks: list[OpcodeBlock] = []
    n = len(nodes)
    i = 0
    while i < n:
        node = nodes[i]
        if node.kind != "at_opcode":
            i += 1
            continue
        content = _strip_terminator(node.raw)
        match = _AT_OPCODE_RE.match(content)
        if match is None:
            i += 1
            continue
        spelling = match.group(1).decode("ascii")
        count = int(match.group(2))
        time_blocks: list[TimeBlock] = []
        j = i + 1
        while j < n:
            tnode = nodes[j]
            if tnode.kind == "time_header":
                tb, next_j = _build_time_block(tnode, nodes, j)
                time_blocks.append(tb)
                j = next_j
                continue
            if tnode.kind in (
                "at_opcode",
                "section_open",
                "section_close",
                "eq_header",
            ):
                break
            j += 1
        blocks.append(
            OpcodeBlock(
                header=node,
                spelling=spelling,
                declared_count=count,
                time_blocks=tuple(time_blocks),
            ),
        )
        i = j
    return blocks


def _build_time_block(
    header_node: LineNode,
    nodes: list[LineNode],
    start: int,
) -> tuple[TimeBlock, int]:
    """Build one ``TimeBlock`` starting at ``nodes[start]``.

    Returns the block and the index of the next unprocessed node.
    Operand lines are consecutive ``hex_payload`` nodes after the header.
    """
    content = _strip_terminator(header_node.raw)
    match = _TIME_HEADER_RE.match(content)
    if match is None:
        raise ParParseError(
            f"expected TIME header at line {header_node.line_no}, "
            f"got: {content!r}",
        )
    frame = int(match.group(1))
    unk1 = int(match.group(2))
    unk2 = int(match.group(3))
    unk3 = int(match.group(4))

    operand_lines: list[LineNode] = []
    operand_bytes = 0
    n = len(nodes)
    k = start + 1
    while k < n:
        onode = nodes[k]
        if onode.kind != "hex_payload":
            break
        ocontent = _strip_terminator(onode.raw)
        pairs = ocontent.split()
        operand_bytes += len(pairs)
        operand_lines.append(onode)
        k += 1

    return (
        TimeBlock(
            header=header_node,
            operand_lines=tuple(operand_lines),
            frame=frame,
            unk1=unk1,
            unk2=unk2,
            unk3=unk3,
            operand_width_bytes=operand_bytes,
        ),
        k,
    )


# ---------------------------------------------------------------------------
# Serializer
# ---------------------------------------------------------------------------


def serialize_par(doc: ParDoc) -> bytes:
    """Serialize a ``ParDoc`` back to bytes.

    The serializer concatenates ``node.raw`` for every node in order,
    which is the exact original byte stream. No text regeneration, no
    newline translation, no normalization.
    """
    return b"".join(node.raw for node in doc.nodes)


# ---------------------------------------------------------------------------
# Corpus statistics
# ---------------------------------------------------------------------------


def compute_corpus_stats(docs: Sequence[ParDoc]) -> CorpusStats:
    """Aggregate statistics across a sequence of parsed ``.par`` documents."""
    time_blocks_total = 0
    all_spellings: set[str] = set()
    width_counter: Counter[int] = Counter()
    total_bytes = 0
    for doc in docs:
        time_blocks_total += doc.time_block_count
        all_spellings |= doc.spellings
        for width, count in doc.operand_width_histogram.items():
            width_counter[width] += count
        total_bytes += len(doc.source_bytes)
    widths = tuple(sorted(width_counter.keys()))
    return CorpusStats(
        fixture_count=len(docs),
        time_blocks_total=time_blocks_total,
        spellings_total=len(all_spellings),
        widths_observed=widths,
        width_histogram=dict(width_counter),
        total_bytes=total_bytes,
    )
