"""Payload layout and stream ownership-span computation for WD3 containers."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from .stream import StreamInfo


class PayloadMapError(ValueError):
    """Raised when payload layout invariants are violated."""


class PayloadContainer(Protocol):
    """Protocol for payload-layout computation."""
    total_size: int
    stream_header_offsets: list[int]
    streams: list[StreamInfo]


@dataclass(frozen=True, slots=True)
class PayloadLayout:
    """Layout of a WD3 blob divided into three regions.

    Attributes:
        prefix: (start, end) of the structural prefix.
        post_prefix_gap: (start, end) of the gap between structure and body.
        body: (start, end) of the raw byte body.
    """
    prefix: tuple[int, int]
    post_prefix_gap: tuple[int, int]
    body: tuple[int, int]

    @property
    def total_size(self) -> int:
        return self.body[1]

    @property
    def body_size(self) -> int:
        return self.body[1] - self.body[0]


@dataclass(frozen=True, slots=True)
class OwnershipSpan:
    """A body region owned by one or more streams.

    Attributes:
        start: Start offset (relative to blob base).
        end: End offset (exclusive).
        owners: Stream indices that cover this region.
    """
    start: int
    end: int
    owners: tuple[int, ...]

    @property
    def size(self) -> int:
        return self.end - self.start


def compute_payload_layout(container: PayloadContainer) -> PayloadLayout:
    """Compute the three-region layout (prefix, gap, body) of a WD3 container.

    Args:
        container: An object implementing the ``PayloadContainer`` protocol.

    Returns:
        A ``PayloadLayout`` with byte-offset boundaries.

    Raises:
        PayloadMapError: If stream boundaries overlap or exceed ``total_size``.
    """
    if not container.stream_header_offsets or not container.streams:
        raise PayloadMapError("WD3 container has no stream structure")

    prefix_end = max(offset + 32 for offset in container.stream_header_offsets)
    stream_starts = [stream.start_offset for stream in container.streams]
    body_start = min(stream_starts)

    if prefix_end > body_start:
        raise PayloadMapError("stream start overlaps the structural prefix")
    if body_start >= container.total_size:
        raise PayloadMapError("stream start is outside total_size")

    for stream in container.streams:
        if not body_start <= stream.start_offset < container.total_size:
            raise PayloadMapError(
                f"stream start is outside the WD3 body: stream {stream.index}"
            )
        if not stream.start_offset < stream.end_offset <= container.total_size:
            raise PayloadMapError(
                f"stream end is outside total_size: stream {stream.index}"
            )

    return PayloadLayout(
        prefix=(0, prefix_end),
        post_prefix_gap=(prefix_end, body_start),
        body=(body_start, container.total_size),
    )


def compute_ownership_spans(container: PayloadContainer) -> Sequence[OwnershipSpan]:
    """Compute per-region stream ownership spans for the body.

    Partitions the body into intervals, each owned by the set of streams
    whose offset range covers it.

    Args:
        container: An object implementing the ``PayloadContainer`` protocol.

    Returns:
        Ordered list of ``OwnershipSpan`` covering the body.

    Raises:
        PayloadMapError: If an orphan interval (no owner) exists.
    """
    layout = compute_payload_layout(container)
    boundaries: set[int] = {layout.body[0], layout.body[1]}
    for stream in container.streams:
        boundaries.add(stream.start_offset)
        boundaries.add(stream.end_offset)

    ordered = sorted(boundaries)
    spans: list[OwnershipSpan] = []
    for start, end in zip(ordered, ordered[1:]):
        idxs = sorted(
            stream.index
            for stream in container.streams
            if stream.start_offset <= start and end <= stream.end_offset
        )
        if not idxs:
            raise PayloadMapError(
                f"orphan body interval 0x{start:X}-0x{end:X}"
            )
        spans.append(OwnershipSpan(start=start, end=end, owners=tuple(idxs)))
    return spans
