"""WD3 blob serialization — structure + gap + body concatenation."""

from __future__ import annotations

from typing import Protocol

from .stream import StreamInfo
from .wd3_writer import Wd3Structure, Wd3StructureError, serialize_wd3_structure


class Wd3Blob(Wd3Structure, Protocol):
    """Protocol extending ``Wd3Structure`` with the payload fields."""
    post_prefix_gap: bytes
    body: bytes
    streams: list[StreamInfo]


def serialize_wd3_blob(container: Wd3Blob) -> bytes:
    """Serialize the complete WD3 blob (structure + gap + body).

    Validates that the concatenated fields match ``container.total_size``.

    Args:
        container: An object implementing the ``Wd3Blob`` protocol.

    Returns:
        The complete byte-exact WD3 blob.

    Raises:
        Wd3StructureError: If the serialized size does not match ``total_size``.
    """
    structure = serialize_wd3_structure(container)
    actual_size = len(structure) + len(container.post_prefix_gap) + len(container.body)
    if actual_size != container.total_size:
        raise Wd3StructureError(
            f"serialized fields total {actual_size} bytes, "
            + f"expected total_size {container.total_size}"
        )
    return structure + container.post_prefix_gap + container.body
