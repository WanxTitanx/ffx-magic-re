"""
C2 COLOR-family authoring-payload codec.

Lossless parse and serialize of the raw 8-byte COLOR-family payload
(COLOR, COLMOVE, COLACCELE) as four 16-bit little-endian words,
preserving bit patterns exactly.

RAW AUTHORING CODEC ONLY
------------------------
This module operates on the 8-byte payload bytes authored in Yonishi
.par files and embedded verbatim in compiled eff_NNNN.bin /
magic_NNNN.dll .data sections (proven by the 3-chain audit in
work/layer_c/C2_YONISHI_CODEC_AUDIT.md).

It does NOT interpret, project, or edit the 16-byte runtime slot
record that PPP callback handlers consume (argument+8..+14 inside a
16-byte record per C2_HANDLER_SCHEMAS.md). The 8->16 byte runtime
expansion bridge is separately gated and explicitly out of scope.

Evidence base: 87 exact COLOR-family entries across 8 .par sources,
2 mag_ids (0154 + 0346), 20/20 pdt+eff+pc 3-chain, 92.2% multi-control
clean. See work/layer_c/C2_YONISHI_CODEC_AUDIT_FIXTURES.json.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import override

_COLOR_STRUCT = struct.Struct("<4H")
COLOR_PAYLOAD_SIZE = _COLOR_STRUCT.size


@dataclass(frozen=True, slots=True)
class ColorPayload:
    """Four unsigned 16-bit little-endian words from a COLOR-family payload.

    The value type carries ONLY the raw bit patterns. Opcode (COLOR /
    COLMOVE / COLACCELE), .par source, mag_id, and byte offsets are
    provenance metadata that live outside this type — callers retain
    them alongside the payload as needed.
    """

    w0: int
    w1: int
    w2: int
    w3: int

    @property
    def words(self) -> tuple[int, int, int, int]:
        return (self.w0, self.w1, self.w2, self.w3)


@dataclass(frozen=True, slots=True)
class ColorPayloadSizeError(ValueError):
    actual_size: int
    expected_size: int

    @override
    def __str__(self) -> str:
        return (
            f"COLOR payload must be exactly {self.expected_size} bytes; "
            f"got {self.actual_size}"
        )


def parse_color_payload(data: bytes) -> ColorPayload:
    """Parse 8 raw bytes into four little-endian u16 words.

    Raises ColorPayloadSizeError if len(data) != 8.
    """
    if len(data) != COLOR_PAYLOAD_SIZE:
        raise ColorPayloadSizeError(
            actual_size=len(data),
            expected_size=COLOR_PAYLOAD_SIZE,
        )
    w0, w1, w2, w3 = _COLOR_STRUCT.unpack(data)
    return ColorPayload(w0=w0, w1=w1, w2=w2, w3=w3)


def serialize_color_payload(payload: ColorPayload) -> bytes:
    """Serialize four u16 words back to the exact 8 raw bytes."""
    return _COLOR_STRUCT.pack(payload.w0, payload.w1, payload.w2, payload.w3)
