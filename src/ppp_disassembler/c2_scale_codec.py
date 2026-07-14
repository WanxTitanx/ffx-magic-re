"""
C2 SCALE-family authoring-payload codec.

Lossless parse and serialize of the raw 12-byte SCALE-family payload
(SCALE, SCLMOVE, SCLACCELE) as three 32-bit little-endian words,
preserving bit patterns exactly.

RAW AUTHORING CODEC ONLY
------------------------
This module operates on the 12-byte payload bytes authored in Yonishi
.par files and embedded verbatim in compiled eff_NNNN.bin /
magic_NNNN.dll .data sections (proven by the 3-chain audit in
work/layer_c/C2_SCALE_YONISHI_AUDIT.md).

It does NOT interpret, project, or edit any runtime slot record that
PPP callback handlers consume. The 12-byte payload is purely a raw
authoring artifact — no offset parameter, no handler index claim,
no XYZ/axis semantic labels. The bridge to any runtime record is
separately gated and explicitly out of scope.

Evidence base: 79 distinct unique_evidence SCALE-family payloads
across 9 .par sources, 2 mag_ids (0154 + 0346), 310 three-chain
matches, 100% negative-control clean (0/5 hits for all 157 entries).
See work/layer_c/C2_SCALE_LEVEL_A_PROMOTION_REVIEW.md and
work/layer_c/C2_YONISHI_CODEC_AUDIT_FIXTURES.json.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import override

_SCALE_STRUCT = struct.Struct("<3I")
SCALE_PAYLOAD_SIZE = _SCALE_STRUCT.size


@dataclass(frozen=True, slots=True)
class ScalePayload:
    """Three unsigned 32-bit little-endian words from a SCALE-family payload.

    The value type carries ONLY the raw bit patterns. Opcode (SCALE /
    SCLMOVE / SCLACCELE), .par source, mag_id, and byte offsets are
    provenance metadata that live outside this type — callers retain
    them alongside the payload as needed.
    """

    w0: int
    w1: int
    w2: int


@dataclass(frozen=True, slots=True)
class ScalePayloadSizeError(ValueError):
    actual_size: int
    expected_size: int

    @override
    def __str__(self) -> str:
        return (
            f"SCALE payload must be exactly {self.expected_size} bytes; "
            f"got {self.actual_size}"
        )


def parse_scale_payload(data: bytes) -> ScalePayload:
    """Parse 12 raw bytes into three little-endian u32 words.

    Raises ScalePayloadSizeError if len(data) != 12.
    """
    if len(data) != SCALE_PAYLOAD_SIZE:
        raise ScalePayloadSizeError(
            actual_size=len(data),
            expected_size=SCALE_PAYLOAD_SIZE,
        )
    w0, w1, w2 = _SCALE_STRUCT.unpack(data)
    return ScalePayload(w0=w0, w1=w1, w2=w2)


def serialize_scale_payload(payload: ScalePayload) -> bytes:
    """Serialize three u32 words back to the exact 12 raw bytes."""
    return _SCALE_STRUCT.pack(payload.w0, payload.w1, payload.w2)
