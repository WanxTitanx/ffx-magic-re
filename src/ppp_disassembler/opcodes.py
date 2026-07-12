"""PPP Opcode Table — 36 EgoVM opcode entries + 6 alpha function selectors.

Data-decoded structural layout of the EgoVM opcode type descriptors and
alpha-function selector bytes found in WD3 particle program containers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class OpcodeEntry:
    """A single PPP opcode entry from the EgoVM type descriptor table.

    Attributes:
        index: Ordinal position in the opcode table (0–35).
        opcode_byte: The single-byte opcode value.
        name: Mnemonic name (e.g. ``pppDrawShape``).
        category: Functional category label.
        n_operands: Expected number of operands.
        total_size: Total instruction size in bytes (header + operands).
        median_size: Typical/median instruction size.
        size_range: Observed size range as ``"min-max"`` string.
        operand_types: Optional list of operand type annotations.
    """
    index: int
    opcode_byte: int
    name: str
    category: str
    n_operands: int = 1
    total_size: int = 2
    median_size: int = 2
    size_range: str = ""
    operand_types: tuple[str, ...] = ()

    @property
    def hex_byte(self) -> str:
        return f"0x{self.opcode_byte:02x}"


@dataclass(frozen=True, slots=True)
class AlphaEntry:
    """Alpha function selector entry.

    Attributes:
        opcode_byte: The byte selector value.
        alpha_mult: Integer multiplier (alpha denominator or scale).
        description: Human-readable description of the alpha mode.
    """
    opcode_byte: int
    alpha_mult: int
    description: str

    @property
    def hex_byte(self) -> str:
        return f"0x{self.opcode_byte:02x}"


# ---- Alpha Function Selectors ----
ALPHA_FUNCTIONS: Final[dict[int, AlphaEntry]] = {
    0x41: AlphaEntry(0x41, 256, "alpha=1.0 (full)"),
    0x42: AlphaEntry(0x42, 16, "alpha=0.0625"),
    0x46: AlphaEntry(0x46, 32, "alpha=0.125"),
    0x48: AlphaEntry(0x48, 2, "alpha=0.0078125"),
    0x88: AlphaEntry(0x88, 512, "alpha=2.0 (boost)"),
    0x44: AlphaEntry(0x44, 0, "INVALID (warning)"),
}

# ---- 36 Opcode Entries ----
# Sanitized: handler RVAs, host_context offsets, and DLL names have been removed.
# Only structural metadata (index, byte, name, category, operand layout) is kept.
OPCODES: Final[dict[int, OpcodeEntry]] = {}

_opcode_defs: list[tuple[int, int, str, str, int, int, int, str]] = [
    # (idx, byte, name, category, nop, tsz, msz, srange)
    (0, 0x00, "pppKeThRes32x4",  "thread_resolution", 0, 1, 1, "1-1"),
    (1, 0x01, "pppKeThRes64x4",  "thread_resolution", 0, 1, 1, "1-1"),
    (2, 0x02, "pppKeThRes64x16", "thread_resolution", 0, 1, 1, "1-1"),
    (3, 0x03, "pppKeGrvTgt",     "gravity", 0, 1, 1, "1-1"),
    (4, 0x04, "pppAccele",       "acceleration", 1, 2, 2, "1-166"),
    (5, 0x05, "pppAngAccele",    "angular_accel", 1, 2, 2, "1-234"),
    (6, 0x06, "pppSclAccele",    "scale_accel", 1, 2, 2, "1-409"),
    (7, 0x07, "pppColAccele",    "color_accel", 2, 8, 8, "1-32"),
    (8, 0x08, "pppKeGrvEff",     "gravity_effect", 3, 13, 13, "3-146"),
    (9, 0x09, "pppMove",         "movement", 1, 2, 2, "1-25"),
    (10, 0x0A, "pppAngMove",     "angular_movement", 1, 2, 2, "1-30"),
    (11, 0x0B, "pppSclMove",     "scale_movement", 1, 2, 2, "1-692"),
    (12, 0x0C, "pppColMove",     "color_movement", 1, 2, 2, "1-123"),
    (13, 0x0D, "pppPoint",       "point", 1, 2, 2, "1-336"),
    (14, 0x0E, "pppAngle",       "angle", 0, 1, 1, "1-41"),
    (15, 0x0F, "pppScale",       "scale", 1, 2, 2, "1-374"),
    (16, 0x10, "pppColor",       "color", 1, 2, 2, "1-570"),
    (17, 0x11, "pppKeDrct",      "direction", 0, 1, 1, "1-349"),
    (18, 0x12, "pppRandFV",      "random_float_vec", 1, 2, 2, "1-825"),
    (19, 0x13, "pppMatrixXYZ",   "matrix", 1, 2, 2, "1-26"),
    (20, 0x14, "pppMatrixLoc",   "matrix", 1, 2, 2, "1-882"),
    (21, 0x15, "pppMatrixScl",   "matrix", 1, 2, 2, "1-86"),
    (22, 0x16, "pppDrawMatrix",  "draw_matrix", 1, 2, 2, "1-163"),
    (23, 0x17, "pppDrawMatrixFront", "draw_matrix_front", 2, 7, 7, "1-2414"),
    (24, 0x18, "pppKeZCrctShp",  "z_correct_shape", 3, 10, 10, "1-37"),
    (25, 0x19, "pppKeThTp",      "thread_type", 1, 6, 6, "1-14"),
    (26, 0x1A, "pppKeThSft",     "thread_shift", 1, 2, 2, "1-828"),
    (27, 0x1B, "pppKeTh",        "thread", 1, 2, 2, "1-273"),
    (28, 0x1C, "pppDrawMdl",     "draw_model", 1, 2, 2, "1-27"),
    (29, 0x1D, "pppDrawMdlTs",   "draw_model_ts", 1, 2, 2, "1-25"),
    (30, 0x1E, "pppDrawShape",   "draw_shape", 1, 2, 2, "1-31"),
    (31, 0x1F, "pppDrawShapeX",  "draw_shape_ext", 1, 2, 2, "1-806"),
    (32, 0x20, "pppPointAp",     "point_appearance", 1, 2, 2, "1-99"),
    (33, 0x21, "pppVertexAp",    "vertex_appearance", 1, 2, 2, "1-546"),
    (34, 0x22, "pppKeBornRnd2",  "born_random", 1, 2, 2, "1-1429"),
    (35, 0x23, "pppKeBornRnd3",  "born_random", 1, 2, 2, "1-25"),
]

for tup in _opcode_defs:
    idx, byte, name, cat, nop, tsz, msz, srange = tup
    OPCODES[byte] = OpcodeEntry(
        index=idx, opcode_byte=byte, name=name,
        category=cat, n_operands=nop, total_size=tsz,
        median_size=msz, size_range=srange,
    )


def lookup_opcode(byte: int) -> OpcodeEntry:
    """Look up an opcode by byte value.

    Returns the ``OpcodeEntry`` if the byte is in the 0x00–0x23 range.
    Raises ``KeyError`` for alpha-function bytes or undefined bytes.
    """
    if byte in OPCODES:
        return OPCODES[byte]
    if byte in ALPHA_FUNCTIONS:
        msg = f"Byte 0x{byte:02x} is an alpha function selector, not an opcode"
        raise KeyError(msg)
    raise KeyError(f"Unknown/unmapped opcode byte 0x{byte:02x}")


def is_known_opcode(byte: int) -> bool:
    """Check if a byte is a known opcode (0x00–0x23)."""
    return byte in OPCODES


def is_alpha_selector(byte: int) -> bool:
    """Check if a byte is an alpha function selector."""
    return byte in ALPHA_FUNCTIONS
