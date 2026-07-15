from dataclasses import dataclass
from typing import override


PPP_SLOT_SIZE = 16
PPP_HANDLER_ENTRY_SIZE = 40


@dataclass(frozen=True, slots=True)
class PppSlot:
    handler_table_index: int
    parameter_offset: int
    flags: int
    primary_callback_relative: int
    secondary_callback_relative: int


@dataclass(frozen=True, slots=True)
class RelocatedPppSlot:
    handler_entry_address: int
    parameter_offset: int
    flags: int
    primary_callback_address: int
    secondary_callback_address: int


@dataclass(frozen=True, slots=True)
class PppSlotOffsetError(ValueError):
    field_name: str
    relative_offset: int
    section_size: int

    @override
    def __str__(self) -> str:
        return (
            f"{self.field_name} offset 0x{self.relative_offset:X} is outside "
            f"section size 0x{self.section_size:X}"
        )


@dataclass(frozen=True, slots=True)
class PppSlotDataError(ValueError):
    offset: int
    available_size: int

    @override
    def __str__(self) -> str:
        return (
            f"PPP slot at 0x{self.offset:X} requires {PPP_SLOT_SIZE} bytes; "
            f"only {self.available_size} available"
        )


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "little")


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "little")


def parse_ppp_slot(data: bytes, offset: int) -> PppSlot:
    available_size = len(data) - offset
    if offset < 0 or available_size < PPP_SLOT_SIZE:
        raise PppSlotDataError(offset=offset, available_size=max(0, available_size))

    return PppSlot(
        handler_table_index=_u32(data, offset),
        parameter_offset=_u16(data, offset + 4),
        flags=_u16(data, offset + 6),
        primary_callback_relative=_u32(data, offset + 8),
        secondary_callback_relative=_u32(data, offset + 12),
    )


def serialize_ppp_slot(slot: PppSlot) -> bytes:
    return b"".join(
        (
            slot.handler_table_index.to_bytes(4, "little"),
            slot.parameter_offset.to_bytes(2, "little"),
            slot.flags.to_bytes(2, "little"),
            slot.primary_callback_relative.to_bytes(4, "little"),
            slot.secondary_callback_relative.to_bytes(4, "little"),
        )
    )


def resolve_ppp_slot(
    slot: PppSlot,
    *,
    section_base: int,
    section_size: int,
    handler_table_base: int,
) -> RelocatedPppSlot:
    relative_callbacks = (
        ("primary_callback", slot.primary_callback_relative),
        ("secondary_callback", slot.secondary_callback_relative),
    )
    for field_name, relative_offset in relative_callbacks:
        if relative_offset >= section_size:
            raise PppSlotOffsetError(
                field_name=field_name,
                relative_offset=relative_offset,
                section_size=section_size,
            )

    return RelocatedPppSlot(
        handler_entry_address=(
            handler_table_base
            + PPP_HANDLER_ENTRY_SIZE * slot.handler_table_index
        ),
        parameter_offset=slot.parameter_offset,
        flags=slot.flags,
        primary_callback_address=(
            section_base + slot.primary_callback_relative
        ),
        secondary_callback_address=(
            section_base + slot.secondary_callback_relative
        ),
    )
