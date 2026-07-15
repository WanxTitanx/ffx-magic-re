from collections.abc import Iterator
from dataclasses import dataclass

from .layer_c_slot import PPP_SLOT_SIZE, PppSlot, parse_ppp_slot


@dataclass(frozen=True, slots=True)
class PppResourceRoot:
    offset: int
    primary_section_offsets: tuple[int, ...]
    relocation_table_offsets: tuple[int, int, int]


@dataclass(frozen=True, slots=True)
class PppSlotRecord:
    offset: int
    section_offset: int
    program_offset: int
    slot: PppSlot


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "little")


def _i16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "little", signed=True)


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "little")


def find_ppp_resource_roots(data: bytes) -> tuple[PppResourceRoot, ...]:
    roots: list[PppResourceRoot] = []
    for offset in range(0, len(data) - 32, 4):
        root = _parse_resource_root_candidate(data, offset)
        if root is not None:
            roots.append(root)
    return tuple(roots)


def iter_ppp_slots(
    data: bytes,
    root: PppResourceRoot,
) -> Iterator[PppSlotRecord]:
    for section_relative in root.primary_section_offsets:
        section_offset = root.offset + section_relative
        program_offset = section_offset + 16
        while True:
            slot_count = _i16(data, program_offset + 38)
            for slot_index in range(slot_count):
                slot_offset = program_offset + 40 + PPP_SLOT_SIZE * slot_index
                yield PppSlotRecord(
                    offset=slot_offset,
                    section_offset=section_offset,
                    program_offset=program_offset,
                    slot=parse_ppp_slot(data, slot_offset),
                )
            next_relative = _u32(data, program_offset)
            if next_relative == 0:
                break
            program_offset = section_offset + next_relative


def _parse_resource_root_candidate(
    data: bytes,
    offset: int,
) -> PppResourceRoot | None:
    primary_count = _u16(data, offset + 6)
    count2 = _u16(data, offset + 8)
    count3 = _u16(data, offset + 10)
    count4 = _u16(data, offset + 12)
    table1 = _u32(data, offset + 16)
    table2 = _u32(data, offset + 20)
    table3 = _u32(data, offset + 24)
    table4 = _u32(data, offset + 28)
    table_offsets = (table1, table2, table3, table4)
    if not (0 < primary_count <= 64):
        return None
    if any(count > 256 for count in (count2, count3, count4)):
        return None
    if any(relative < 32 or relative % 4 for relative in table_offsets):
        return None
    if tuple(sorted(table_offsets)) != table_offsets:
        return None
    if any(offset + relative >= len(data) for relative in table_offsets):
        return None

    primary_table = offset + table1
    primary_sections = tuple(
        _u32(data, primary_table + 4 * index)
        for index in range(primary_count)
    )
    if any(
        relative < 32
        or relative % 4
        or not _valid_primary_section(data, offset, relative)
        for relative in primary_sections
    ):
        return None
    if not _valid_auxiliary_tables(
        data,
        offset,
        (count2, count3, count4),
        (table2, table3, table4),
    ):
        return None
    return PppResourceRoot(
        offset=offset,
        primary_section_offsets=primary_sections,
        relocation_table_offsets=(table2, table3, table4),
    )


def _valid_primary_section(data: bytes, root: int, relative: int) -> bool:
    section = root + relative
    if section + 56 > len(data):
        return False
    section_size = _u32(data, section)
    if section_size < 56 or section + section_size > len(data):
        return False
    if not _valid_counted_u32_table(data, section, section_size, _u32(data, section + 8)):
        return False
    if not _valid_counted_u32_table(data, section, section_size, _u32(data, section + 12)):
        return False

    program = section + 16
    visited: set[int] = set()
    found_slot = False
    while True:
        program_relative = program - section
        if program_relative in visited or program + 40 > section + section_size:
            return False
        visited.add(program_relative)
        slot_count = _i16(data, program + 38)
        if not (0 <= slot_count <= 256):
            return False
        if program + 40 + PPP_SLOT_SIZE * slot_count > section + section_size:
            return False
        for slot_index in range(slot_count):
            slot = parse_ppp_slot(data, program + 40 + PPP_SLOT_SIZE * slot_index)
            if slot.handler_table_index > 255:
                return False
            if slot.primary_callback_relative >= section_size:
                return False
            if slot.secondary_callback_relative >= section_size:
                return False
            found_slot = True
        next_relative = _u32(data, program)
        if next_relative == 0:
            return found_slot
        if next_relative <= program_relative or next_relative % 4:
            return False
        program = section + next_relative


def _valid_counted_u32_table(
    data: bytes,
    section: int,
    section_size: int,
    relative: int,
) -> bool:
    if relative < 16 or relative + 4 > section_size:
        return False
    table = section + relative
    count = _u32(data, table)
    if count > 4096 or relative + 4 + 4 * count > section_size:
        return False
    return all(_u32(data, table + 4 + 4 * index) < section_size for index in range(count))


def _valid_auxiliary_tables(
    data: bytes,
    root: int,
    counts: tuple[int, int, int],
    offsets: tuple[int, int, int],
) -> bool:
    resource_size = len(data) - root
    section2 = root + offsets[0]
    if section2 + 32 * counts[0] > len(data):
        return False
    for index in range(counts[0]):
        entry = section2 + 32 * index
        if any(_u32(data, entry + part) >= resource_size for part in (20, 24, 28)):
            return False
    section3 = root + offsets[1]
    if section3 + 4 * counts[1] > len(data):
        return False
    if any(_u32(data, section3 + 4 * index) >= resource_size for index in range(counts[1])):
        return False
    section4 = root + offsets[2]
    if section4 + 8 * counts[2] > len(data):
        return False
    return all(
        _u32(data, section4 + 8 * index + 4) < resource_size
        for index in range(counts[2])
    )
