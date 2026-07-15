from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .layer_c_resource import PppResourceRoot, find_ppp_resource_roots, iter_ppp_slots


class NonBehavioralColorFamilyError(ValueError):
    def __init__(self) -> None:
        super().__init__("pppColor is excluded from the useful-behavior queue")


class InvalidUsefulPppSpecError(ValueError):
    detail: str

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)


@dataclass(frozen=True, slots=True)
class UsefulPppFamilySpec:
    opcode_name: str
    handler_index: int
    raw_payload_width: int
    runtime_operand_offset: int
    runtime_operand_width: int

    def __post_init__(self) -> None:
        if self.opcode_name == "pppColor":
            raise NonBehavioralColorFamilyError
        if self.handler_index < 0:
            raise InvalidUsefulPppSpecError("handler index must be non-negative")
        if self.raw_payload_width <= 0:
            raise InvalidUsefulPppSpecError("raw payload width must be positive")
        if self.runtime_operand_offset < 0 or self.runtime_operand_width <= 0:
            raise InvalidUsefulPppSpecError("runtime operand window must be positive")
        if self.runtime_operand_offset + self.runtime_operand_width > self.raw_payload_width:
            raise InvalidUsefulPppSpecError("runtime operand window exceeds raw payload")


@dataclass(frozen=True, slots=True)
class UsefulPppCandidate:
    opcode_name: str
    handler_index: int
    section_offset: int
    program_offset: int
    slot_offset: int
    callback_record_offset: int
    raw_payload_offset: int
    raw_payload_width: int
    runtime_operand_offset: int
    runtime_operand_width: int
    record_sha256: str


@dataclass(frozen=True, slots=True)
class UsefulPppRejection:
    opcode_name: str
    slot_offset: int
    callback_record_offset: int
    reason: str


@dataclass(frozen=True, slots=True)
class UsefulPppCandidateReport:
    candidates: tuple[UsefulPppCandidate, ...]
    rejections: tuple[UsefulPppRejection, ...]


@dataclass(frozen=True, slots=True)
class _Span:
    start: int
    end: int

    def overlaps(self, start: int, end: int) -> bool:
        return start < self.end and self.start < end


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "little")


def _structural_spans(data: bytes, root: PppResourceRoot) -> tuple[_Span, ...]:
    spans: list[_Span] = [_Span(root.offset, root.offset + 32)]
    for section_relative in root.primary_section_offsets:
        section = root.offset + section_relative
        spans.append(_Span(section, section + 16))
        for table_field in (8, 12):
            table = section + _u32(data, section + table_field)
            count = _u32(data, table)
            spans.append(_Span(table, table + 4 + 4 * count))

    seen_programs: set[int] = set()
    for record in iter_ppp_slots(data, root):
        if record.program_offset in seen_programs:
            continue
        seen_programs.add(record.program_offset)
        slot_count = int.from_bytes(
            data[record.program_offset + 38:record.program_offset + 40],
            "little",
            signed=True,
        )
        spans.append(_Span(record.program_offset, record.program_offset + 40 + 16 * slot_count))
    return tuple(spans)


def select_useful_ppp_candidates(
    data: bytes,
    spec: UsefulPppFamilySpec,
) -> UsefulPppCandidateReport:
    candidates: list[UsefulPppCandidate] = []
    rejections: list[UsefulPppRejection] = []
    for root in find_ppp_resource_roots(data):
        spans = _structural_spans(data, root)
        for slot_record in iter_ppp_slots(data, root):
            slot = slot_record.slot
            if slot.handler_table_index != spec.handler_index:
                continue
            callback = slot_record.section_offset + slot.primary_callback_relative
            record_end = callback + 8 + spec.raw_payload_width
            section_end = slot_record.section_offset + _u32(data, slot_record.section_offset)
            if callback < slot_record.section_offset or record_end > section_end:
                rejections.append(UsefulPppRejection(
                    opcode_name=spec.opcode_name,
                    slot_offset=slot_record.offset,
                    callback_record_offset=callback,
                    reason="out_of_section",
                ))
                continue
            if any(span.overlaps(callback, record_end) for span in spans):
                rejections.append(UsefulPppRejection(
                    opcode_name=spec.opcode_name,
                    slot_offset=slot_record.offset,
                    callback_record_offset=callback,
                    reason="structural_overlap",
                ))
                continue
            record_bytes = data[callback:record_end]
            raw_payload = callback + 8
            candidates.append(UsefulPppCandidate(
                opcode_name=spec.opcode_name,
                handler_index=spec.handler_index,
                section_offset=slot_record.section_offset,
                program_offset=slot_record.program_offset,
                slot_offset=slot_record.offset,
                callback_record_offset=callback,
                raw_payload_offset=raw_payload,
                raw_payload_width=spec.raw_payload_width,
                runtime_operand_offset=raw_payload + spec.runtime_operand_offset,
                runtime_operand_width=spec.runtime_operand_width,
                record_sha256=hashlib.sha256(record_bytes).hexdigest(),
            ))
    return UsefulPppCandidateReport(tuple(candidates), tuple(rejections))
