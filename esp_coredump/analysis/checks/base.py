#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Base class for check rules.
"""

from __future__ import annotations

from ..report import (
    CHECK_CONFIRMED,
    CHECK_FOUND,
    CHECK_NOT_ENOUGH_DATA,
    AnalysisReport,
    CheckResult,
    ElfSectionInfo,
    Fact,
    Frame,
)

# Addresses below this are "near zero"
NEAR_ZERO_LIMIT = 0x1000


class Rule:
    """
    One independent check.
    A rule reads the report and returns a list of results.
    It returns an empty list when it has nothing to say.
    """

    # Versioned id, like 'crash-category.v1'. Change the version when the meaning changes.
    id = ''
    # Architectures the rule works on. Empty means all.
    architectures: tuple[str, ...] = ()
    # What the rule reads, for people who read the code
    needs: tuple[str, ...] = ()

    def applies_to(self, report: AnalysisReport) -> bool:
        return not self.architectures or report.target.architecture in self.architectures

    def run(self, report: AnalysisReport) -> list[CheckResult]:
        raise NotImplementedError

    def _result(self, result: str, summary: str, evidence_ids: list[str], subject: str | None = None, value: str | None = None) -> CheckResult:
        check_id = f'check:{self.id}' if subject is None else f'check:{self.id}:{subject}'
        return CheckResult(check_id, self.id, result, summary, list(evidence_ids), value)

    def confirmed(self, summary, evidence_ids, subject=None, value=None):
        return self._result(CHECK_CONFIRMED, summary, evidence_ids, subject, value)

    def found(self, summary, evidence_ids, subject=None, value=None):
        return self._result(CHECK_FOUND, summary, evidence_ids, subject, value)

    def not_enough_data(self, summary, evidence_ids=(), subject=None):
        return self._result(CHECK_NOT_ENOUGH_DATA, summary, list(evidence_ids), subject)


def app_section_at(report: AnalysisReport, addr: int) -> ElfSectionInfo | None:
    """The app ELF section addr falls in, or None. Sections can overlap, and code wins."""
    sections = [s for s in report.elf.sections if s.contains(addr)]
    return next((s for s in sections if s.kind == 'code'), sections[0] if sections else None)


def code_section(report: AnalysisReport, addr: int) -> tuple[str, bool] | None:
    """
    The executable section addr falls in, as (name, is_rom), or None.
    ROM sections are only known when the ROM ELF was found, so None means
    'not accounted for', not 'not executable'.
    """
    section = app_section_at(report, addr)
    if section is not None and section.kind == 'code':
        return section.name, False
    if report.rom is not None:
        for section in report.rom.sections:
            if section.contains(addr):
                return section.name, True
    return None


def frame_place(frame: Frame | None) -> str:
    """A frame as rule text, like 'f() (main/app.c:12)', or '' when it has no function name."""
    if frame is None or not frame.function:
        return ''
    return f'{frame.function}()' + (f' ({frame.file}:{frame.line})' if frame.file and frame.line else '')


def get_fact(report: AnalysisReport, fact_id: str) -> Fact | None:
    for fact in report.facts:
        if fact.id == fact_id:
            return fact
    return None
