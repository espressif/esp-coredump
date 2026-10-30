#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Check rules and the runner.
To add a rule: write a Rule class in a new module and add it to RULES.
"""

from __future__ import annotations

from ..report import AnalysisReport
from .address import AddressClassRule
from .base import Rule
from .breakpoint import BreakpointKindRule
from .cache_error import CacheErrorRule
from .category import CrashCategoryRule
from .context import ContextQualityRule
from .faulting_access import FaultingAccessRule
from .indirect_call import IndirectCallRule
from .riscv_target import InvalidInstructionTargetRule
from .watchdog import InterruptWatchdogRule

RULES: list[Rule] = [
    CrashCategoryRule(),
    BreakpointKindRule(),
    InterruptWatchdogRule(),
    CacheErrorRule(),
    AddressClassRule(),
    ContextQualityRule(),
    InvalidInstructionTargetRule(),
    IndirectCallRule(),
    FaultingAccessRule(),
]


class CheckError(Exception):
    """A rule returned a bad result. This is a bug in the rule."""


def run_checks(report: AnalysisReport, rules: list[Rule] | None = None) -> None:
    """Run every rule that applies and add the results to the report."""
    ids = report.all_ids()
    seen = set()
    for rule in RULES if rules is None else rules:
        if not rule.applies_to(report):
            continue
        for result in rule.run(report):
            missing = [i for i in result.evidence_ids if i not in ids]
            if missing:
                raise CheckError(f'{result.id} cites {missing}, which are not in the report')
            if result.id in seen:
                raise CheckError(f'{result.id} is used twice')
            seen.add(result.id)
            report.checks.append(result)


__all__ = ['RULES', 'CheckError', 'Rule', 'run_checks']
