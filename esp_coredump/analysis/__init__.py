#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Crash analysis: a structured JSON report made from a core dump.
"""

import os

from .collect import ElfMismatchError, ReportError, build_report
from .report import NOT_AVAILABLE, REPORT_VERSION, AnalysisReport
from .summary import summary_text

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), 'schema', 'report-v1.json')

__all__ = [
    'AnalysisReport',
    'ElfMismatchError',
    'NOT_AVAILABLE',
    'REPORT_VERSION',
    'ReportError',
    'SCHEMA_PATH',
    'build_report',
    'summary_text',
]
