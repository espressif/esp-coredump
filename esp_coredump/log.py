#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#
"""esp-coredump logger extending esp-pylib with legacy ``--debug`` info level."""

from __future__ import annotations

from typing import Any

from esp_pylib.logger import EspLog, Verbosity

# ``--debug`` flag value at/above which ``note()`` is shown (legacy logging.INFO).
_INFO_LEVEL = 3
# Default when the CLI never calls ``set_log_level`` (library / ``idf.py`` use).
# Matches unset Python logging → WARNING, i.e. ``--debug 2``.
_DEFAULT_LOG_LEVEL = 2


class CoreDumpLog(EspLog):
    def __init__(self, no_color: bool | None = None) -> None:
        super().__init__(no_color)
        self._log_level = _DEFAULT_LOG_LEVEL

    def set_log_level(self, log_level: int) -> None:
        """Apply the legacy ``--debug`` flag (0..4) from the CLI."""
        self._log_level = max(0, min(4, log_level))
        if log_level <= 0:
            self.set_verbosity(Verbosity.SILENT)
        elif log_level <= 3:
            self.set_verbosity(Verbosity.NORMAL)
        else:
            self.set_verbosity(Verbosity.VERBOSE)

    def note(self, *args: Any) -> None:
        """Status output (legacy ``logging.info``). Requires ``--debug`` 3+."""
        if self._log_level >= _INFO_LEVEL:
            super().note(*args)


log = CoreDumpLog()
