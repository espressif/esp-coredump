#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Shared case list, paths and command arguments for the ``analyze`` tests.

A module rather than a fixture, because ``ANALYSIS_CASES`` is needed at import
time by ``pytest.mark.parametrize``. Both ``test_analysis.py`` and
``test_espcoredump.py`` run the same dumps, so a new crash case is added here
once instead of in each of them.
"""

import os

from esp_coredump.analysis.report import NO_SOURCE_ENV

TARGET = 'esp32s31'
# The dumps the expected output tests use. One build, one case: see tests/README.md.
ANALYSIS_CASES = ['null_write']
TEST_DIR_ABS_PATH = os.path.dirname(__file__)
ESP_PROG_DIR = os.path.join(TEST_DIR_ABS_PATH, 'test_apps', 'built_apps')


def analysis_paths(case):
    """The core dump, application ELF and expected summary of one crash case."""
    return (
        os.path.join(TEST_DIR_ABS_PATH, TARGET, f'coredump_{case}.b64'),
        os.path.join(ESP_PROG_DIR, f'{TARGET}_{case}.elf'),
        os.path.join(TEST_DIR_ABS_PATH, TARGET, f'expected_analysis_{case}'),
    )


def analyze_argv(core, prog, *options):
    """The analyze arguments for any core dump and ELF. Callers prepend their own runner."""
    return ['-m', 'esp_coredump', '--chip', TARGET, 'analyze', '-c', core, *options, prog]


def analysis_args(case, extra=()):
    """The analyze arguments for one case. Callers prepend their own runner."""
    core, prog, _ = analysis_paths(case)
    return analyze_argv(core, prog, '-t', 'b64', *extra)


def no_source_env():
    """
    The environment for an analyze run without C source lines. They are read from
    the machine that built the ELF, so they would differ from one machine to another.
    """
    return {**os.environ, NO_SOURCE_ENV: '1'}


def without_banner(stdout):
    """Drop the version line the group callback prints before any subcommand."""
    return stdout.decode().split('\n', 1)[1]


def assert_analysis_error(proc):
    """Every bad input reports the same way: exit 1, one message, no traceback."""
    stderr = proc.stderr.decode()
    assert proc.returncode == 1, stderr
    assert 'No analysis was made' in stderr
    assert 'Traceback' not in stderr
    return stderr
