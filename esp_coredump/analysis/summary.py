#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Short text summary of a crash report, for the terminal.
"""

from __future__ import annotations

import textwrap

from rich.text import Text

from .checks.address import AddressClassRule
from .checks.base import app_section_at
from .checks.breakpoint import BreakpointKindRule
from .checks.category import CrashCategoryRule
from .report import (
    CHECK_CONFIRMED,
    CHECK_FOUND,
    CHECK_NOT_ENOUGH_DATA,
    DISASM_ROW_RE,
    NOT_AVAILABLE,
    STACK_OK,
    AnalysisReport,
    CheckResult,
    Frame,
    no_source,
    source_problem,
)

WIDTH = 100
INDENT = ' ' * 14
# Frames shown for the crashed task, and source lines around the crash line
MAX_SUMMARY_FRAMES = 5
SOURCE_CONTEXT = 2
# IDF functions between the code that called abort() or assert() and the crash PC
PANIC_PATH_FUNCTIONS = ('panic_abort', 'esp_system_abort', 'abort', '__assert_func')

# Terminal styles for the confidence levels. A warning code gets WARNING_STYLE.
LABEL_STYLES = {CHECK_CONFIRMED: 'green', CHECK_FOUND: 'yellow', CHECK_NOT_ENOUGH_DATA: 'dim'}
WARNING_STYLE = 'yellow'
HEADLINE_STYLE = 'bold red'
HEADING_STYLE = 'magenta'
FAULT_ROW_STYLE = 'yellow'
CRASH_SITE_STYLE = 'cyan'


def label(value: str | None) -> str:
    """Make a stored value readable, for example sp_outside_bounds -> sp outside bounds."""
    return '' if value is None else value.replace('_', ' ')


def _labeled(label_text: str, style: str, text: str) -> Text:
    # pad to the indent, and keep one space when the label fills it by itself
    head = '  ' + label_text.ljust(len(INDENT) - 3) + ' '
    line = Text(textwrap.fill(text, width=WIDTH, initial_indent=head, subsequent_indent=INDENT))
    line.stylize(style, 2, 2 + len(label_text))
    return line


def frame_text(frame: Frame) -> str:
    text = f'{frame.function}()' if frame.function else f'0x{frame.pc:08x}'
    if frame.file:
        text += f' at {frame.file}' + (f':{frame.line}' if frame.line else '')
    return text


def _site_text(report: AnalysisReport, frame: Frame) -> str:
    """The crash site. A PC in data, such as a buffer called through a pointer, is named by the variable there."""
    section = app_section_at(report, frame.pc) if frame.function else None
    if section is not None and section.kind != 'code':
        return f'{frame.function} (data, {section.name})'
    return frame_text(frame)


def source_lines(frame: Frame, elf_path: str | None = None) -> list[Text]:
    """
    Lines around the frame line, read from the local source file. When the file
    cannot be used, one line says why, so that a missing file is not mistaken for
    a frame that has no source at all. Silent when the output asked for no source.
    """
    if not frame.line or no_source():
        return []
    problem = source_problem(frame.source_path, elf_path)
    if problem is not None:
        # only worth saying when the debug info named a file in the first place
        return [Text(f'  source not shown because {frame.file} {problem}')] if frame.file else []
    path = frame.source_path
    try:
        with open(str(path), encoding='utf-8', errors='replace') as f:
            text = f.read().splitlines()
    except OSError:
        return []
    if frame.line > len(text):
        return []
    first = max(1, frame.line - SOURCE_CONTEXT)
    last = min(len(text), frame.line + SOURCE_CONTEXT)
    width = len(str(last))
    lines = []
    for n in range(first, last + 1):
        line = Text(f'  {">" if n == frame.line else " "} {n:>{width}} | {text[n - 1].rstrip()}')
        if n == frame.line:
            line.stylize(FAULT_ROW_STYLE, 2)
        lines.append(line)
    return lines


def restates_headline(check: CheckResult) -> bool:
    """
    Results the terminal does not need, they stay in the JSON report.
    The category is shown in the headline, unless it was guessed from a frame.
    A PC in the app code is the normal case.
    """
    if check.rule == CrashCategoryRule.id and check.result != CHECK_NOT_ENOUGH_DATA:
        # the headline carries the category, but not the reason it is missing
        return not any(i.startswith('frame:') for i in check.evidence_ids)
    return check.rule == AddressClassRule.id and check.value == 'elf_code'


def summary_text(report: AnalysisReport, elf_path: str | None = None) -> Text:
    """
    The crash headline, where it happened, the source and disassembly around it, the
    findings and the warnings, with terminal styles. elf_path is used to skip changed
    source files.
    """
    crash = report.crash
    category = next((c.value for c in report.checks if c.rule == CrashCategoryRule.id), None)
    # a breakpoint can be a watchpoint, say which one when a rule found out
    category = next((c.value for c in report.checks if c.rule == BreakpointKindRule.id and c.value), category)
    reason = crash.reason or label(NOT_AVAILABLE)
    lines = [Text(), Text(f'Crash: {reason}' + (f' ({label(category)})' if category else ''), style=HEADLINE_STYLE)]

    task = report.crashed_task()
    task_text = f"task '{task.name}' ({task.id})" if task and task.name else (task.id if task else f'task {label(NOT_AVAILABLE)}')
    where = [
        f'core {crash.core}' if crash.core is not None else f'core {label(NOT_AVAILABLE)}',
        task_text,
        f'PC {crash.pc:#010x}' if crash.pc is not None else f'PC {label(NOT_AVAILABLE)}',
    ]
    if crash.bad_address is not None:
        where.append(f'bad address {crash.bad_address:#010x}')
    lines.append(Text('  ' + ', '.join(where)))
    if task is not None and task.stack.status != NOT_AVAILABLE:
        stack = task.stack
        stack_line = f'  stack {label(stack.status)}'
        if stack.status == STACK_OK and stack.start is not None and stack.end is not None and stack.sp is not None:
            stack_line += f' (SP uses {stack.end - stack.sp} of {stack.end - stack.start} bytes)'
        lines.append(Text(stack_line))
    if report.elf.match != 'match':
        lines.append(Text(f'  ELF match: {label(report.elf.match)}'))
    if task is not None and task.frames:
        # the crash site is the first frame outside the IDF panic path, if it has a source line
        site = next((i for i, f in enumerate(task.frames) if f.function not in PANIC_PATH_FUNCTIONS), 0)
        if not (task.frames[site].file and task.frames[site].line):
            site = 0
        # only the crash site is styled, so the one line to read stands out from the callers
        lead = f'  {task.frames[site - 1].function}() was called from ' if site else '  in '
        lines.append(Text.assemble(lead, (_site_text(report, task.frames[site]), CRASH_SITE_STYLE)))
        lines.extend(source_lines(task.frames[site], elf_path))
        callers = task.frames[site + 1 : site + MAX_SUMMARY_FRAMES]
        if callers:
            lines.append(Text('Called from:', style=HEADING_STYLE))
            lines.extend(Text(f'  {frame_text(fr)}') for fr in callers)
            more = len(task.frames) - site - MAX_SUMMARY_FRAMES
            if more > 0:
                lines.append(Text(f'  ... {more} more'))

    disassembly = report.disassembly
    if disassembly is not None:
        title = f' ({disassembly.title})' if disassembly.title else ''
        lines.append(Text(f'Disassembly around 0x{disassembly.address:08x}{title}:', style=HEADING_STYLE))
        for row in disassembly.text.splitlines():
            line = Text(f'  {row}')
            match = DISASM_ROW_RE.match(row)
            # the row the window was built around
            if match and int(match.group(2), 16) == disassembly.address:
                line.stylize(FAULT_ROW_STYLE, 2 + match.start(2))
            lines.append(line)

    lines.append(Text('Findings:', style=HEADING_STYLE))
    # confirmed first, so the strongest conclusion leads
    findings = sorted((c for c in report.checks if not restates_headline(c)), key=lambda c: c.result != CHECK_CONFIRMED)
    if findings:
        lines.extend(_labeled(f'[{label(c.result)}]', LABEL_STYLES.get(c.result, ''), c.summary) for c in findings)
    else:
        lines.append(Text('  none'))

    if report.warnings:
        lines.append(Text('Warnings:', style=HEADING_STYLE))
        lines.extend(_labeled(f'[{label(w.code)}]', WARNING_STYLE, w.message) for w in report.warnings)
    else:
        lines.append(Text.assemble(('Warnings:', HEADING_STYLE), ' none'))
    return Text('\n').join(lines)
