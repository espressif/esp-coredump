#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Shorten the local source paths in report text.
"""

from __future__ import annotations

import os
import re

# Folders used to shorten source paths
PATH_MARKERS = ('/managed_components/', '/components/', '/main/')
# Absolute paths inside a text, like in assert messages
ABS_PATH_RE = re.compile(r'(?<![\w.])(?:[A-Za-z]:)?[/\\](?:[^\s:()\'"/\\]+[/\\])+[^\s:()\'"/\\]+')
# Chars that can not be inside a path in a panic message.
# A colon counts only when it is not a drive letter colon.
PATH_STOP_RE = re.compile(r':(?![/\\])|[()\'"\n]')


def short_path(path: str | None) -> str | None:
    """Remove the local part of a source path."""
    if not path:
        return None
    path = path.replace('\\', '/')
    hits = [path.find(m) for m in PATH_MARKERS if m in path]
    if hits:
        return path[min(hits) + 1 :]
    return os.path.basename(path)


def find_path_start(text: str, seg_start: int, end: int) -> int:
    """Return the start of the last absolute path in text[seg_start:end], or -1."""
    found = -1
    i = seg_start
    while i < end:
        at_start = i == seg_start or text[i - 1].isspace() or text[i - 1] == ':'
        if at_start and text[i].isalpha() and text[i + 1 : i + 3] in (':\\', ':/'):
            # Windows drive, skip its slash
            found = i
            i += 3
            continue
        if at_start and text[i] == '/':
            found = i
        i += 1
    return found


def short_paths_in_text(text: str) -> str:
    """Shorten absolute paths in a text. Paths can have spaces if they have a known folder."""
    markers = PATH_MARKERS + tuple(m.replace('/', '\\') for m in PATH_MARKERS)
    done = 0  # text before this is already handled
    while True:
        # the first marker after the handled part
        hits = [hit for hit in ((text.find(m, done), m) for m in markers) if hit[0] >= 0]
        if not hits:
            break
        pos, marker = min(hits)
        # the path is after the last stop char before the marker
        stops = [x.end() for x in PATH_STOP_RE.finditer(text, done, pos)]
        start = find_path_start(text, max([done] + stops), pos + 1)
        if start >= 0:
            text = text[:start] + text[pos + 1 :]
            done = start + len(marker) - 1
        else:
            done = pos + 1
    return ABS_PATH_RE.sub(lambda x: short_path(x.group(0)) or '', text)
