# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Branded startup banner (MOTD).

Shown on interactive, human-facing commands only. It is written to stderr and
suppressed when output is piped/redirected, for the non-interactive `scheduled`
command, or when VULNSCANAI_NO_BANNER / --no-banner is set — so machine-readable
output (JSON/SARIF, cron logs) is never polluted.
"""

from __future__ import annotations

import os
import sys

from . import __version__
from .fips import status_line

# Commands whose output may be consumed by machines or run unattended.
_NO_BANNER_COMMANDS = {"scheduled"}

_CYAN = "\033[36m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"

_WORDMARK = "V U L N S C A N · A I"
_TAGLINE = "FIPS-aware RHEL vulnerability scanner"
_WIDTH = 50


def _unicode_ok(stream) -> bool:
    enc = (getattr(stream, "encoding", "") or "").upper()
    locale = (os.environ.get("LC_ALL") or os.environ.get("LANG") or "").upper()
    return "UTF" in enc or "UTF" in locale


def _color_ok(stream) -> bool:
    return stream.isatty() and not os.environ.get("NO_COLOR")


def banner(host: str = "", *, stream=None) -> str:
    """Render the banner as a string (no I/O)."""
    stream = stream or sys.stderr
    uni = _unicode_ok(stream)
    col = _color_ok(stream)
    tl, tr, bl, br, h, v = (
        ("╔", "╗", "╚", "╝", "═", "║") if uni else ("+", "+", "+", "+", "-", "|"))

    def row(text: str) -> str:
        return v + " " + text.ljust(_WIDTH - 1) + v

    top = tl + h * _WIDTH + tr
    bot = bl + h * _WIDTH + br
    mark = row(_WORDMARK)
    tag = row(_TAGLINE)
    if col:
        top, mark, bot = (_CYAN + s + _RESET for s in (top, mark, bot))
        mark = mark.replace(_WORDMARK, _BOLD + _WORDMARK + _RESET + _CYAN)
        tag = tag.replace(_TAGLINE, _DIM + _TAGLINE + _RESET)
    status = status_line()
    foot = f"  v{__version__}" + (f"  ·  host: {host}" if host else "")
    if col:
        foot = _DIM + foot + _RESET
        status = _DIM + "  " + status + _RESET
    else:
        status = "  " + status
    return "\n".join([top, mark, tag, bot, foot, status])


def print_banner(command, host: str = "", *, stream=None) -> None:
    """Print the banner to stderr for interactive human commands only."""
    stream = stream or sys.stderr
    if os.environ.get("VULNSCANAI_NO_BANNER"):
        return
    if command in _NO_BANNER_COMMANDS:
        return
    if not stream.isatty():
        return
    stream.write(banner(host, stream=stream) + "\n\n")
