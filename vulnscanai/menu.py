# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Interactive, menu-driven front-end for vulnscan-ai.

Run ``vulnscan-ai`` with no arguments on a terminal (or ``vulnscan-ai menu``
explicitly) to get a navigable menu that covers every subcommand, so operators
don't have to remember flag names.

Design notes:
  * The menu never re-implements a command. Each choice is turned into the same
    ``argv`` the CLI parser accepts, run through ``parser.parse_args`` and
    dispatched via ``args.func(cfg, args)`` -- so defaults, validation and
    behaviour stay identical to typing the command by hand (no drift).
  * Navigation uses a small stdlib ``curses`` widget (arrow keys + Enter) when a
    capable TTY is present, and degrades to a plain numbered prompt otherwise
    (no TTY, ``TERM=dumb``, ``VULNSCANAI_NO_CURSES``, or any curses error) so it
    keeps working over odd SSH sessions, in pipes and in tests.
  * Each curses widget is a self-contained session: it is torn down before a
    command runs, so the command's own output and prompts (scan progress, the
    per-finding fix approval, getpass) use the normal cooked terminal.
"""

from __future__ import annotations

import os
import re
import socket
import sys
from typing import List, Optional, Tuple, Union

from . import __version__
from .scanners import SCANNERS


# A distinct sentinel so ``None`` can be a legitimate menu value (e.g. "All
# severities" -> pass no --min-severity flag).
_CANCEL = object()

_Item = Tuple[str, object]      # (label, value)


# --------------------------------------------------------------------------- #
# terminal helpers
# --------------------------------------------------------------------------- #
def _eprint(*a, **k):
    print(*a, file=sys.stderr, **k)


def _interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _use_curses() -> bool:
    """True when a highlighted arrow-key menu is safe to draw."""
    if not _interactive():
        return False
    if os.environ.get("VULNSCANAI_NO_CURSES"):
        return False
    if (os.environ.get("TERM") or "dumb") == "dumb":
        return False
    try:
        import curses  # noqa: F401
    except Exception:  # noqa: BLE001 -- any import/platform failure -> fall back
        return False
    return True


def _ask(prompt: str, default: str = "") -> Optional[str]:
    """Cooked-mode free-text prompt. Returns the entry (or the default when
    blank), or None if the operator interrupts."""
    label = prompt + (f" [{default}]" if default else "")
    try:
        s = input(f"{label}: ").strip()
    except (EOFError, KeyboardInterrupt):
        return None
    return s or default


def _ask_yesno(prompt: str, default: bool = True) -> bool:
    d = "Y/n" if default else "y/N"
    try:
        s = input(f"{prompt} [{d}]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return default
    if not s:
        return default
    return s[0] == "y"


def _pause() -> None:
    try:
        input("\nPress Enter to return to the menu … ")
    except (EOFError, KeyboardInterrupt):
        pass


# --------------------------------------------------------------------------- #
# single-choice widget (curses, with numbered fallback)
# --------------------------------------------------------------------------- #
def _choose(title: str, items: List[_Item],
            subtitle: Optional[str] = None) -> object:
    """Pick one item. Returns its value, or _CANCEL on q/Esc/interrupt."""
    if _use_curses():
        try:
            return _curses_choose(title, items, subtitle)
        except Exception:  # noqa: BLE001 -- never let a draw glitch kill the menu
            pass
    return _numbered_choose(title, items, subtitle)


def _curses_choose(title: str, items: List[_Item], subtitle: Optional[str]):
    import curses

    def _inner(stdscr):
        curses.curs_set(0)
        try:
            curses.use_default_colors()
        except curses.error:
            pass
        idx = 0
        n = len(items)
        while True:
            stdscr.erase()
            h, w = stdscr.getmaxyx()
            row = 0
            row = _addln(stdscr, row, w, title, curses.A_BOLD)
            if subtitle:
                row = _addln(stdscr, row, w, subtitle, curses.A_DIM)
            row += 1
            for i, (label, _) in enumerate(items):
                marker = "›" if i == idx else " "
                num = f"{i + 1}." if i < 9 else "  "
                attr = curses.A_REVERSE if i == idx else curses.A_NORMAL
                row = _addln(stdscr, row, w, f" {marker} {num} {label}", attr)
                if row >= h - 1:
                    break
            _addln(stdscr, h - 1, w,
                   "↑/↓ move · Enter select · q back", curses.A_DIM)
            stdscr.refresh()
            k = stdscr.getch()
            if k in (curses.KEY_UP, ord("k")):
                idx = (idx - 1) % n
            elif k in (curses.KEY_DOWN, ord("j")):
                idx = (idx + 1) % n
            elif k in (curses.KEY_ENTER, 10, 13):
                return items[idx][1]
            elif k in (27, ord("q")):
                return _CANCEL
            elif ord("1") <= k <= ord("9") and (k - ord("1")) < n:
                return items[k - ord("1")][1]

    return curses.wrapper(_inner)


def _numbered_choose(title: str, items: List[_Item], subtitle: Optional[str]):
    print(f"\n{title}")
    if subtitle:
        print(f"  {subtitle}")
    for i, (label, _) in enumerate(items):
        print(f"  {i + 1}. {label}")
    while True:
        try:
            s = input("Choose a number (q to go back) ▸ ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return _CANCEL
        if s in ("q", "quit"):
            return _CANCEL
        if s.isdigit() and 1 <= int(s) <= len(items):
            return items[int(s) - 1][1]
        print("  ? please enter a listed number")


# --------------------------------------------------------------------------- #
# multi-choice widget (curses, with numbered fallback)
# --------------------------------------------------------------------------- #
def _multi_choose(title: str, options: List[str]) -> Union[List[str], object]:
    """Pick zero or more items. Returns a list, or _CANCEL on cancel."""
    if _use_curses():
        try:
            return _curses_multi(title, options)
        except Exception:  # noqa: BLE001
            pass
    return _numbered_multi(title, options)


def _curses_multi(title: str, options: List[str]):
    import curses

    def _inner(stdscr):
        curses.curs_set(0)
        try:
            curses.use_default_colors()
        except curses.error:
            pass
        idx = 0
        sel: set = set()
        n = len(options)
        while True:
            stdscr.erase()
            h, w = stdscr.getmaxyx()
            row = _addln(stdscr, 0, w, title, curses.A_BOLD)
            row += 1
            for i, opt in enumerate(options):
                box = "[x]" if i in sel else "[ ]"
                marker = "›" if i == idx else " "
                attr = curses.A_REVERSE if i == idx else curses.A_NORMAL
                row = _addln(stdscr, row, w, f" {marker} {box} {opt}", attr)
                if row >= h - 1:
                    break
            _addln(stdscr, h - 1, w,
                   "space toggle · Enter confirm · q back", curses.A_DIM)
            stdscr.refresh()
            k = stdscr.getch()
            if k in (curses.KEY_UP, ord("k")):
                idx = (idx - 1) % n
            elif k in (curses.KEY_DOWN, ord("j")):
                idx = (idx + 1) % n
            elif k == ord(" "):
                sel.symmetric_difference_update({idx})
            elif k in (curses.KEY_ENTER, 10, 13):
                return [options[i] for i in sorted(sel)]
            elif k in (27, ord("q")):
                return _CANCEL

    return curses.wrapper(_inner)


def _numbered_multi(title: str, options: List[str]):
    print(f"\n{title}")
    for i, opt in enumerate(options):
        print(f"  {i + 1}. {opt}")
    try:
        s = input("Numbers, comma/space separated (q to go back) ▸ ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return _CANCEL
    if s in ("q", "quit", ""):
        return _CANCEL
    picks = []
    for tok in re.split(r"[ ,]+", s):
        if tok.isdigit() and 1 <= int(tok) <= len(options):
            opt = options[int(tok) - 1]
            if opt not in picks:
                picks.append(opt)
    return picks or _CANCEL


def _addln(stdscr, row: int, width: int, text: str, attr: int = 0) -> int:
    """Draw one clipped line at column 2; return the next row. Never raises
    (curses errors on the last cell of the screen, which we don't care about)."""
    try:
        stdscr.addnstr(row, 2, text, max(0, width - 3), attr)
    except Exception:  # noqa: BLE001
        pass
    return row + 1


# --------------------------------------------------------------------------- #
# reusable option pickers shared by several commands
# --------------------------------------------------------------------------- #
_SEV_ITEMS: List[_Item] = [
    ("All (use the configured floor)", None),
    ("low and above", "low"),
    ("moderate and above", "moderate"),
    ("important and above", "important"),
    ("critical only", "critical"),
]


def _pick_severity() -> object:
    return _choose("Minimum severity to include", _SEV_ITEMS)


def _pick_scanners(cfg) -> object:
    """Return argv tokens for the scanner selection, or _CANCEL."""
    which = _choose("Which scanners?", [
        ("All scanners", "all"),
        (f"Default ({', '.join(cfg.scanners)})", "default"),
        ("Choose specific scanners…", "choose"),
    ])
    if which is _CANCEL:
        return _CANCEL
    if which == "all":
        return ["--all"]
    if which == "default":
        return []
    picked = _multi_choose("Select scanners (space toggles)", list(SCANNERS))
    if picked is _CANCEL or not picked:
        return _CANCEL
    toks: List[str] = []
    for s in picked:
        toks += ["--scanner", s]
    return toks


# --------------------------------------------------------------------------- #
# per-command argv builders  (return argv list, or None/_CANCEL to go back)
# --------------------------------------------------------------------------- #
def _b_scan(cfg) -> Optional[List[str]]:
    argv = ["scan"]
    toks = _pick_scanners(cfg)
    if toks is _CANCEL:
        return None
    argv += toks
    sev = _pick_severity()
    if sev is _CANCEL:
        return None
    if sev:
        argv += ["--min-severity", sev]
    if not _ask_yesno("Enrich findings (KEV/EPSS + vendor/patched filters)?", True):
        argv.append("--no-enrich")
    pdf = _ask("Also write a PDF report to (blank = skip)", "")
    if pdf:
        argv += ["--pdf", pdf]
    return argv


def _b_fix(cfg) -> Optional[List[str]]:
    argv = ["fix"]
    src = _choose("Fix which findings?", [
        ("Re-scan now, then fix", "scan"),
        ("Use the last saved scan", "saved"),
    ])
    if src is _CANCEL:
        return None
    if src == "scan":
        argv.append("--scan")
        toks = _pick_scanners(cfg)
        if toks is _CANCEL:
            return None
        argv += toks
    sev = _pick_severity()
    if sev is _CANCEL:
        return None
    if sev:
        argv += ["--min-severity", sev]
    mode = _choose("How should fixes be handled?", [
        ("Interactive — approve each fix", "interactive"),
        ("Dry-run — show plans, apply nothing", "dry"),
        ("Auto-apply ALL without prompting (dangerous)", "auto"),
        ("Export a bash script (no changes made)", "script"),
        ("Export an Ansible playbook (no changes made)", "ansible"),
    ])
    if mode is _CANCEL:
        return None
    if mode == "dry":
        argv.append("--dry-run")
    elif mode == "auto":
        if not _ask_yesno("Really apply EVERY proposed fix with no prompts?", False):
            return None
        argv.append("--yes")
    elif mode == "script":
        p = _ask("Write bash script to", "vulnscan-ai-fixes.sh")
        if not p:
            return None
        argv += ["--export-script", p]
    elif mode == "ansible":
        p = _ask("Write Ansible playbook to", "vulnscan-ai-fixes.yml")
        if not p:
            return None
        argv += ["--export-ansible", p]
    return argv


def _b_rollback(cfg) -> Optional[List[str]]:
    action = _choose("Roll back a fix", [
        ("List fixes that have a stored backup", "list"),
        ("Roll back a specific finding id", "id"),
    ])
    if action is _CANCEL:
        return None
    if action == "list":
        return ["rollback", "--list"]
    fid = _ask("Finding id to roll back", "")
    if not fid:
        return None
    return ["rollback", fid]


def _b_report(cfg) -> Optional[List[str]]:
    out = _ask("Write report to", "vulnscan-ai-report.pdf")
    if not out:
        return None
    argv = ["report", "-o", out]
    sev = _pick_severity()
    if sev is _CANCEL:
        return None
    if sev:
        argv += ["--min-severity", sev]
    return argv


def _b_news(cfg) -> Optional[List[str]]:
    source = _choose("Advisory source", [
        ("All configured sources", None),
        ("CISA KEV (known-exploited)", "kev"),
        ("NVD recent", "nvd"),
        ("Distro errata (Alma/Rocky/Oracle)", "distro"),
    ])
    if source is _CANCEL:
        return None
    argv = ["news"]
    if source:
        argv += ["--source", source]
    if _ask_yesno("Fetch the latest now (needs network)?", False):
        argv.append("--refresh")
    limit = _ask("How many advisories to show", "30")
    if limit and limit.isdigit():
        argv += ["--limit", limit]
    return argv


def _b_dashboard(cfg) -> Optional[List[str]]:
    action = _choose("Web dashboard", [
        ("Start the dashboard server", "start"),
        ("Set or replace the login password", "pw"),
        ("Show the current configuration", "list"),
        ("Allow a network client (IP/CIDR)", "allow"),
        ("Remove a network client (IP/CIDR)", "deny"),
    ])
    if action is _CANCEL:
        return None
    if action == "pw":
        return ["dashboard", "--set-password"]
    if action == "list":
        return ["dashboard", "--list"]
    if action in ("allow", "deny"):
        ip = _ask("IP or CIDR", "")
        if not ip:
            return None
        return ["dashboard", f"--{action}", ip]
    # start
    argv = ["dashboard"]
    port = _ask("Listen port (blank = default 65101)", "")
    if port and port.isdigit():
        argv += ["--port", port]
    bind = _choose("Bind address", [
        ("Localhost only (127.0.0.1)", "127.0.0.1"),
        ("All interfaces (0.0.0.0)", "0.0.0.0"),  # nosec B104
    ])
    if bind is _CANCEL:
        return None
    argv += ["--bind", bind]
    return argv


def _b_scheduled(cfg) -> Optional[List[str]]:
    argv = ["scheduled"]
    toks = _pick_scanners(cfg)
    if toks is _CANCEL:
        return None
    argv += toks
    if _ask_yesno("Include an AI remediation plan in the report?", False):
        argv.append("--plan")
    if _ask_yesno("Write an HTML report instead of PDF?", False):
        argv.append("--html")
    failon = _choose("Exit non-zero when findings reach…", [
        ("Never (always exit 0)", None),
        ("low and above", "low"),
        ("moderate and above", "moderate"),
        ("important and above", "important"),
        ("critical only", "critical"),
    ])
    if failon is _CANCEL:
        return None
    if failon:
        argv += ["--fail-on", failon]
    return argv


def _b_update_oval(cfg) -> Optional[List[str]]:
    if not _ask_yesno("Download the OVAL feed now (can be tens of MB)?", True):
        return None
    return ["update-oval"]


# Top-level menu entries: (label, key). ``info``/``providers``/``setup`` take no
# options, so they build a trivial argv inline.
_TOP: List[Tuple[str, str]] = [
    ("Scan for vulnerabilities", "scan"),
    ("Fix findings (AI-assisted, approval-gated)", "fix"),
    ("Roll back an applied fix", "rollback"),
    ("Report from the last scan", "report"),
    ("Advisories / news feed", "news"),
    ("Host, FIPS & scanner status", "info"),
    ("AI providers", "providers"),
    ("Web dashboard", "dashboard"),
    ("Scheduled scan (non-interactive)", "scheduled"),
    ("Update the OVAL security feed", "update-oval"),
    ("Setup wizard", "setup"),
]

_BUILDERS = {
    "scan": _b_scan,
    "fix": _b_fix,
    "rollback": _b_rollback,
    "report": _b_report,
    "news": _b_news,
    "info": lambda cfg: ["info"],
    "providers": lambda cfg: ["providers"],
    "dashboard": _b_dashboard,
    "scheduled": _b_scheduled,
    "update-oval": _b_update_oval,
    "setup": lambda cfg: ["setup"],
}


# --------------------------------------------------------------------------- #
# main loop
# --------------------------------------------------------------------------- #
def _run_command(cfg, parser, argv: List[str]) -> None:
    """Parse the built argv with the real CLI parser and dispatch it, so the
    command behaves exactly as if it had been typed."""
    from .ai import ProviderError
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        _eprint("Could not build that command.")
        return
    try:
        rc = args.func(cfg, args)
        if rc not in (0, None):
            print(f"\n(command exited with status {rc})")
    except ProviderError as exc:
        _eprint(f"AI provider error: {exc}")
    except KeyboardInterrupt:
        _eprint("\nInterrupted.")


def run_menu(cfg, parser) -> int:
    """Interactive front-end loop. `parser` is the CLI's build_parser() result."""
    subtitle = f"host {socket.gethostname()} · v{__version__}"
    while True:
        key = _choose("vulnscan·ai — interactive menu", _TOP, subtitle=subtitle)
        if key is _CANCEL:
            print("Bye.")
            return 0
        argv = _BUILDERS[key](cfg)
        if argv is None or argv is _CANCEL:
            continue
        print()
        _run_command(cfg, parser, argv)
        _pause()
