# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Already-patched (applicability) enricher.

The `dnf`/`oscap` scanners report an advisory whenever a vulnerable package
*version* is present. For multi-version (installonly) packages — the kernel
above all — old builds linger on disk after an update, so the scanners keep
listing historical advisories that `dnf` can no longer act on: `dnf update
--advisory=ALSA-...` just says "Nothing to do" because the newest build is
already installed.

This enricher asks `dnf check-update` — the authoritative "what would actually
install" set — and marks a finding `already_patched` when its package has a fix
in the repo metadata (it carries an advisory) but no installable update. The
won't-fix family (annotated by the vendor-state enricher) is left alone, since
those genuinely have no fix. `models.apply_patched_states` then drops the marked
findings. Local (`dnf check-update`); fails safe — if the set can't be
determined, nothing is dropped.
"""

from __future__ import annotations

import re
from typing import List, Optional, Set

from ..models import VENDOR_NO_FIX_STATES, Finding
from .base import have, run

_ARCHES = {"x86_64", "noarch", "i686", "i386", "aarch64", "ppc64le", "s390x",
           "src"}
_ADVISORY_RE = re.compile(
    r"(?:RH[SBE]A|AL[SBE]A|ELSA|RLSA|CESA)-?\d{4}[:\-]\d+", re.I)


def parse_check_update(text: str) -> Set[str]:
    """Package base names (arch stripped) from `dnf check-update` output."""
    names: Set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # The trailing "Obsoleting Packages" section isn't an upgrade list.
        if line.lower().startswith("obsoleting"):
            break
        parts = line.split()
        # Real rows look like: name.arch  epoch:ver-rel  repo
        if len(parts) < 3 or "." not in parts[0]:
            continue
        name, _, arch = parts[0].rpartition(".")
        names.add(name if arch in _ARCHES else parts[0])
    return names


def parse_updateinfo_advisories(text: str) -> Set[str]:
    """Advisory ids from `dnf updateinfo list` output (one per line, col 1)."""
    out: Set[str] = set()
    for line in text.splitlines():
        m = _ADVISORY_RE.match(line.strip())
        if m:
            out.add(m.group(0))
    return out


class PatchedStateEnricher:
    name = "patched"

    def __init__(self, config) -> None:
        self.config = config

    def available(self) -> bool:
        return have("dnf") or have("yum")

    def _pm(self) -> str:
        return "dnf" if have("dnf") else "yum"

    def upgradable(self) -> Optional[Set[str]]:
        """Packages with an installable update, or None on error."""
        rc, out, _ = run([self._pm(), "-q", "check-update"], timeout=180)
        # 0 = nothing to update, 100 = updates listed; anything else is an error
        # (no repos, network down) -> signal "unknown" so we drop nothing.
        if rc not in (0, 100):
            return None
        return parse_check_update(out)

    def actionable_advisories(self) -> Optional[Set[str]]:
        """Advisory ids that actually have an installable update, or None.

        `updateinfo list --updates` is the realistic set: it excludes advisories
        already satisfied by an installed (or newer) build — unlike `--available`,
        which still lists a superseded kernel advisory.
        """
        rc, out, _ = run([self._pm(), "-q", "updateinfo", "list", "--updates"],
                         timeout=180)
        if rc not in (0, 100):
            return None
        return parse_updateinfo_advisories(out)

    def enrich(self, findings: List[Finding]) -> List[Finding]:
        upgradable = self.upgradable()
        actionable = self.actionable_advisories()
        # An EMPTY updateinfo set is ambiguous: it can mean "nothing actionable"
        # OR "updateinfo metadata isn't populated" (minimal repos / stale cache).
        # Treat only a NON-empty set as an authoritative advisory signal, so a
        # package-less oscap finding is never dropped on the strength of an empty
        # set alone — that would silently hide a real, unpatched advisory.
        if not actionable:
            actionable = None
        if upgradable is None and actionable is None:
            return findings                      # no usable signal -> drop nothing
        for f in findings:
            if f.source not in ("dnf", "oscap"):
                continue
            # Only act on findings that carry a real fix (repo metadata);
            # leave won't-fix advisories for manual mitigation.
            if not (f.advisory or f.fixed_version or f.package):
                continue
            if (f.vendor_fix_state or "").strip().lower() in VENDOR_NO_FIX_STATES:
                continue
            # Collect every authoritative "is this actionable?" signal we have
            # for this finding; drop only when ALL of them say no. oscap findings
            # carry an advisory but no package, so the advisory signal is key.
            signals = []
            if f.package and upgradable is not None:
                signals.append(f.package in upgradable)
            if f.advisory and actionable is not None:
                signals.append(f.advisory in actionable)
            if signals and not any(signals):
                f.already_patched = True
        return findings
