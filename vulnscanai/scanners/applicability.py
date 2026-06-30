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

from typing import List, Optional, Set

from ..models import VENDOR_NO_FIX_STATES, Finding
from .base import have, run

_ARCHES = {"x86_64", "noarch", "i686", "i386", "aarch64", "ppc64le", "s390x",
           "src"}


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


class PatchedStateEnricher:
    name = "patched"

    def __init__(self, config) -> None:
        self.config = config

    def available(self) -> bool:
        return have("dnf") or have("yum")

    def upgradable(self) -> Optional[Set[str]]:
        """The set of packages with an installable update, or None on error."""
        pm = "dnf" if have("dnf") else "yum"
        rc, out, _ = run([pm, "-q", "check-update"], timeout=180)
        # 0 = nothing to update, 100 = updates listed; anything else is an error
        # (no repos, network down) -> signal "unknown" so we drop nothing.
        if rc not in (0, 100):
            return None
        return parse_check_update(out)

    def enrich(self, findings: List[Finding]) -> List[Finding]:
        upgradable = self.upgradable()
        if upgradable is None:
            return findings
        for f in findings:
            if f.source not in ("dnf", "oscap") or not f.package:
                continue
            # Only act on findings that carry a real fix (came from repo
            # metadata); leave won't-fix advisories for manual mitigation.
            if not (f.advisory or f.fixed_version):
                continue
            if (f.vendor_fix_state or "").strip().lower() in VENDOR_NO_FIX_STATES:
                continue
            if f.package not in upgradable:
                f.already_patched = True
        return findings
