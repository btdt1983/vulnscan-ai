# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Native RHEL scanner: dnf/yum updateinfo + Red Hat Security Advisories.

This is the most authoritative source for a RHEL-based host. It asks the
package manager which installed packages are affected by published security
advisories (RHSA) and which CVEs those advisories address, using the OVAL
security metadata shipped in the repositories.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from ..models import Finding
from .base import Scanner, have, run

_KNOWN_ARCHES = {
    "x86_64", "noarch", "aarch64", "i686", "i386",
    "s390x", "ppc64le", "ppc64", "armv7hl", "src",
}

# e.g.  CVE-2024-1234 Important/Sec. kernel-5.14.0-427.el9.x86_64
_CVE_LINE = re.compile(
    r"^(?P<cve>CVE-\d{4}-\d+)\s+(?P<sev>\S+)\s+(?P<nevra>\S+)\s*$"
)
# e.g.  RHSA-2024:1234 Important/Sec. kernel-5.14.0-427.el9.x86_64
_ADV_LINE = re.compile(
    r"^(?P<adv>(?:RH[SBE]A|FEDORA|ALSA|ELSA)-\d{4}[:-]\d+)\s+(?P<sev>\S+)\s+(?P<nevra>\S+)\s*$"
)


def parse_nevra(nevra: str) -> Tuple[str, Optional[str], Optional[str]]:
    """Split name-[epoch:]version-release.arch into (name, evr, arch)."""
    arch = None
    rest = nevra
    if "." in nevra:
        head, tail = nevra.rsplit(".", 1)
        if tail in _KNOWN_ARCHES:
            arch, rest = tail, head
    parts = rest.rsplit("-", 2)
    if len(parts) == 3:
        name, version, release = parts
        return name, f"{version}-{release}", arch
    return rest, None, arch


class DnfRhsaScanner(Scanner):
    name = "dnf"

    def __init__(self, config) -> None:
        super().__init__(config)
        self.pm = "dnf" if have("dnf") else ("yum" if have("yum") else None)

    def available(self) -> bool:
        return self.pm is not None

    def _installed_version(self, package: str) -> Optional[str]:
        rc, out, _ = run(["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", package])
        if rc == 0 and out and "is not installed" not in out:
            return out.strip()
        return None

    def _advisory_map(self) -> Dict[str, Tuple[str, str]]:
        """Map fixed-package nevra -> (advisory_id, severity)."""
        mapping: Dict[str, Tuple[str, str]] = {}
        rc, out, _ = run([self.pm, "-q", "updateinfo", "list", "--security", "--available"])
        if rc not in (0, 100):  # 100 = updates available
            return mapping
        for line in out.splitlines():
            m = _ADV_LINE.match(line.strip())
            if m:
                sev = m.group("sev").split("/")[0]
                mapping[m.group("nevra")] = (m.group("adv"), sev)
        return mapping

    def scan(self) -> List[Finding]:
        if not self.available():
            return []
        adv_map = self._advisory_map()

        rc, out, err = run([self.pm, "-q", "updateinfo", "list", "cves"])
        if rc not in (0, 100):
            # No security metadata or repos unreachable: surface nothing rather
            # than guessing.
            return []

        # Group CVE rows by the fixed package nevra so one update == one finding.
        by_nevra: Dict[str, Dict] = {}
        for line in out.splitlines():
            m = _CVE_LINE.match(line.strip())
            if not m:
                continue
            nevra = m.group("nevra")
            sev = m.group("sev").split("/")[0]
            entry = by_nevra.setdefault(
                nevra, {"cves": set(), "severity": sev}
            )
            entry["cves"].add(m.group("cve"))

        findings: List[Finding] = []
        for nevra, entry in by_nevra.items():
            name, evr, _arch = parse_nevra(nevra)
            advisory, adv_sev = adv_map.get(nevra, (None, None))
            severity = adv_sev or entry["severity"] or "unknown"
            cves = sorted(entry["cves"])
            refs = [f"https://access.redhat.com/security/cve/{c}" for c in cves]
            if advisory:
                rhsa_id = advisory.replace(":", "-")
                refs.insert(0, f"https://access.redhat.com/errata/{rhsa_id}")
            findings.append(
                Finding(
                    source=self.name,
                    title=f"{name}: {len(cves)} security update(s) available",
                    cve_ids=cves,
                    severity=severity,
                    package=name,
                    installed_version=self._installed_version(name),
                    fixed_version=evr,
                    advisory=advisory,
                    description=(
                        f"Package {name} is affected by {len(cves)} published "
                        f"CVE(s). A fixed build ({evr}) is available via {self.pm}."
                    ),
                    references=refs,
                    raw={"nevra": nevra},
                )
            )
        return findings
