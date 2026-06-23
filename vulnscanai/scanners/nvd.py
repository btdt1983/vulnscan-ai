# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""CVE enrichment from public vulnerability databases.

Adds CVSS scores, vectors and human-readable descriptions to findings by
querying the Red Hat Security Data API and, as a fallback, the NIST NVD API.
These are the "vulnerability websites" the tool searches against.
"""

from __future__ import annotations

import time
from typing import Any, List, Optional

from .. import http
from ..models import VENDOR_NO_FIX_STATES, Finding
from .oval import detect_distro

# How "actionable" each Red Hat fix state is. When a CVE lists several entries
# for the same package/product we keep the most-affected one, so a finding that
# is "affected" in one entry is never suppressed by a "not affected" in another.
_STATE_ACTIONABILITY = {
    "affected": 5,
    "fix deferred": 4,
    "under investigation": 3,
    "new": 3,
    "will not fix": 2,
    "out of support scope": 2,
    "not affected": 1,
}


def _cpe_major(cpe: str) -> Optional[str]:
    """Major version from a Red Hat enterprise_linux CPE, else None.

    e.g. 'cpe:/o:redhat:enterprise_linux:9' / '...:9::baseos' -> '9'.
    """
    parts = (cpe or "").split(":")
    for i, seg in enumerate(parts):
        if seg == "enterprise_linux" and i + 1 < len(parts):
            ver = parts[i + 1]
            return ver.split(".")[0] if ver else None
    return None


def _package_matches(entry_pkg: str, finding_pkg: str) -> bool:
    """True if a package_state entry refers to the finding's package.

    Conservative on purpose: exact match, or a subpackage that shares the
    source name as a prefix (openssl -> openssl-libs). Never the reverse, so a
    real finding is not silently dropped on a loose match.
    """
    if not entry_pkg or not finding_pkg:
        return False
    return entry_pkg == finding_pkg or finding_pkg.startswith(entry_pkg + "-")


def select_package_state(package_state: Any, major: Optional[str],
                         package: Optional[str]) -> Optional[str]:
    """Return Red Hat's fix_state for `package` on RHEL `major`, or None."""
    if not package or not major or not isinstance(package_state, list):
        return None
    best: Optional[str] = None
    best_rank = -1
    for entry in package_state:
        if not isinstance(entry, dict):
            continue
        if _cpe_major(entry.get("cpe", "")) != major:
            continue
        if not _package_matches(entry.get("package_name", "") or "", package):
            continue
        state = (entry.get("fix_state") or "").strip().lower()
        rank = _STATE_ACTIONABILITY.get(state, 0)
        if rank > best_rank:
            best, best_rank = state, rank
    return best


class NvdEnricher:
    """Not a detection scanner: it augments findings produced by others."""

    name = "nvd"

    def __init__(self, config) -> None:
        self.config = config
        try:
            _, self._major = detect_distro()
        except Exception:  # noqa: BLE001
            self._major = None

    def enrich(self, findings: List[Finding]) -> List[Finding]:
        if not self.config.enrich:
            return findings
        for f in findings:
            cve = f.primary_cve
            if not cve:
                continue
            try:
                if self._enrich_redhat(f, cve):
                    continue
                self._enrich_nvd(f, cve)
            except http.HttpError:
                # Network/feed problems must never abort a scan.
                continue
        return findings

    def _enrich_redhat(self, f: Finding, cve: str) -> bool:
        url = f"{self.config.redhat_api}/cve/{cve}.json"
        try:
            data = http.get_json(url, timeout=self.config.timeout)
        except http.HttpError:
            return False
        if not isinstance(data, dict):
            return False
        cvss3 = data.get("cvss3") or {}
        score = cvss3.get("cvss3_base_score")
        if score is not None:
            try:
                f.cvss_score = float(score)
            except (TypeError, ValueError):
                pass
        f.cvss_vector = cvss3.get("cvss3_scoring_vector") or f.cvss_vector
        if data.get("threat_severity") and f.severity in ("", "unknown"):
            f.severity = str(data["threat_severity"]).lower()
        details = data.get("details") or []
        if details and not f.description.strip().endswith(details[0][:20]):
            f.description = (f.description + "\n\n" + " ".join(details)).strip()
        self._annotate_vendor_state(f, data)
        return True

    def _annotate_vendor_state(self, f: Finding, data: dict) -> None:
        """Record Red Hat's per-product fix state on the finding.

        "not affected" is left for `apply_vendor_states` to drop; the won't-fix
        family is annotated so the report and the AI know no dnf update exists.
        """
        state = select_package_state(data.get("package_state"), self._major,
                                     f.package)
        if not state:
            return
        f.vendor_fix_state = state
        if state in VENDOR_NO_FIX_STATES:
            note = (f"[vendor] Red Hat marks this '{state}' for RHEL "
                    f"{self._major}: no dnf security update will ship; "
                    f"mitigate manually.")
            if note not in f.description:
                f.description = (f.description + "\n\n" + note).strip()

    def _enrich_nvd(self, f: Finding, cve: str) -> Optional[bool]:
        headers = {}
        if self.config.nvd_api_key:
            headers["apiKey"] = self.config.nvd_api_key
        else:
            # NVD throttles anonymous callers hard; be polite.
            time.sleep(0.7)
        url = f"{self.config.nvd_api}?cveId={cve}"
        data = http.get_json(url, headers=headers, timeout=self.config.timeout)
        vulns = data.get("vulnerabilities") or []
        if not vulns:
            return False
        cve_obj = vulns[0].get("cve", {})
        descs = cve_obj.get("descriptions", [])
        for d in descs:
            if d.get("lang") == "en":
                if d["value"] not in f.description:
                    f.description = (f.description + "\n\n" + d["value"]).strip()
                break
        metrics = cve_obj.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                cvss = metrics[key][0].get("cvssData", {})
                if f.cvss_score is None and cvss.get("baseScore") is not None:
                    f.cvss_score = float(cvss["baseScore"])
                f.cvss_vector = f.cvss_vector or cvss.get("vectorString")
                break
        return True
