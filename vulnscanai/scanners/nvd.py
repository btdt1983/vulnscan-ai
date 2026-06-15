"""CVE enrichment from public vulnerability databases.

Adds CVSS scores, vectors and human-readable descriptions to findings by
querying the Red Hat Security Data API and, as a fallback, the NIST NVD API.
These are the "vulnerability websites" the tool searches against.
"""

from __future__ import annotations

import time
from typing import List, Optional

from .. import http
from ..models import Finding


class NvdEnricher:
    """Not a detection scanner: it augments findings produced by others."""

    name = "nvd"

    def __init__(self, config) -> None:
        self.config = config

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
        return True

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
