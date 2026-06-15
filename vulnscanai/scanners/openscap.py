"""OpenSCAP (oscap) OVAL-based CVE scanner.

Uses the Red Hat OVAL feed to evaluate the host for known vulnerabilities.
This complements the dnf scanner and is the basis for SCAP/STIG compliance
reporting in FIPS-regulated environments. If oscap or the OVAL feed are not
present the scanner reports itself unavailable and is skipped.
"""

from __future__ import annotations

import glob
import os
import re
import tempfile
from typing import List, Optional
from xml.etree import ElementTree as ET

from ..models import Finding
from .base import Scanner, have, run

# Candidate locations for a pre-staged RHEL OVAL definition file.
_OVAL_GLOBS = [
    "/usr/share/xml/scap/ssg/content/*-oval.xml",
    "/var/lib/vulnscan-ai/oval/*.xml",
    os.path.expanduser("~/.local/state/vulnscan-ai/oval/*.xml"),
]

_NS = {"r": "http://oval.mitre.org/XMLSchema/oval-results-5"}


class OpenScapScanner(Scanner):
    name = "oscap"

    def available(self) -> bool:
        return have("oscap") and self._oval_file() is not None

    def _oval_file(self) -> Optional[str]:
        patterns = list(_OVAL_GLOBS)
        # Prefer a feed staged by `vulnscan-ai update-oval` in the state dir.
        state_dir = getattr(self.config, "state_dir", None)
        if state_dir:
            patterns.insert(0, os.path.join(state_dir, "oval", "*.xml"))
        for pattern in patterns:
            matches = sorted(glob.glob(pattern))
            if matches:
                return matches[-1]
        return None

    def scan(self) -> List[Finding]:
        oval = self._oval_file()
        if not have("oscap") or not oval:
            return []
        with tempfile.TemporaryDirectory(prefix="vulnscanai-oscap-") as tmp:
            results = os.path.join(tmp, "results.xml")
            run([
                "oscap", "oval", "eval",
                "--results", results,
                oval,
            ], timeout=900)
            if not os.path.isfile(results):
                return []
            return self._parse_results(results, oval)

    def _parse_results(self, results_path: str, oval_path: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            tree = ET.parse(results_path)
        except ET.ParseError:
            return findings
        root = tree.getroot()
        # Definitions that evaluated "true" are present vulnerabilities.
        for definition in root.iter("{http://oval.mitre.org/XMLSchema/oval-results-5}definition"):
            if definition.get("result") != "true":
                continue
            def_id = definition.get("definition_id", "")
            cves = sorted(set(re.findall(r"CVE-\d{4}-\d+", def_id)))
            findings.append(
                Finding(
                    source=self.name,
                    title=f"OVAL definition {def_id} matched",
                    cve_ids=cves,
                    severity="unknown",
                    description=(
                        "OpenSCAP OVAL evaluation flagged this definition as "
                        "present on the host."
                    ),
                    references=[
                        f"https://access.redhat.com/security/cve/{c}" for c in cves
                    ],
                    raw={"definition_id": def_id, "oval": os.path.basename(oval_path)},
                )
            )
        return findings
