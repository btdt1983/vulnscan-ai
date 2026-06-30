# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""OpenSCAP (oscap) OVAL-based CVE scanner.

Uses a published OVAL feed to evaluate the host for known vulnerabilities. Only
*patch*/*vulnerability* class definitions that evaluate true are reported — the
feed also contains `inventory` definitions (e.g. "the OS is installed") that are
true on every host and must never be flagged. CVE ids and severity come from the
definition metadata, not a regex on the definition id.
"""

from __future__ import annotations

import glob
import os
import re
import tempfile
from typing import Dict, List, Optional
from xml.etree import ElementTree as ET

from ..models import Finding
from .base import Scanner, have, run

# Candidate locations for a pre-staged OVAL definition file.
_OVAL_GLOBS = [
    "/usr/share/xml/scap/ssg/content/*-oval.xml",
    "/var/lib/vulnscan-ai/oval/*.xml",
    os.path.expanduser("~/.local/state/vulnscan-ai/oval/*.xml"),
]

# Definition classes we treat as real vulnerabilities. Everything else
# (inventory, compliance, miscellaneous) is informational and dropped.
_VULN_CLASSES = {"patch", "vulnerability"}
_ADVISORY_RE = re.compile(r"\b([A-Z]{2,5}-\d{4}:\d+)\b")
_SEVERITY_RE = re.compile(r"\((Critical|Important|Moderate|Low)\)")
_SEV_MAP = {"critical": "critical", "important": "important",
            "moderate": "moderate", "low": "low"}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_oval_definitions(oval_path: str) -> Dict[str, dict]:
    """Map OVAL definition id -> {class, title, cves, advisory, severity}.

    Streams the (large) feed with iterparse so we don't hold it all in memory.
    """
    out: Dict[str, dict] = {}
    try:
        # OVAL feed downloaded from the distro's official source over TLS;
        # ElementTree resolves no external entities/DTDs (no XXE file read).
        context = ET.iterparse(oval_path, events=("end",))  # nosec B314
    except (OSError, ET.ParseError):
        return out
    try:
        for _event, elem in context:
            if _local(elem.tag) != "definition":
                continue
            def_id = elem.get("id", "")
            klass = elem.get("class", "")
            title, cves, advisory, severity = "", [], None, "unknown"
            for child in elem.iter():
                lname = _local(child.tag)
                if lname == "title" and child.text:
                    title = child.text.strip()
                elif lname == "reference" and child.get("source") == "CVE":
                    rid = child.get("ref_id")
                    if rid:
                        cves.append(rid)
                elif lname == "severity" and child.text:
                    severity = _SEV_MAP.get(child.text.strip().lower(), severity)
            if severity == "unknown" and title:
                m = _SEVERITY_RE.search(title)
                if m:
                    severity = _SEV_MAP[m.group(1).lower()]
            if title:
                m = _ADVISORY_RE.search(title)
                if m:
                    advisory = m.group(1)
            out[def_id] = {"class": klass, "title": title,
                           "cves": sorted(set(cves)), "advisory": advisory,
                           "severity": severity}
            elem.clear()  # free memory as we stream
    except ET.ParseError:
        pass
    return out


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
            run(["oscap", "oval", "eval", "--results", results, oval],
                timeout=900)
            if not os.path.isfile(results):
                return []
            return self._parse_results(results, oval)

    def _parse_results(self, results_path: str, oval_path: str) -> List[Finding]:
        defs = parse_oval_definitions(oval_path)
        findings: List[Finding] = []
        try:
            # Results file produced locally by `oscap` from our own scan run.
            tree = ET.parse(results_path)  # nosec B314
        except ET.ParseError:
            return findings
        ns = "{http://oval.mitre.org/XMLSchema/oval-results-5}"
        for definition in tree.getroot().iter(f"{ns}definition"):
            if definition.get("result") != "true":
                continue
            def_id = definition.get("definition_id", "")
            meta = defs.get(def_id)
            # Only report confirmed patch/vulnerability definitions; drop
            # inventory/compliance (e.g. "OS is installed") and anything we
            # cannot confirm is a vulnerability.
            if not meta or meta["class"] not in _VULN_CLASSES:
                continue
            cves = meta["cves"]
            findings.append(Finding(
                source=self.name,
                title=meta["title"] or f"OVAL definition {def_id}",
                cve_ids=cves,
                severity=meta["severity"],
                advisory=meta["advisory"],
                description=("OpenSCAP OVAL evaluation found this advisory "
                             "applies to the host (an affected package is "
                             "installed below the fixed version)."),
                references=[f"https://access.redhat.com/security/cve/{c}"
                            for c in cves],
                raw={"definition_id": def_id, "class": meta["class"],
                     "oval": os.path.basename(oval_path)},
            ))
        return findings
