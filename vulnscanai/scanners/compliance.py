# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Compliance-benchmark scanner (XCCDF via OpenSCAP / SCAP Security Guide).

Where the `oscap` OVAL scanner answers "which CVEs affect this host", this one
answers "does this host meet a hardening benchmark" — CIS, DISA STIG, PCI-DSS,
HIPAA, ANSSI, ... — by running `oscap xccdf eval` against a profile in the
distro's SCAP Security Guide datastream and reporting the compliance score plus
each failing rule.

It is deliberately NOT in the default SCANNERS registry: an XCCDF evaluation is
a minutes-long full-system audit, so it is a distinct, explicitly-selected mode
(`scan --compliance <profile>`) rather than something `scan --all` runs.

Parsing is split into small pure helpers (profile listing, alias resolution,
rule metadata, results) so they are unit-testable without an oscap run — the
same pattern as the OVAL scanner. XML is parsed with ElementTree, which resolves
no external entities/DTDs (no XXE), on files we produced or the distro shipped.
"""

from __future__ import annotations

import glob
import os
import tempfile
from typing import Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

from ..models import ComplianceReport, ComplianceRule, XCCDF_SEVERITY_ALIAS
from .base import have, run
from .oval import detect_distro

# Candidate locations for a SCAP Security Guide datastream (scap-security-guide
# package). Filenames follow ssg-<distro><major>-ds.xml (e.g. ssg-rhel9-ds.xml).
_SSG_DIR = "/usr/share/xml/scap/ssg/content"

# Friendly aliases -> the profile-id suffix after "..._profile_". Resolution also
# accepts a bare suffix or a full profile id, so these are conveniences, not the
# only accepted spellings. Exact ids vary per datastream; resolve_profile()
# always validates against what the host's datastream actually offers.
PROFILE_ALIASES: Dict[str, str] = {
    "cis": "cis",                       # distro default (on RHEL-likes: L2 server)
    "cis-l1": "cis_server_l1",
    "cis-l2": "cis",
    "cis-server-l1": "cis_server_l1",
    "cis-server-l2": "cis",
    "cis-workstation-l1": "cis_workstation_l1",
    "cis-workstation-l2": "cis_workstation_l2",
    "cis-ws-l1": "cis_workstation_l1",
    "cis-ws-l2": "cis_workstation_l2",
    "stig": "stig",
    "stig-gui": "stig_gui",
    "pci": "pci-dss",
    "pci-dss": "pci-dss",
    "hipaa": "hipaa",
    "ospp": "ospp",
    "cui": "cui",
    "nist-800-171": "cui",
    "e8": "e8",
    "essential8": "e8",
    "anssi-minimal": "anssi_bp28_minimal",
    "anssi-intermediary": "anssi_bp28_intermediary",
    "anssi-enhanced": "anssi_bp28_enhanced",
    "anssi-high": "anssi_bp28_high",
}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


# --------------------------------------------------------------------------- #
# datastream / profile discovery (pure helpers + host lookups)
# --------------------------------------------------------------------------- #
def candidate_datastreams(distro_id: str, major: str) -> List[str]:
    """SSG datastream basenames to try, most-specific first (incl. RHEL-like
    fallbacks so CentOS/Rocky/Alma resolve to their own or a rhel stream)."""
    names = [f"ssg-{distro_id}{major}-ds.xml"]
    if distro_id not in ("rhel",):
        names.append(f"ssg-rhel{major}-ds.xml")
    if distro_id not in ("centos",):
        names.append(f"ssg-centos{major}-ds.xml")
    seen: Dict[str, None] = {}
    return [n for n in names if not (n in seen or seen.setdefault(n, None))]


def find_datastream(explicit: Optional[str] = None,
                    ssg_dir: str = _SSG_DIR) -> Optional[str]:
    """Locate a SCAP datastream: an explicit path wins, else the one matching
    this distro, else any ssg-*-ds.xml present."""
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    distro_id, major = detect_distro()
    for name in candidate_datastreams(distro_id, major):
        path = os.path.join(ssg_dir, name)
        if os.path.isfile(path):
            return path
    matches = sorted(glob.glob(os.path.join(ssg_dir, "ssg-*-ds.xml")))
    return matches[-1] if matches else None


def parse_profiles(text: str) -> List[Tuple[str, str]]:
    """Parse `oscap info --profiles <ds>` output into [(profile_id, title)].

    Each line is `xccdf_...content_profile_<id>:<Title>`. The id itself never
    contains a colon, so split on the first one only.
    """
    out: List[Tuple[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or ":" not in line or "_profile_" not in line:
            continue
        pid, _, title = line.partition(":")
        pid = pid.strip()
        if pid:
            out.append((pid, title.strip()))
    return out


def _profile_suffix(profile_id: str) -> str:
    marker = "_profile_"
    idx = profile_id.rfind(marker)
    return profile_id[idx + len(marker):] if idx >= 0 else profile_id


def resolve_profile(requested: str,
                    available: List[Tuple[str, str]]) -> Optional[str]:
    """Map a user-supplied profile spec to a real profile id in `available`.

    Accepts a full profile id, a bare suffix (e.g. `cis_server_l1`), or a
    friendly alias (`cis-l1`, `stig`, `pci`). Returns None if nothing matches.
    """
    req = (requested or "").strip()
    if not req:
        return None
    ids = [pid for pid, _ in available]
    suffix_map = {_profile_suffix(pid).lower(): pid for pid in ids}
    # 1. exact full id
    if req in ids:
        return req
    lower = req.lower()
    # 2. alias -> suffix
    suffix = PROFILE_ALIASES.get(lower)
    if suffix and suffix.lower() in suffix_map:
        return suffix_map[suffix.lower()]
    # 3. bare suffix (accept both - and _ spellings)
    for cand in (lower, lower.replace("-", "_")):
        if cand in suffix_map:
            return suffix_map[cand]
    return None


# --------------------------------------------------------------------------- #
# XCCDF metadata + results parsing
# --------------------------------------------------------------------------- #
def parse_xccdf_rules(datastream_path: str) -> Dict[str, dict]:
    """Stream the datastream for Rule metadata: id -> {title, severity, fix,
    references}. severity is normalised to the shared severity scale."""
    out: Dict[str, dict] = {}
    try:
        # Distro-shipped datastream; ElementTree resolves no external entities.
        context = ET.iterparse(datastream_path, events=("end",))  # nosec B314
    except (OSError, ET.ParseError):
        return out
    try:
        for _event, elem in context:
            if _local(elem.tag) != "Rule":
                continue
            rid = elem.get("id", "")
            if not rid:
                elem.clear()
                continue
            raw_sev = (elem.get("severity") or "unknown").lower()
            title, refs, has_fix = "", [], False
            for child in elem.iter():
                lname = _local(child.tag)
                if lname == "title" and child.text and not title:
                    title = child.text.strip()
                elif lname == "fix":
                    has_fix = True
                elif lname == "ident" and child.text:
                    refs.append(child.text.strip())
            out[rid] = {
                "title": title,
                "severity": XCCDF_SEVERITY_ALIAS.get(raw_sev, "unknown"),
                "fix_available": has_fix,
                "references": refs,
            }
            elem.clear()
    except ET.ParseError:
        pass
    return out


def parse_xccdf_results(results_path: str) -> Tuple[float, Dict[str, str],
                                                    Dict[str, str]]:
    """Parse an XCCDF results file into (score, {rule_id: result},
    {rule_id: raw_severity}).

    The TestResult carries one <rule-result idref=... severity=...> per rule with
    a child <result> outcome, and a <score> node (0-100). Severity here is a
    fallback for rules missing from the benchmark metadata.
    """
    results: Dict[str, str] = {}
    severities: Dict[str, str] = {}
    score = 0.0
    try:
        # Results file we just produced with `oscap xccdf eval`.
        tree = ET.parse(results_path)  # nosec B314
    except (OSError, ET.ParseError):
        return score, results, severities
    for elem in tree.getroot().iter():
        lname = _local(elem.tag)
        if lname == "rule-result":
            rid = elem.get("idref", "")
            if not rid:
                continue
            sev = (elem.get("severity") or "").lower()
            if sev:
                severities[rid] = sev
            for child in elem:
                if _local(child.tag) == "result" and child.text:
                    results[rid] = child.text.strip().lower()
                    break
        elif lname == "score":
            try:
                score = float((elem.text or "0").strip())
            except ValueError:
                pass
    return score, results, severities


def build_report(profile: str, profile_title: str, datastream: str,
                 rule_meta: Dict[str, dict], score: float,
                 results: Dict[str, str], severities: Dict[str, str],
                 hostname: str = "", generated: str = "") -> ComplianceReport:
    """Combine benchmark metadata + evaluation results into a ComplianceReport."""
    rules: List[ComplianceRule] = []
    for rid, result in results.items():
        # "notselected" means the rule is not part of this profile at all — it
        # was never evaluated, so it does not belong in the report (a full SSG
        # datastream carries ~1500 rules; a profile selects a few dozen).
        if result == "notselected":
            continue
        meta = rule_meta.get(rid, {})
        severity = meta.get("severity")
        if not severity or severity == "unknown":
            raw = severities.get(rid, "")
            severity = XCCDF_SEVERITY_ALIAS.get(raw, "unknown")
        title = meta.get("title") or _readable_rule_id(rid)
        rules.append(ComplianceRule(
            rule_id=rid,
            title=title,
            result=result,
            severity=severity,
            fix_available=bool(meta.get("fix_available")),
            references=list(meta.get("references", [])),
        ))
    return ComplianceReport(
        profile=profile,
        profile_title=profile_title,
        datastream=os.path.basename(datastream),
        score=score,
        rules=rules,
        hostname=hostname,
        generated=generated,
    )


def _readable_rule_id(rule_id: str) -> str:
    """Fallback title from a rule id, e.g. ..._rule_sshd_disable_root_login ->
    'sshd disable root login'."""
    marker = "_rule_"
    idx = rule_id.rfind(marker)
    stem = rule_id[idx + len(marker):] if idx >= 0 else rule_id
    return stem.replace("_", " ").strip() or rule_id


# --------------------------------------------------------------------------- #
# scanner
# --------------------------------------------------------------------------- #
class ComplianceScanner:
    """Runs one XCCDF profile evaluation. Not a Scanner subclass (it yields a
    ComplianceReport, not Findings) and not in the SCANNERS registry."""

    name = "compliance"

    def __init__(self, config) -> None:
        self.config = config
        self.datastream = find_datastream(
            getattr(config, "compliance_datastream", None))

    def available(self) -> bool:
        return have("oscap") and self.datastream is not None

    def list_profiles(self) -> List[Tuple[str, str]]:
        if not self.available():
            return []
        rc, out, _ = run(["oscap", "info", "--profiles", self.datastream],
                         timeout=60)
        return parse_profiles(out) if rc == 0 or out else []

    def resolve(self, requested: str) -> Optional[str]:
        return resolve_profile(requested, self.list_profiles())

    def evaluate(self, profile_id: str, profile_title: str = "",
                 hostname: str = "", generated: str = "",
                 timeout: int = 1800) -> Optional[ComplianceReport]:
        """Run `oscap xccdf eval` for one profile and return a ComplianceReport.

        oscap exits non-zero (2) when rules fail — that is a normal result, not
        an error, so we key off the results file being produced, not the code.
        """
        if not self.available():
            return None
        rule_meta = parse_xccdf_rules(self.datastream)
        with tempfile.TemporaryDirectory(prefix="vulnscanai-xccdf-") as tmp:
            results = os.path.join(tmp, "results.xml")
            run(["oscap", "xccdf", "eval", "--profile", profile_id,
                 "--results", results, self.datastream], timeout=timeout)
            if not os.path.isfile(results):
                return None
            score, outcomes, severities = parse_xccdf_results(results)
        return build_report(profile_id, profile_title, self.datastream,
                            rule_meta, score, outcomes, severities,
                            hostname=hostname, generated=generated)
