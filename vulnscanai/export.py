# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Machine-readable exports for ticketing / code-scanning ingestion.

  * JSON  - a flat, stable document (tool metadata + summary + findings).
  * SARIF - SARIF 2.1.0, consumable by GitHub code scanning, DefectDojo,
            and most vulnerability-management pipelines.
"""

from __future__ import annotations

from typing import Dict, List

from . import __version__
from .models import ComplianceReport, Finding

INFO_URI = "https://example.invalid/vulnscan-ai"


def _summary(findings: List[Finding]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for f in findings:
        key = f.severity.lower() or "unknown"
        key = {"high": "important", "medium": "moderate"}.get(key, key)
        out[key] = out.get(key, 0) + 1
    out["total"] = len(findings)
    return out


def build_json(findings: List[Finding], hostname: str, generated: str) -> Dict:
    return {
        "tool": "vulnscan-ai",
        "version": __version__,
        "host": hostname,
        "generated": generated,
        "summary": _summary(findings),
        "findings": [f.to_dict() for f in findings],
    }


# --------------------------------------------------------------------------- #
# SARIF
# --------------------------------------------------------------------------- #
def _sarif_level(severity: str) -> str:
    s = (severity or "").lower()
    if s in ("critical", "important", "high"):
        return "error"
    if s in ("moderate", "medium"):
        return "warning"
    if s == "low":
        return "note"
    return "warning"


def _security_severity(f: Finding) -> str:
    """Numeric 0.0-10.0 string; GitHub uses this to rank security alerts."""
    if f.cvss_score is not None:
        return f"{f.cvss_score:.1f}"
    return {
        "critical": "9.5", "important": "7.5", "high": "7.5",
        "moderate": "5.0", "medium": "5.0", "low": "2.0",
    }.get((f.severity or "").lower(), "0.0")


def _rule_id(f: Finding) -> str:
    return f.primary_cve or f.advisory or f"VULNSCANAI-{f.id}"


def _help_uri(f: Finding) -> str:
    if f.primary_cve:
        return f"https://access.redhat.com/security/cve/{f.primary_cve}"
    if f.advisory:
        return f"https://access.redhat.com/errata/{f.advisory.replace(':', '-')}"
    return INFO_URI


def build_sarif(findings: List[Finding]) -> Dict:
    rules: List[Dict] = []
    rule_index: Dict[str, int] = {}
    results: List[Dict] = []

    for f in findings:
        rid = _rule_id(f)
        level = _sarif_level(f.severity)
        sec = _security_severity(f)
        if rid not in rule_index:
            rule_index[rid] = len(rules)
            rules.append({
                "id": rid,
                "name": rid,
                "shortDescription": {"text": f.title or rid},
                "fullDescription": {"text": (f.description or f.title or rid)[:1000]},
                "helpUri": _help_uri(f),
                "help": {"text": (
                    f.remediation.summary if f.remediation and f.remediation.summary
                    else (f.description or f.title or rid))[:1000]},
                "defaultConfiguration": {"level": level},
                "properties": {
                    "security-severity": sec,
                    "cve": f.cve_ids,
                    "tags": ["security", "vulnerability", "rhel"],
                },
            })
        result = {
            "ruleId": rid,
            "ruleIndex": rule_index[rid],
            "level": level,
            "message": {"text": _result_message(f)},
            "locations": [{
                "logicalLocations": [{
                    "name": f.package or "system",
                    "kind": "package",
                    "fullyQualifiedName": f.raw.get("nevra", f.package or "system"),
                }],
            }],
            "partialFingerprints": {"vulnscanai/v1": f.id},
            "properties": {
                "security-severity": sec,
                "severity": f.severity,
                "cve": f.cve_ids,
                "advisory": f.advisory,
                "package": f.package,
                "installedVersion": f.installed_version,
                "fixedVersion": f.fixed_version,
                "cvss": f.cvss_score,
                "scanner": f.source,
            },
        }
        if f.remediation and f.remediation.commands:
            result["properties"]["remediationCommands"] = f.remediation.commands
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "vulnscan-ai",
                    "version": __version__,
                    "informationUri": INFO_URI,
                    "rules": rules,
                },
            },
            "results": results,
        }],
    }


def _result_message(f: Finding) -> str:
    bits = [f.title or "Vulnerability"]
    if f.package:
        fix = f" (fixed in {f.fixed_version})" if f.fixed_version else ""
        bits.append(f"Package {f.package}{fix}.")
    if f.cve_ids:
        bits.append("CVEs: " + ", ".join(f.cve_ids) + ".")
    return " ".join(bits)


# --------------------------------------------------------------------------- #
# compliance benchmark SARIF (one rule + one result per failing XCCDF rule)
# --------------------------------------------------------------------------- #
def build_compliance_sarif(report: ComplianceReport) -> Dict:
    rules: List[Dict] = []
    results: List[Dict] = []
    for i, r in enumerate(report.fails):
        level = _sarif_level(r.severity)
        rules.append({
            "id": r.rule_id,
            "name": r.rule_id.rsplit("_rule_", 1)[-1],
            "shortDescription": {"text": r.title or r.rule_id},
            "helpUri": INFO_URI,
            "defaultConfiguration": {"level": level},
            "properties": {
                "security-severity": {
                    "critical": "9.5", "important": "7.5", "high": "7.5",
                    "moderate": "5.0", "medium": "5.0", "low": "2.0",
                }.get((r.severity or "").lower(), "0.0"),
                "identifiers": r.references,
                "remediationAvailable": r.fix_available,
                "tags": ["compliance", report.profile],
            },
        })
        results.append({
            "ruleId": r.rule_id,
            "ruleIndex": i,
            "level": level,
            "message": {"text": f"{r.title or r.rule_id} — failed "
                                f"({report.profile_title or report.profile})."},
            "locations": [{
                "logicalLocations": [{"name": report.hostname or "system",
                                      "kind": "resource"}],
            }],
            "partialFingerprints": {"vulnscanai/compliance/v1": r.rule_id},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "vulnscan-ai-compliance",
                    "version": __version__,
                    "informationUri": INFO_URI,
                    "rules": rules,
                },
            },
            "properties": {
                "profile": report.profile,
                "score": round(report.score, 1),
                "pass": report.pass_count,
                "fail": report.fail_count,
            },
            "results": results,
        }],
    }
