# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Core data models shared across scanners, AI providers and the reporter."""

from __future__ import annotations

import fnmatch
import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# Red Hat severity ordering, used for sorting and filtering.
SEVERITY_ORDER = {
    "critical": 4,
    "important": 3,
    "high": 3,
    "moderate": 2,
    "medium": 2,
    "low": 1,
    "unknown": 0,
    "": 0,
}


def severity_rank(severity: Optional[str]) -> int:
    return SEVERITY_ORDER.get((severity or "").strip().lower(), 0)


@dataclass
class Remediation:
    """An AI-proposed fix for a single finding."""

    summary: str = ""
    explanation: str = ""
    commands: List[str] = field(default_factory=list)
    config_changes: List[str] = field(default_factory=list)
    verification: Optional[str] = None
    requires_reboot: bool = False
    risk: str = "unknown"          # low | medium | high | unknown
    confidence: float = 0.0        # 0.0 - 1.0
    provider: str = ""
    model: str = ""
    # Transactional metadata (set by the model for config/service fixes). When
    # any of these is present the applier runs in transactional mode: snapshot
    # the files, apply, validate before restart, reload the service, and roll
    # back automatically on failure.
    backup_paths: List[str] = field(default_factory=list)
    service: Optional[str] = None          # systemd unit to validate/reload
    validate_cmd: Optional[str] = None     # config check run BEFORE (re)start
    restart_mode: str = "none"             # reload | restart | none
    rollback_commands: List[str] = field(default_factory=list)
    # Populated by the applier:
    applied: bool = False
    rolled_back: bool = False
    backup_dir: Optional[str] = None
    apply_results: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Remediation":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class Finding:
    """A single detected vulnerability."""

    source: str                        # scanner that produced it (dnf, oscap, ...)
    title: str = ""
    cve_ids: List[str] = field(default_factory=list)
    severity: str = "unknown"
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    package: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    advisory: Optional[str] = None     # e.g. RHSA-2024:1234
    description: str = ""
    # Red Hat's per-product fix state for this CVE/package, when known:
    # "not affected" | "will not fix" | "out of support scope" |
    # "fix deferred" | "affected" | ... (set by the nvd enricher).
    vendor_fix_state: Optional[str] = None
    # Runtime exposure of the affected package, set by the service-state
    # enricher: "active" (ships a service/socket that is running or enabled),
    # "inactive" (ships only dormant — stopped and disabled — units),
    # "no-service" (ships no service units; risk is library/CLI level), or
    # None (not assessed). Only "inactive" is acted on (severity downgrade).
    runtime_state: Optional[str] = None
    # Exploitation intelligence (set by the exploit enricher from public feeds):
    # `exploited` = the CVE is in the CISA KEV catalog (actively exploited in the
    # wild); `epss` = FIRST.org EPSS exploit-probability (0.0-1.0). Both drive
    # prioritisation; see models.apply_exploit_priority.
    exploited: bool = False
    epss: Optional[float] = None
    # Set by the patched-state enricher: the affected package has no installable
    # update (`dnf check-update`) although a fix exists, i.e. the host already
    # has it (or a newer build supersedes it). apply_patched_states drops these.
    already_patched: bool = False
    references: List[str] = field(default_factory=list)
    remediation: Optional[Remediation] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        """A stable identifier for de-duplication and caching."""
        parts = [
            self.source,
            self.advisory or "",
            ",".join(sorted(self.cve_ids)),
            self.package or "",
        ]
        # Config/hardening findings (ssh, scap rules) carry no advisory, CVE or
        # package, so fall back to the title to keep their ids distinct. Package
        # findings always have one of the above, so their ids stay unchanged.
        if not (self.advisory or self.cve_ids or self.package):
            parts.append(self.title)
        basis = "|".join(parts)
        digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:12]
        return digest

    @property
    def primary_cve(self) -> Optional[str]:
        return self.cve_ids[0] if self.cve_ids else None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["id"] = self.id
        if self.remediation is None:
            d["remediation"] = None
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Finding":
        d = dict(d)
        d.pop("id", None)
        rem = d.pop("remediation", None)
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        finding = cls(**{k: v for k, v in d.items() if k in known})
        if rem:
            finding.remediation = Remediation.from_dict(rem)
        return finding


def merge_findings(findings: List[Finding]) -> List[Finding]:
    """De-duplicate findings by id, merging CVE ids and references."""
    by_id: Dict[str, Finding] = {}
    for f in findings:
        if f.id in by_id:
            existing = by_id[f.id]
            existing.cve_ids = sorted(set(existing.cve_ids) | set(f.cve_ids))
            existing.references = sorted(set(existing.references) | set(f.references))
            if severity_rank(f.severity) > severity_rank(existing.severity):
                existing.severity = f.severity
        else:
            by_id[f.id] = f
    return list(by_id.values())


def _merge_group(members: List[Finding]) -> Finding:
    """Merge findings that describe the same vuln into one richest record."""
    if len(members) == 1:
        return members[0]
    # Prefer a record that has a package, then an advisory, then severity.
    base = max(members, key=lambda f: (bool(f.package), bool(f.advisory),
                                       severity_rank(f.severity)))
    cves, refs = set(base.cve_ids), set(base.references)
    for m in members:
        cves |= set(m.cve_ids)
        refs |= set(m.references)
        if severity_rank(m.severity) > severity_rank(base.severity):
            base.severity = m.severity
        for attr in ("package", "installed_version", "fixed_version",
                     "advisory", "cvss_score", "cvss_vector"):
            if not getattr(base, attr) and getattr(m, attr):
                setattr(base, attr, getattr(m, attr))
    base.cve_ids = sorted(cves)
    base.references = sorted(refs)
    return base


def dedup_cross_scanner(findings: List[Finding]) -> List[Finding]:
    """Collapse findings from different scanners that share an advisory or CVE.

    `merge_findings` only dedups within a scanner (id includes source); dnf and
    oscap report the same missing advisory, so without this the same vuln shows
    twice. Groups are formed transitively over shared advisory/CVE keys.
    """
    n = len(findings)
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    owner: Dict[str, int] = {}
    for i, f in enumerate(findings):
        keys = set(f.cve_ids)
        if f.advisory:
            keys.add(f.advisory)
        for k in keys:
            if k in owner:
                union(i, owner[k])
            else:
                owner[k] = i

    groups: Dict[int, List[Finding]] = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(findings[i])
    return [_merge_group(members) for members in groups.values()]


def match_ignore(finding: Finding, patterns: List[str]) -> bool:
    """True if any baseline pattern matches the finding (id, CVE, advisory,
    package, or title — globs allowed). Blank/`#` lines are ignored."""
    fields = [finding.id, finding.advisory or "", finding.package or "",
              finding.title or "", *finding.cve_ids]
    for pat in patterns:
        pat = pat.strip()
        if not pat or pat.startswith("#"):
            continue
        if any(fnmatch.fnmatch(val, pat) for val in fields if val):
            return True
    return False


def apply_ignores(findings: List[Finding],
                  patterns: List[str]) -> Tuple[List[Finding], int]:
    """Return (kept, suppressed_count) after applying baseline patterns."""
    if not patterns:
        return findings, 0
    kept = [f for f in findings if not match_ignore(f, patterns)]
    return kept, len(findings) - len(kept)


# Red Hat publishes, per CVE and per product, whether each package is actually
# affected. "not affected" is a confirmed false positive for this host. The
# won't-fix family describes real issues the vendor will not ship a security
# update for, so those are kept (and annotated by the enricher) — only the
# "not affected" verdict is safe to drop.
VENDOR_NOT_AFFECTED = "not affected"
VENDOR_NO_FIX_STATES = {"will not fix", "out of support scope", "fix deferred"}


def apply_vendor_states(findings: List[Finding]) -> Tuple[List[Finding], int]:
    """Drop findings Red Hat marks 'not affected' for this product.

    Returns (kept, suppressed_count). Findings carrying any other vendor state
    (including the won't-fix family, which are genuine) are kept unchanged.
    """
    kept = [f for f in findings
            if (f.vendor_fix_state or "").strip().lower() != VENDOR_NOT_AFFECTED]
    return kept, len(findings) - len(kept)


def apply_service_states(findings: List[Finding]) -> Tuple[List[Finding], int]:
    """Downgrade findings whose affected daemon is confirmed dormant.

    A package marked runtime_state == "inactive" ships only systemd units that
    are stopped AND disabled: the vulnerability is real but not exposed until
    the service is started. We keep the finding (so it resurfaces if you ever
    enable the unit) but lower its severity to "low" and annotate it, so the
    severity floor filters it out of the actionable view. The original severity
    is preserved in raw["severity_before_runtime"].

    Returns (findings, downgraded_count). Findings are mutated in place.
    """
    downgraded = 0
    for f in findings:
        if (f.runtime_state or "") != "inactive":
            continue
        if severity_rank(f.severity) <= severity_rank("low"):
            continue  # already at/below the floor; just leave the annotation
        unit_list = f.raw.get("service_units", [])
        units = ", ".join(unit_list) or "its service"
        verb = "are" if len(unit_list) > 1 else "is"
        orig = f.severity
        f.raw["severity_before_runtime"] = orig
        f.severity = "low"
        note = (f"Runtime exposure: the package is installed but {units} "
                f"{verb} stopped and disabled — not exposed until started. "
                f"Severity lowered from {orig} to low; reassess if you enable "
                f"or start the service.")
        f.description = (f.description + "\n" + note) if f.description else note
        downgraded += 1
    return findings, downgraded


def apply_patched_states(findings: List[Finding]) -> Tuple[List[Finding], int]:
    """Drop findings whose fix is already applied (no installable update).

    The patched-state enricher marks `already_patched` when a package-CVE finding
    has a fix in the repo metadata but `dnf check-update` offers no update for it,
    which means the host already has the fix (a very common kernel case: old
    kernels linger installed, so the scanners still list historical advisories
    that `dnf` can no longer act on). Returns (kept, dropped_count).
    """
    kept = [f for f in findings if not f.already_patched]
    return kept, len(findings) - len(kept)


def apply_exploit_priority(findings: List[Finding]) -> Tuple[List[Finding], int]:
    """Raise the priority of findings known to be exploited, and annotate EPSS.

    A finding whose CVE is in the CISA KEV catalog (`exploited`) is actively
    attacked in the wild — the single strongest prioritisation signal. We raise
    such a finding to at least "important" (preserving the original in
    raw["severity_before_exploit"]) so it can't hide below the severity floor,
    and annotate it. A high EPSS probability is annotated too (but never lowers
    or, by itself, raises severity — it is a likelihood, not a confirmed fact).

    Runs AFTER the vendor/service downgrades on purpose: an exploited CVE matters
    even if the local daemon is currently dormant. Returns (findings, raised).
    """
    raised = 0
    for f in findings:
        notes = []
        if f.exploited:
            notes.append("[exploited] In the CISA KEV catalog — actively "
                         "exploited in the wild; prioritise remediation.")
            if severity_rank(f.severity) < severity_rank("important"):
                f.raw["severity_before_exploit"] = f.severity
                f.severity = "important"
                raised += 1
        if f.epss is not None and f.epss >= 0.5:
            notes.append(f"[epss] Exploit probability {f.epss:.0%} (FIRST.org "
                         f"EPSS) — high likelihood of exploitation.")
        for note in notes:
            if note not in f.description:
                f.description = (f.description + "\n" + note) if f.description else note
    return findings, raised


def diff_findings(old: List[Finding],
                  new: List[Finding]) -> Tuple[List[Finding], List[Finding]]:
    """Compare two scans by stable finding id.

    Returns (added, resolved): findings present in `new` but not `old`, and
    findings present in `old` but not `new`. Used to surface drift between the
    previous saved scan and the current one.
    """
    old_ids = {f.id for f in old}
    new_ids = {f.id for f in new}
    added = [f for f in new if f.id not in old_ids]
    resolved = [f for f in old if f.id not in new_ids]
    return added, resolved


def findings_to_json(findings: List[Finding], indent: int = 2) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=indent, sort_keys=True)


def findings_from_json(text: str) -> List[Finding]:
    return [Finding.from_dict(d) for d in json.loads(text)]
