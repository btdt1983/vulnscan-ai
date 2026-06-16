"""Core data models shared across scanners, AI providers and the reporter."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

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


def findings_to_json(findings: List[Finding], indent: int = 2) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=indent, sort_keys=True)


def findings_from_json(text: str) -> List[Finding]:
    return [Finding.from_dict(d) for d in json.loads(text)]
