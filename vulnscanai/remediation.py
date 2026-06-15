"""AI-driven remediation: propose fixes, gate on approval, then apply.

Design choices (per the tool's safety posture):
  * The model only *proposes* shell commands; it never executes anything.
  * Proposed commands are screened against a deny-list before they can run.
  * Nothing runs without explicit per-finding approval unless --yes is given.
  * --dry-run produces the full plan and report but executes nothing.
"""

from __future__ import annotations

import re
import shlex
import subprocess
from typing import Callable, List, Optional

from .ai import AIProvider, ProviderError, extract_json
from .models import Finding, Remediation

SYSTEM_PROMPT = """You are a senior RHEL security engineer producing remediation \
plans for vulnerability findings on Red Hat Enterprise Linux based systems \
(RHEL, AlmaLinux, Rocky, CentOS Stream).

Rules:
- Prefer the package manager (dnf/yum) for patching. Be specific: pin the exact \
package when sensible (e.g. `dnf update -y --advisory=RHSA-2024:1234`).
- Only propose commands that are safe, idempotent and standard. Never propose \
destructive commands (rm -rf, mkfs, dd to a device, disabling SELinux/firewall, \
piping curl into a shell, force-removing packages).
- Respect FIPS: do not weaken crypto policy; if a fix touches crypto, note it.
- If a reboot is required (e.g. kernel/glibc/openssl), set requires_reboot true.
- Keep the plan minimal and scoped to the finding.

Respond with ONLY a JSON object, no prose, with this schema:
{
  "summary": "one line",
  "explanation": "why this fixes it and any caveats",
  "commands": ["shell command", ...],
  "config_changes": ["human-readable non-command step", ...],
  "verification": "command to confirm the fix",
  "requires_reboot": true|false,
  "risk": "low|medium|high",
  "confidence": 0.0-1.0
}"""

# Commands we refuse to run regardless of what the model proposes.
_DENY_PATTERNS = [
    r"\brm\s+-rf?\b.*\s/(?:\s|$)",      # rm -rf /
    r"\bmkfs\b",
    r"\bdd\b.*\bof=/dev/",
    r"\b(curl|wget)\b.*\|\s*(sudo\s+)?(ba)?sh",
    r"setenforce\s+0",
    r"--nodeps",
    r"\bdnf\b.*\bremove\b",
    r"\byum\b.*\bremove\b",
    r"update-crypto-policies\s+--set\s+LEGACY",
    r":\(\)\s*\{",                       # fork bomb
    r"\bchmod\s+-R\s+777\b",
]
_DENY_RE = [re.compile(p) for p in _DENY_PATTERNS]


def screen_command(cmd: str) -> Optional[str]:
    """Return a reason string if the command is disallowed, else None."""
    for rx in _DENY_RE:
        if rx.search(cmd):
            return f"blocked by safety policy (matched /{rx.pattern}/)"
    return None


def _finding_brief(f: Finding) -> str:
    lines = [
        f"Source scanner: {f.source}",
        f"Title: {f.title}",
        f"Severity: {f.severity}",
        f"CVEs: {', '.join(f.cve_ids) or 'n/a'}",
        f"Advisory: {f.advisory or 'n/a'}",
        f"Package: {f.package or 'n/a'}",
        f"Installed version: {f.installed_version or 'n/a'}",
        f"Fixed version: {f.fixed_version or 'n/a'}",
        f"CVSS: {f.cvss_score if f.cvss_score is not None else 'n/a'}",
        "",
        "Description:",
        (f.description or "n/a")[:2000],
    ]
    return "\n".join(lines)


def propose(provider: AIProvider, finding: Finding) -> Remediation:
    """Ask the model for a remediation plan for one finding."""
    text = provider.complete(SYSTEM_PROMPT, _finding_brief(finding))
    data = extract_json(text)
    rem = Remediation(
        summary=str(data.get("summary", "")),
        explanation=str(data.get("explanation", "")),
        commands=[str(c) for c in data.get("commands", []) if str(c).strip()],
        config_changes=[str(c) for c in data.get("config_changes", [])],
        verification=data.get("verification"),
        requires_reboot=bool(data.get("requires_reboot", False)),
        risk=str(data.get("risk", "unknown")).lower(),
        confidence=float(data.get("confidence", 0.0) or 0.0),
        provider=provider.name,
        model=provider.model,
    )
    return rem


def propose_all(provider: AIProvider, findings: List[Finding],
                on_progress: Optional[Callable[[int, int, Finding], None]] = None
                ) -> None:
    total = len(findings)
    for i, f in enumerate(findings, 1):
        if on_progress:
            on_progress(i, total, f)
        try:
            f.remediation = propose(provider, f)
        except ProviderError as exc:
            f.remediation = Remediation(
                summary="(AI proposal failed)",
                explanation=str(exc),
                provider=provider.name,
                model=provider.model,
                risk="unknown",
            )


def apply(finding: Finding, dry_run: bool = False) -> bool:
    """Execute the approved remediation commands for a finding.

    Returns True if all commands succeeded (or dry-run). Records per-command
    output on the remediation object.
    """
    rem = finding.remediation
    if rem is None:
        return False
    rem.apply_results = []
    ok = True
    for cmd in rem.commands:
        reason = screen_command(cmd)
        if reason:
            rem.apply_results.append(
                {"command": cmd, "status": "blocked", "detail": reason}
            )
            ok = False
            continue
        if dry_run:
            rem.apply_results.append(
                {"command": cmd, "status": "dry-run", "detail": "not executed"}
            )
            continue
        try:
            proc = subprocess.run(
                shlex.split(cmd),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=1800,
                check=False,
            )
            status = "ok" if proc.returncode == 0 else "failed"
            ok = ok and proc.returncode == 0
            rem.apply_results.append({
                "command": cmd,
                "status": status,
                "returncode": proc.returncode,
                "detail": proc.stdout[-4000:],
            })
        except Exception as exc:  # noqa: BLE001
            ok = False
            rem.apply_results.append(
                {"command": cmd, "status": "error", "detail": str(exc)}
            )
    rem.applied = not dry_run and ok
    return ok
