"""AI-driven remediation: propose fixes, gate on approval, then apply.

Design choices (per the tool's safety posture):
  * The model only *proposes* shell commands; it never executes anything.
  * Proposed commands are screened against a deny-list before they can run.
  * Nothing runs without explicit per-finding approval unless --yes is given.
  * --dry-run produces the full plan and report but executes nothing.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import time
from typing import Callable, Dict, List, Optional

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
- When the fix edits a configuration file, set "backup_paths" to the exact \
file(s) you change so they can be snapshotted and rolled back. Provide a \
"validate_cmd" that checks the new config WITHOUT restarting (e.g. `sshd -t`, \
`nginx -t`, `visudo -cf <file>`), and set "service" + "restart_mode" to apply it. \
PREFER "reload" over "restart" to avoid dropping live connections. For sshd \
always use validate_cmd `sshd -t`, service `sshd`, restart_mode `reload`.

Respond with ONLY a JSON object, no prose, with this schema:
{
  "summary": "one line",
  "explanation": "why this fixes it and any caveats",
  "commands": ["shell command", ...],
  "config_changes": ["human-readable non-command step", ...],
  "verification": "command to confirm the fix",
  "requires_reboot": true|false,
  "risk": "low|medium|high",
  "confidence": 0.0-1.0,
  "backup_paths": ["/etc/ssh/sshd_config", ...],
  "validate_cmd": "sshd -t",
  "service": "sshd",
  "restart_mode": "reload|restart|none",
  "rollback_commands": ["optional non-file rollback, e.g. dnf history undo last"]
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
        backup_paths=[str(p) for p in data.get("backup_paths", []) if str(p).strip()],
        service=(str(data["service"]).strip() or None) if data.get("service") else None,
        validate_cmd=(str(data["validate_cmd"]).strip() or None)
        if data.get("validate_cmd") else None,
        restart_mode=str(data.get("restart_mode", "none") or "none").lower(),
        rollback_commands=[str(c) for c in data.get("rollback_commands", [])
                           if str(c).strip()],
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


# --------------------------------------------------------------------------- #
# Low-level execution + backup/restore helpers.
# --------------------------------------------------------------------------- #
def _run(cmd: str, timeout: int = 1800) -> Dict[str, object]:
    """Run a command (no shell), returning a result dict. Does not screen."""
    try:
        proc = subprocess.run(
            shlex.split(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "command": cmd,
            "status": "ok" if proc.returncode == 0 else "failed",
            "returncode": proc.returncode,
            "detail": proc.stdout[-4000:],
        }
    except Exception as exc:  # noqa: BLE001
        return {"command": cmd, "status": "error", "detail": str(exc)}


def _systemctl(action: str, unit: str, timeout: int = 120) -> Dict[str, object]:
    res = _run(f"systemctl {action} {shlex.quote(unit)}", timeout=timeout)
    res["command"] = f"systemctl {action} {unit}"
    return res


def _snapshot(paths: List[str], dest: str) -> Dict[str, object]:
    """Copy each existing path under dest (preserving mode/mtime) and write a
    manifest so the originals can be restored later."""
    os.makedirs(dest, mode=0o700, exist_ok=True)
    manifest = []
    for p in paths:
        if os.path.isfile(p):
            stored = os.path.join(dest, p.lstrip("/"))
            os.makedirs(os.path.dirname(stored), exist_ok=True)
            shutil.copy2(p, stored)  # preserves mode + mtime
            manifest.append({"original": p, "stored": stored, "existed": True})
        else:
            manifest.append({"original": p, "existed": False})
    with open(os.path.join(dest, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    return {"command": f"backup {len(paths)} file(s) -> {dest}",
            "status": "ok", "detail": dest}


def _restore(backup_dir: str) -> List[Dict[str, object]]:
    """Restore files recorded in <backup_dir>/manifest.json."""
    try:
        with open(os.path.join(backup_dir, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError) as exc:
        return [{"command": f"restore from {backup_dir}", "status": "error",
                 "detail": f"no manifest: {exc}"}]
    out: List[Dict[str, object]] = []
    for item in manifest:
        orig = item.get("original")
        try:
            if item.get("existed"):
                shutil.copy2(item["stored"], orig)
                out.append({"command": f"rollback: restore {orig}",
                            "status": "rolled-back", "detail": "from backup"})
            elif orig and os.path.exists(orig):
                os.remove(orig)  # file was created by the fix; remove it
                out.append({"command": f"rollback: remove {orig}",
                            "status": "rolled-back", "detail": "was absent"})
        except OSError as exc:
            out.append({"command": f"rollback: {orig}", "status": "error",
                        "detail": str(exc)})
    return out


def _is_transactional(rem: Remediation) -> bool:
    return bool(rem.backup_paths or rem.service or rem.validate_cmd
                or rem.rollback_commands)


# --------------------------------------------------------------------------- #
# Apply: simple (package) and transactional (config/service) paths.
# --------------------------------------------------------------------------- #
def apply(finding: Finding, dry_run: bool = False,
          state_dir: Optional[str] = None) -> bool:
    """Apply the approved remediation for a finding.

    Package fixes (no transactional metadata) run command-by-command as before.
    Config/service fixes (backup_paths/service/validate_cmd present) run
    transactionally: snapshot -> commands -> validate -> reload -> verify, with
    automatic rollback on any failure. Returns True on success (or dry-run).
    """
    rem = finding.remediation
    if rem is None:
        return False
    rem.apply_results = []
    rem.rolled_back = False
    if _is_transactional(rem):
        return _apply_transactional(finding, dry_run, state_dir)
    return _apply_simple(rem, dry_run)


def _apply_simple(rem: Remediation, dry_run: bool) -> bool:
    ok = True
    for cmd in rem.commands:
        reason = screen_command(cmd)
        if reason:
            rem.apply_results.append({"command": cmd, "status": "blocked",
                                      "detail": reason})
            ok = False
            continue
        if dry_run:
            rem.apply_results.append({"command": cmd, "status": "dry-run",
                                      "detail": "not executed"})
            continue
        res = _run(cmd)
        ok = ok and res["status"] == "ok"
        rem.apply_results.append(res)
    rem.applied = not dry_run and ok
    return ok


def _apply_transactional(finding: Finding, dry_run: bool,
                         state_dir: Optional[str]) -> bool:
    rem = finding.remediation
    assert rem is not None
    results = rem.apply_results

    # Screen every command (incl. validate) up front: a blocked command must
    # abort before we touch anything on disk.
    to_screen = list(rem.commands) + ([rem.validate_cmd] if rem.validate_cmd else [])
    for cmd in to_screen:
        reason = screen_command(cmd)
        if reason:
            results.append({"command": cmd, "status": "blocked", "detail": reason})
            rem.applied = False
            return False

    if dry_run:
        if rem.backup_paths:
            results.append({"command": f"backup {', '.join(rem.backup_paths)}",
                            "status": "dry-run", "detail": "not executed"})
        for cmd in rem.commands:
            results.append({"command": cmd, "status": "dry-run",
                            "detail": "not executed"})
        if rem.validate_cmd:
            results.append({"command": f"validate: {rem.validate_cmd}",
                            "status": "dry-run", "detail": "not executed"})
        if rem.service and rem.restart_mode in ("reload", "restart"):
            results.append({"command": f"systemctl {rem.restart_mode} {rem.service}",
                            "status": "dry-run", "detail": "not executed"})
        rem.applied = False
        return True

    # 1. Snapshot the files we are about to change.
    if rem.backup_paths:
        dest = os.path.join(state_dir or os.getcwd(), "backups", finding.id,
                            time.strftime("%Y%m%d-%H%M%S"))
        results.append(_snapshot(rem.backup_paths, dest))
        rem.backup_dir = dest

    def _rollback(reason: str) -> bool:
        results.append({"command": "ROLLBACK", "status": "rolled-back",
                        "detail": reason})
        if rem.backup_dir:
            results.extend(_restore(rem.backup_dir))
        for rc in rem.rollback_commands:
            if not screen_command(rc):
                results.append(_run(rc))
        # Revert runtime state from the restored config.
        if rem.service and rem.restart_mode in ("reload", "restart"):
            results.append(_systemctl(rem.restart_mode, rem.service))
        rem.applied = False
        rem.rolled_back = True
        return False

    # 2. Run the change commands.
    for cmd in rem.commands:
        res = _run(cmd)
        results.append(res)
        if res["status"] != "ok":
            return _rollback(f"command failed: {cmd}")

    # 3. Validate the new config BEFORE (re)starting — prevents service lockout.
    if rem.validate_cmd:
        res = _run(rem.validate_cmd)
        res["command"] = f"validate: {rem.validate_cmd}"
        results.append(res)
        if res["status"] != "ok":
            return _rollback(f"validation failed: {rem.validate_cmd}")

    # 4. Apply via the service manager and confirm it stays healthy.
    if rem.service and rem.restart_mode in ("reload", "restart"):
        res = _systemctl(rem.restart_mode, rem.service)
        results.append(res)
        if res["status"] != "ok":
            return _rollback(f"{rem.restart_mode} {rem.service} failed")
        health = _systemctl("is-active", rem.service)
        results.append(health)
        if health["status"] != "ok":
            return _rollback(f"{rem.service} not active after {rem.restart_mode}")

    # 5. Verification (informational only; never triggers rollback).
    if rem.verification and not screen_command(rem.verification):
        res = _run(rem.verification)
        res["command"] = f"verify: {rem.verification}"
        results.append(res)

    rem.applied = True
    return True


def restore_backup(finding: Finding) -> bool:
    """Manually roll back a previously-applied transactional fix.

    Used by the `rollback` CLI command. Restores the snapshot and re-applies the
    service so its runtime state matches the restored config.
    """
    rem = finding.remediation
    if rem is None or not rem.backup_dir:
        return False
    rem.apply_results = _restore(rem.backup_dir)
    if rem.service and rem.restart_mode in ("reload", "restart"):
        rem.apply_results.append(_systemctl(rem.restart_mode, rem.service))
    rem.rolled_back = True
    rem.applied = False
    return True
