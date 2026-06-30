# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
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
- For a systemd service hardening finding, create a drop-in at \
`/etc/systemd/system/<unit>.d/10-hardening.conf` (the path is given as `dropin`). \
Set "backup_paths" to that file, make `systemctl daemon-reload` the LAST command \
after writing it, set "validate_cmd" to `systemd-analyze verify <unit>`, "service" \
to the unit, "restart_mode" to `restart`, and add `systemctl daemon-reload` to \
"rollback_commands". Apply only conservative directives that will not break the \
service.
- For an exposed-port finding, prefer the least-disruptive fix: bind the service \
to localhost in its own config (transactional: backup the config, validate, \
reload), otherwise restrict the port with the firewall (`firewall-cmd`), \
otherwise stop+disable the service if it is unused. Never block the SSH port you \
are connected through.

Respond with ONLY a JSON object, no prose. Replace every <...> placeholder with
a real value (or null where it says "or null"); never echo a placeholder back.
Schema:
{
  "summary": "<one-line summary>",
  "explanation": "<why this fixes it and any caveats>",
  "commands": ["<shell command>"],
  "config_changes": ["<human-readable non-command step>"],
  "verification": "<command that confirms the fix, or null>",
  "requires_reboot": false,
  "risk": "low",
  "confidence": 0.0,
  "backup_paths": ["<exact file you edit>"],
  "validate_cmd": "<non-destructive config check e.g. sshd -t, or null>",
  "service": "<systemd unit to reload, or null>",
  "restart_mode": "none",
  "rollback_commands": ["<optional non-file rollback, e.g. dnf history undo last>"]
}"""

# restart_mode must be exactly one of these; anything else (incl. a model that
# echoes the "reload|restart|none" menu) is normalised to "none".
_VALID_RESTART = {"reload", "restart", "none"}

# Finding sources whose fix legitimately edits a config file or manages a
# service, and may therefore carry transactional metadata (backup_paths /
# validate_cmd / service / restart_mode). Package-CVE sources (dnf, oscap) must
# NOT: their fix is a `dnf update`, so any backup/validate/service the model
# attaches — e.g. backing up sshd_config and "validating" by restarting sshd to
# update a Python library — is a hallucination and is stripped.
_CONFIG_SOURCES = {"ssh", "systemd", "ports", "webroot"}

# Recognised advisory id shapes (Red Hat / AlmaLinux / Oracle / Rocky families).
_ADVISORY_RE = re.compile(
    r"^(?:RH[SBE]A|AL[SBE]A|ELSA|RLSA|CESA)-?\d{4}[:\-]\d+", re.I)

# "dnf/yum update" prints this when the targeted advisory/package changes
# nothing — exit code is still 0, which would otherwise read as a real success.
_NOTHING_DONE_RE = re.compile(r"\bnothing to do\b", re.I)

# Literal placeholder strings from older/example schemas that a weak model may
# echo verbatim. Matched case-insensitively after stripping; always discarded.
_PLACEHOLDER_TEXTS = {
    "one line", "why this fixes it and any caveats",
    "command to confirm the fix", "shell command",
    "human-readable non-command step", "reload|restart|none",
    "optional non-file rollback, e.g. dnf history undo last",
}

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
    # Surface scanner hints (e.g. systemd drop-in path, recommended directives)
    # so the model can produce a precise transactional plan.
    for key in ("dropin", "recommended", "config_file", "directive",
                "current", "service", "address", "port", "category"):
        val = f.raw.get(key) if isinstance(f.raw, dict) else None
        if val:
            lines.append(f"{key}: {val}")
    return "\n".join(lines)


def _scrub(val: object) -> Optional[str]:
    """Drop a model echo of a schema placeholder.

    Placeholders are written as <...>; a weak/small model sometimes copies them
    verbatim (e.g. returns the literal "command to confirm the fix"). Returns a
    clean non-empty string, or None when the value is empty or an echoed
    placeholder.
    """
    if val is None:
        return None
    s = str(val).strip()
    if not s:
        return None
    if s.startswith("<") and s.endswith(">"):
        return None
    if s.lower() in _PLACEHOLDER_TEXTS:
        return None
    return s


def _real_command(cmd: Optional[str]) -> Optional[str]:
    """Return cmd only if its first token resolves to a real executable.

    Guards validate_cmd / verification: prose like "validate nginx version" or a
    leftover placeholder must never be executed as if it were a command.
    """
    cmd = _scrub(cmd)
    if cmd is None:
        return None
    try:
        toks = shlex.split(cmd)
    except ValueError:
        return None
    if not toks:
        return None
    # Search the sbin dirs too: validate binaries (sshd, nginx, visudo) live in
    # /usr/sbin, which isn't always on PATH. Over-dropping a real validate_cmd
    # would mean restarting a service unvalidated, so resolve generously.
    search = (os.environ.get("PATH", "") + ":/usr/sbin:/sbin:/usr/local/sbin")
    if shutil.which(toks[0], path=search) is None:
        return None
    return cmd


def _rewrite_advisory(commands: List[str], advisory: Optional[str]) -> List[str]:
    """Force any `--advisory=` to the finding's real advisory id.

    A weak model often invents a malformed id (e.g. `ALSAA2026:28973`), which
    `dnf` then silently matches to nothing. When the finding carries a real,
    well-formed advisory, substitute it so the update actually applies.
    """
    adv = (advisory or "").strip()
    if not adv or not _ADVISORY_RE.match(adv):
        return commands
    return [re.sub(r"--advisory[=\s]\S+", f"--advisory={adv}", c) for c in commands]


def propose(provider: AIProvider, finding: Finding) -> Remediation:
    """Ask the model for a remediation plan for one finding, then sanitise it."""
    text = provider.complete(SYSTEM_PROMPT, _finding_brief(finding))
    data = extract_json(text)

    commands = [str(c) for c in data.get("commands", []) if str(c).strip()]
    commands = _rewrite_advisory(commands, finding.advisory)

    restart_mode = str(data.get("restart_mode", "none") or "none").lower().strip()
    if restart_mode not in _VALID_RESTART:
        restart_mode = "none"

    backup_paths = [str(p) for p in data.get("backup_paths", []) if str(p).strip()]
    service = _scrub(data.get("service"))
    validate_cmd = _real_command(data.get("validate_cmd"))

    # Transactional scaffolding only makes sense for config/service findings.
    # Strip it from package-CVE findings, where the model tends to hallucinate
    # unrelated config backups / service restarts.
    if finding.source not in _CONFIG_SOURCES:
        backup_paths, validate_cmd, service, restart_mode = [], None, None, "none"

    rem = Remediation(
        summary=_scrub(data.get("summary")) or "",
        explanation=_scrub(data.get("explanation")) or "",
        commands=commands,
        config_changes=[s for s in (_scrub(c) for c in data.get("config_changes", []))
                        if s],
        verification=_real_command(data.get("verification")),
        requires_reboot=bool(data.get("requires_reboot", False)),
        risk=str(data.get("risk", "unknown")).lower(),
        confidence=float(data.get("confidence", 0.0) or 0.0),
        provider=provider.name,
        model=provider.model,
        backup_paths=backup_paths,
        service=service,
        validate_cmd=validate_cmd,
        restart_mode=restart_mode,
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
        status = "ok" if proc.returncode == 0 else "failed"
        detail = proc.stdout[-4000:]
        # A dnf/yum update that exits 0 but reports "Nothing to do" changed
        # nothing (often a malformed/irrelevant advisory) — not a real success.
        if (status == "ok" and ("dnf" in cmd or "yum" in cmd)
                and _NOTHING_DONE_RE.search(proc.stdout)):
            status = "no-change"
            detail = ("dnf reported 'Nothing to do' — no package was updated "
                      "(the advisory may not apply to this host).\n" + detail)
        return {"command": cmd, "status": status,
                "returncode": proc.returncode, "detail": detail}
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
StepCallback = Optional[Callable[[Dict[str, object]], None]]


def apply(finding: Finding, dry_run: bool = False,
          state_dir: Optional[str] = None, on_step: StepCallback = None) -> bool:
    """Apply the approved remediation for a finding.

    Package fixes (no transactional metadata) run command-by-command as before.
    Config/service fixes (backup_paths/service/validate_cmd present) run
    transactionally: snapshot -> commands -> validate -> reload -> verify, with
    automatic rollback on any failure. Returns True on success (or dry-run).

    `on_step`, if given, is called with each result dict the moment that step
    finishes (backup, every command, validate, reload, health check, rollback),
    so a caller can stream live progress instead of waiting for the whole apply.
    """
    rem = finding.remediation
    if rem is None:
        return False
    rem.apply_results = []
    rem.rolled_back = False
    if _is_transactional(rem):
        return _apply_transactional(finding, dry_run, state_dir, on_step)
    return _apply_simple(rem, dry_run, on_step)


def _emit(results: List[Dict[str, object]], res: Dict[str, object],
          on_step: StepCallback) -> Dict[str, object]:
    """Record a step result and stream it to the callback. Returns the result."""
    results.append(res)
    if on_step is not None:
        on_step(res)
    return res


def _apply_simple(rem: Remediation, dry_run: bool,
                  on_step: StepCallback = None) -> bool:
    ok = True
    for cmd in rem.commands:
        reason = screen_command(cmd)
        if reason:
            _emit(rem.apply_results,
                  {"command": cmd, "status": "blocked", "detail": reason}, on_step)
            ok = False
            continue
        if dry_run:
            _emit(rem.apply_results,
                  {"command": cmd, "status": "dry-run", "detail": "not executed"},
                  on_step)
            continue
        res = _emit(rem.apply_results, _run(cmd), on_step)
        ok = ok and res["status"] == "ok"
    rem.applied = not dry_run and ok
    return ok


def _apply_transactional(finding: Finding, dry_run: bool,
                         state_dir: Optional[str],
                         on_step: StepCallback = None) -> bool:
    rem = finding.remediation
    assert rem is not None
    results = rem.apply_results

    def emit(res: Dict[str, object]) -> Dict[str, object]:
        return _emit(results, res, on_step)

    # Screen every command (incl. validate) up front: a blocked command must
    # abort before we touch anything on disk.
    to_screen = list(rem.commands) + ([rem.validate_cmd] if rem.validate_cmd else [])
    for cmd in to_screen:
        reason = screen_command(cmd)
        if reason:
            emit({"command": cmd, "status": "blocked", "detail": reason})
            rem.applied = False
            return False

    if dry_run:
        if rem.backup_paths:
            emit({"command": f"backup {', '.join(rem.backup_paths)}",
                  "status": "dry-run", "detail": "not executed"})
        for cmd in rem.commands:
            emit({"command": cmd, "status": "dry-run", "detail": "not executed"})
        if rem.validate_cmd:
            emit({"command": f"validate: {rem.validate_cmd}",
                  "status": "dry-run", "detail": "not executed"})
        if rem.service and rem.restart_mode in ("reload", "restart"):
            emit({"command": f"systemctl {rem.restart_mode} {rem.service}",
                  "status": "dry-run", "detail": "not executed"})
        rem.applied = False
        return True

    # 1. Snapshot the files we are about to change.
    if rem.backup_paths:
        dest = os.path.join(state_dir or os.getcwd(), "backups", finding.id,
                            time.strftime("%Y%m%d-%H%M%S"))
        emit(_snapshot(rem.backup_paths, dest))
        rem.backup_dir = dest

    def _rollback(reason: str) -> bool:
        emit({"command": "ROLLBACK", "status": "rolled-back", "detail": reason})
        if rem.backup_dir:
            for r in _restore(rem.backup_dir):
                emit(r)
        for rc in rem.rollback_commands:
            if not screen_command(rc):
                emit(_run(rc))
        # Revert runtime state from the restored config. daemon-reload first so
        # a removed/restored unit drop-in actually takes effect before restart.
        if rem.service and rem.restart_mode in ("reload", "restart"):
            emit(_run("systemctl daemon-reload"))
            emit(_systemctl(rem.restart_mode, rem.service))
        rem.applied = False
        rem.rolled_back = True
        return False

    # 2. Run the change commands. "no-change" (dnf nothing-to-do) is surfaced
    # but is not a failure, so it does not trigger a rollback.
    for cmd in rem.commands:
        res = emit(_run(cmd))
        if res["status"] not in ("ok", "no-change"):
            return _rollback(f"command failed: {cmd}")

    # 3. Validate the new config BEFORE (re)starting — prevents service lockout.
    if rem.validate_cmd:
        res = _run(rem.validate_cmd)
        res["command"] = f"validate: {rem.validate_cmd}"
        emit(res)
        if res["status"] != "ok":
            return _rollback(f"validation failed: {rem.validate_cmd}")

    # 4. Apply via the service manager and confirm it stays healthy.
    if rem.service and rem.restart_mode in ("reload", "restart"):
        res = emit(_systemctl(rem.restart_mode, rem.service))
        if res["status"] != "ok":
            return _rollback(f"{rem.restart_mode} {rem.service} failed")
        health = emit(_systemctl("is-active", rem.service))
        if health["status"] != "ok":
            return _rollback(f"{rem.service} not active after {rem.restart_mode}")

    # 5. Verification (informational only; never triggers rollback).
    if rem.verification and not screen_command(rem.verification):
        res = _run(rem.verification)
        res["command"] = f"verify: {rem.verification}"
        emit(res)

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
        rem.apply_results.append(_run("systemctl daemon-reload"))
        rem.apply_results.append(_systemctl(rem.restart_mode, rem.service))
    rem.rolled_back = True
    rem.applied = False
    return True
