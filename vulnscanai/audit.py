# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Append-only audit log of remediation actions.

Every fix that is actually applied (or rolled back) — from the CLI *or* the web
dashboard — is recorded as one JSON line in ``<state-dir>/audit.log`` (0600).
This is a security record: it answers *who* ran *what* change, *when*, from
*where*, and *how it turned out*, and it lives independently of the mutable
``findings.json`` so it is not overwritten by the next scan.

Best-effort by design: a logging failure must never abort or roll back a real
remediation, so :func:`record` swallows its own errors. Only state-changing
actions are logged — dry-run previews make no change and are not recorded.
"""

from __future__ import annotations

import getpass
import json
import os
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import Finding


def audit_log_path(cfg) -> str:
    """Path to the append-only audit log inside the state dir."""
    return os.path.join(cfg.state_dir, "audit.log")


def _os_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 -- getuser raises with no passwd entry
        try:
            return f"uid:{os.getuid()}"
        except Exception:  # noqa: BLE001 -- getuid is absent on some platforms
            return "unknown"


def _steps(finding: Finding) -> List[Dict[str, str]]:
    rem = finding.remediation
    if rem is None:
        return []
    return [{"command": str(r.get("command", "")),
             "status": str(r.get("status", ""))}
            for r in (rem.apply_results or [])]


def record(cfg, finding: Finding, *, event: str, source: str,
           actor: Optional[str] = None, dry_run: bool = False) -> Optional[str]:
    """Append one audit event for a fix/rollback. Never raises.

    ``event`` is ``"apply"`` or ``"rollback"``; ``source`` is ``"cli"`` or
    ``"dashboard"``. Returns the log path on success, else None. Dry-run applies
    are intentionally not logged (nothing changed).
    """
    if dry_run:
        return None
    try:
        rem = finding.remediation
        applied = bool(rem and rem.applied)
        rolled_back = bool(rem and rem.rolled_back)
        if event == "rollback":
            # restore_backup clears rem.applied on success.
            result = "rolled-back" if (rem and not rem.applied) else "failed"
        elif rolled_back:
            result = "rolled-back"     # applied then auto-reverted on failure
        else:
            result = "applied" if applied else "failed"
        entry: Dict[str, Any] = {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event": event,
            "source": source,
            "actor": actor or _os_user(),
            "host": socket.gethostname(),
            "finding_id": finding.id,
            "title": finding.title,
            "severity": finding.severity,
            "scanner": finding.source,
            "result": result,
            "rolled_back": rolled_back,
            "steps": _steps(finding),
        }
        if event == "apply":
            # Prefer the provider/model that actually generated this plan;
            # fall back to the configured one.
            entry["provider"] = (getattr(rem, "provider", "") or cfg.provider)
            entry["model"] = (getattr(rem, "model", "") or cfg.model)
        path = audit_log_path(cfg)
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        new = not os.path.exists(path)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        if new:
            os.chmod(path, 0o600)
        return path
    except Exception:  # noqa: BLE001 -- audit logging must never break a fix
        return None


def read(cfg, limit: int = 50) -> List[Dict[str, Any]]:
    """Return the most recent audit events (oldest first), best-effort.

    ``limit`` counts valid events, so a trailing corrupt/blank line never eats
    into the window; ``limit <= 0`` returns every event.
    """
    try:
        with open(audit_log_path(cfg), encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    events: List[Dict[str, Any]] = []
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        try:
            events.append(json.loads(ln))
        except ValueError:
            continue
    if limit and limit > 0:
        return events[-limit:]
    return events
