# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Email notifications for scheduled scans (stdlib smtplib).

Sends a plain-text summary when a scheduled scan finds something worth knowing
about: any finding at or above `notify_min_severity`, or anything new since the
previous scan. Configured via the setup wizard or the config file. Never raises
into the caller — returns (sent, message) so a failed mail can't break a scan.
"""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate
from typing import List, Tuple

from .models import Finding, severity_rank


def _summary(host: str, when: str, findings: List[Finding],
             added: List[Finding], resolved: List[Finding],
             min_sev: str) -> str:
    floor = severity_rank(min_sev)
    counts: dict = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    order = ["critical", "important", "moderate", "low", "unknown"]
    by_sev = "  ".join(f"{s}: {counts[s]}" for s in order if counts.get(s))

    lines = [
        f"vulnscan-ai scheduled scan on {host}",
        f"{when}",
        "",
        f"{len(findings)} finding(s) total" + (f"   ({by_sev})" if by_sev else ""),
        f"New since last scan: {len(added)}    Resolved: {len(resolved)}",
        "",
    ]
    top = sorted((f for f in findings if severity_rank(f.severity) >= floor),
                 key=lambda f: severity_rank(f.severity), reverse=True)
    if top:
        lines.append(f"At or above '{min_sev}':")
        for f in top[:25]:
            cves = ", ".join(f.cve_ids[:3])
            tail = f" [{cves}]" if cves else ""
            lines.append(f"  [{f.severity}] {f.title}{tail}")
        if len(top) > 25:
            lines.append(f"  ... and {len(top) - 25} more")
        lines.append("")
    if added:
        lines.append("Newly appeared:")
        for f in added[:25]:
            lines.append(f"  [{f.severity}] {f.title}")
        lines.append("")
    lines.append("-- vulnscan-ai")
    return "\n".join(lines)


def send_scan_email(cfg, findings: List[Finding], added: List[Finding],
                    resolved: List[Finding], host: str,
                    when: str) -> Tuple[bool, str]:
    """Send the summary if warranted. Returns (sent, human-readable status)."""
    if not getattr(cfg, "notify_email", None):
        return False, "no recipient configured"

    min_sev = getattr(cfg, "notify_min_severity", "important")
    floor = severity_rank(min_sev)
    relevant = [f for f in findings if severity_rank(f.severity) >= floor]
    if not relevant and not added:
        return False, f"nothing at/above '{min_sev}' and no new findings — not sent"

    msg = EmailMessage()
    msg["Subject"] = (f"[vulnscan-ai] {host}: {len(relevant)} finding(s) "
                      f">= {min_sev}, {len(added)} new")
    msg["From"] = getattr(cfg, "smtp_from", None) or cfg.notify_email
    msg["To"] = cfg.notify_email
    msg["Date"] = formatdate(localtime=True)
    msg.set_content(_summary(host, when, findings, added, resolved, min_sev))

    smtp_host = getattr(cfg, "smtp_host", None) or "localhost"
    smtp_port = int(getattr(cfg, "smtp_port", 25) or 25)
    user = getattr(cfg, "smtp_user", None)
    password = getattr(cfg, "smtp_password", None) or ""
    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as s:
            if getattr(cfg, "smtp_starttls", False):
                s.starttls(context=ssl.create_default_context())
            if user:
                s.login(user, password)
            s.send_message(msg)
        return True, f"sent to {cfg.notify_email} via {smtp_host}:{smtp_port}"
    except (smtplib.SMTPException, OSError) as exc:
        return False, f"send failed ({smtp_host}:{smtp_port}): {exc}"
