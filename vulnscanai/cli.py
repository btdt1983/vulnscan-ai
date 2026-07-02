# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Command line interface for vulnscan-ai."""

from __future__ import annotations

import argparse
import datetime
import glob
import os
import re
import socket
import sys
from typing import Dict, List, Optional

from . import __version__, export_fix, remediation
from .ai import PROVIDERS, ProviderError, get_provider
from .config import Config
from .fips import status_line
from .branding import print_banner
from .models import (
    Finding, apply_exploit_priority, apply_ignores, apply_patched_states,
    apply_service_states, apply_vendor_states, dedup_cross_scanner,
    diff_findings, findings_from_json, findings_to_json, merge_findings,
    severity_rank,
)
from .report import write_report
from .scanners import (
    SCANNERS, ExploitEnricher, NvdEnricher, PatchedStateEnricher,
    ServiceStateEnricher, detect_distro, download_oval, is_oval_stale,
    oval_age_days,
)


# --------------------------------------------------------------------------- #
# small terminal helpers
# --------------------------------------------------------------------------- #
def _eprint(*a, **k):
    print(*a, file=sys.stderr, **k)


def _now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z").strip()


def _hostname() -> str:
    return socket.gethostname()


_SEV_TAG = {
    "critical": "CRIT", "important": "IMPT", "high": "HIGH",
    "moderate": "MOD", "medium": "MED", "low": "LOW", "unknown": "UNK",
}
_SEV_ANSI = {
    "critical": "\033[1;31m", "important": "\033[31m", "high": "\033[31m",
    "moderate": "\033[33m", "medium": "\033[33m", "low": "\033[32m",
    "unknown": "\033[2m",
}
_RESET = "\033[0m"
# Order severities for the summary line (highest first).
_SEV_ORDER = ["critical", "important", "high", "moderate", "medium", "low", "unknown"]


def _use_color() -> bool:
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _severity_summary(findings: List[Finding], color: bool = False) -> str:
    """A 'CRIT 3   IMPT 11   LOW 2' tally, in severity order, optionally coloured."""
    counts: Dict[str, int] = {}
    for f in findings:
        counts[(f.severity or "unknown").lower()] = \
            counts.get((f.severity or "unknown").lower(), 0) + 1
    parts = []
    for sev in _SEV_ORDER:
        n = counts.get(sev)
        if not n:
            continue
        seg = f"{_SEV_TAG.get(sev, 'UNK')} {n}"
        if color:
            seg = _SEV_ANSI.get(sev, "") + seg + _RESET
        parts.append(seg)
    return "   ".join(parts)


def _print_findings(findings: List[Finding]) -> None:
    if not findings:
        print("No vulnerabilities found.")
        return
    # Actively-exploited (CISA KEV) findings float to the very top.
    findings = sorted(findings, key=lambda f: (-int(f.exploited),
                                               -severity_rank(f.severity),
                                               -(f.cvss_score or 0)))
    color = _use_color()
    print(f"{'SEV':<5} {'CVSS':<5} {'PACKAGE / ISSUE':<45} {'ADVISORY':<14} CVEs")
    print("-" * 90)
    for f in findings:
        sev = (f.severity or "unknown").lower()
        cell = f"{_SEV_TAG.get(sev, 'UNK'):<5}"        # pad first, colour after
        if color:
            cell = _SEV_ANSI.get(sev, "") + cell + _RESET
        cvss = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "-"
        # Package findings show the package; config findings (ssh, systemd, ...)
        # have no package, so fall back to the title.
        subject = (f.package or f.title or "-")[:44]
        adv = (f.advisory or "-")[:13]
        cves = ", ".join(f.cve_ids[:3]) + ("…" if len(f.cve_ids) > 3 else "")
        flags = ""
        if f.exploited:
            tag = "[KEV]"
            flags += " " + ((_SEV_ANSI["critical"] + tag + _RESET) if color else tag)
        if f.epss is not None and f.epss >= 0.5:
            flags += f" [EPSS {f.epss:.0%}]"
        print(f"{cell} {cvss:<5} {subject:<45} {adv:<14} {cves}{flags}")
    print("-" * 90)
    summary = _severity_summary(findings, color)
    print(f"{len(findings)} finding(s)" + (f":   {summary}" if summary else "."))


def _filter_severity(findings: List[Finding], minimum: str) -> List[Finding]:
    floor = severity_rank(minimum)
    return [f for f in findings if severity_rank(f.severity) >= floor]


def _select_scanners(args, cfg: Config) -> List[str]:
    """Which scanners to run: --all (every registered one) wins, else the
    explicit --scanner flags, else the configured default."""
    if getattr(args, "all", False):
        return list(SCANNERS)
    return args.scanner or cfg.scanners


# --------------------------------------------------------------------------- #
# scanning
# --------------------------------------------------------------------------- #
def _maybe_refresh_oval(cfg: Config) -> None:
    """Auto-refresh the OVAL feed before an oscap scan when it is stale.

    TTL-gated (oval_max_age_days) so it isn't a per-scan download, network-backed
    and fully fail-soft: if the refresh fails, the existing feed (if any) is used
    and the scan continues. Skipped entirely on air-gapped hosts via the
    oval_auto_update toggle or --no-enrich.
    """
    from .scanners.base import have
    if not have("oscap"):
        return                       # nothing will consume the feed
    max_age = int(getattr(cfg, "oval_max_age_days", 7) or 7)
    if not is_oval_stale(cfg, max_age):
        return
    age = oval_age_days(cfg)
    why = "not staged yet" if age is None else f"{age:.0f} days old (> {max_age})"
    _eprint(f"  > OVAL feed {why}; auto-refreshing (this can be tens of MB)...")
    try:
        download_oval(cfg, timeout=max(cfg.timeout, 180))
    except Exception as exc:  # noqa: BLE001
        _eprint(f"  - OVAL auto-update failed ({exc}); using the existing feed "
                f"if present (run 'vulnscan-ai update-oval' to stage one)")


def do_scan(cfg: Config, scanners: List[str], enrich: bool,
            extra_ignores: Optional[List[str]] = None) -> List[Finding]:
    findings: List[Finding] = []
    # Keep the oscap OVAL feed current automatically (TTL-gated, fail-soft).
    if ("oscap" in scanners and enrich
            and getattr(cfg, "oval_auto_update", True)):
        _maybe_refresh_oval(cfg)
    for name in scanners:
        if name == NvdEnricher.name:
            # 'nvd' is an enrichment source, not a detection scanner; it runs
            # automatically below when enrich is on. Tolerate it in the list.
            continue
        cls = SCANNERS.get(name)
        if cls is None:
            _eprint(f"  ! unknown scanner '{name}', skipping")
            continue
        scanner = cls(cfg)
        if not scanner.available():
            _eprint(f"  - {name}: not available on this host, skipping")
            continue
        _eprint(f"  > running {name} scanner...")
        try:
            produced = scanner.scan()
            _eprint(f"    {name}: {len(produced)} finding(s)")
            findings.extend(produced)
        except Exception as exc:  # noqa: BLE001
            _eprint(f"    ! {name} failed: {exc}")
    findings = merge_findings(findings)
    findings = dedup_cross_scanner(findings)
    patterns = list(cfg.ignore) + list(extra_ignores or [])
    if patterns:
        findings, suppressed = apply_ignores(findings, patterns)
        if suppressed:
            _eprint(f"  - {suppressed} finding(s) suppressed by baseline")
    if enrich and findings:
        _eprint(f"  > enriching {len(findings)} finding(s) from CVE feeds...")
        NvdEnricher(cfg).enrich(findings)
        if cfg.vendor_state_filter:
            findings, dropped = apply_vendor_states(findings)
            if dropped:
                _eprint(f"  - {dropped} finding(s) dropped "
                        f"(Red Hat: not affected)")
    # Already-patched: drop package findings dnf can no longer act on (a fix
    # exists in the metadata but no installable update — the common lingering-
    # old-kernel case). Local dnf query; runs regardless of network enrichment.
    if getattr(cfg, "patched_filter", True) and findings:
        enricher = PatchedStateEnricher(cfg)
        if enricher.available():
            enricher.enrich(findings)
            findings, patched = apply_patched_states(findings)
            if patched:
                _eprint(f"  - {patched} finding(s) dropped "
                        f"(already patched — no installable update)")
    # Runtime exposure: downgrade findings whose daemon is stopped and disabled.
    # Local-only (rpm + systemctl), so it runs regardless of network enrichment.
    if cfg.service_state_filter and findings:
        enricher = ServiceStateEnricher(cfg)
        if enricher.available():
            enricher.enrich(findings)
            findings, downgraded = apply_service_states(findings)
            if downgraded:
                _eprint(f"  - {downgraded} finding(s) downgraded "
                        f"(service inactive/disabled)")
    # Exploitation intel: flag CISA-KEV (actively exploited) findings + EPSS.
    # Runs last so an exploited CVE outranks a dormant-service downgrade.
    if enrich and cfg.exploit_enrich and findings:
        ex = ExploitEnricher(cfg)
        if ex.available():
            _eprint("  > checking exploitation intel (CISA KEV, EPSS)...")
            ex.enrich(findings)
            findings, raised = apply_exploit_priority(findings)
            kev = sum(1 for f in findings if f.exploited)
            if kev:
                _eprint(f"  ! {kev} finding(s) actively exploited (CISA KEV)"
                        f"{f'; {raised} raised to important' if raised else ''}")
    return findings


def _save_findings(cfg: Config, findings: List[Finding]) -> None:
    cfg.ensure_state_dir()
    with open(cfg.findings_path, "w", encoding="utf-8") as fh:
        fh.write(findings_to_json(findings))
    os.chmod(cfg.findings_path, 0o600)


def _load_findings(cfg: Config) -> List[Finding]:
    if not os.path.isfile(cfg.findings_path):
        _eprint(f"No saved findings at {cfg.findings_path}. Run 'scan' first.")
        return []
    with open(cfg.findings_path, "r", encoding="utf-8") as fh:
        return findings_from_json(fh.read())


def _load_findings_silent(cfg: Config) -> List[Finding]:
    """Load the previously-saved findings, or [] if none/unreadable (no output)."""
    try:
        with open(cfg.findings_path, "r", encoding="utf-8") as fh:
            return findings_from_json(fh.read())
    except (OSError, ValueError):
        return []


def _print_diff(added: List[Finding], resolved: List[Finding]) -> None:
    """Show drift relative to the previous scan."""
    if not added and not resolved:
        print("No change since the last scan.")
        return
    parts = []
    if added:
        parts.append(f"{len(added)} new")
    if resolved:
        parts.append(f"{len(resolved)} resolved")
    print("Since last scan: " + ", ".join(parts))
    for f in added[:10]:
        print(f"  + [{f.severity}] {(f.package or f.title)[:60]}")
    if len(added) > 10:
        print(f"  + ... and {len(added) - 10} more new")
    for f in resolved[:10]:
        print(f"  - resolved: {(f.package or f.title)[:60]}")
    if len(resolved) > 10:
        print(f"  - ... and {len(resolved) - 10} more resolved")


# --------------------------------------------------------------------------- #
# command handlers
# --------------------------------------------------------------------------- #
def cmd_info(cfg: Config, args) -> int:
    from .hardware import compute_budget_gb
    print(f"vulnscan-ai {__version__}")
    print(status_line())
    budget = compute_budget_gb()
    gpu = budget["gpu"]
    if gpu["present"]:
        vram = f", {gpu['vram_gb']:.0f} GB VRAM" if gpu["vram_gb"] else ""
        print(f"GPU: {gpu['name']}{vram} ({gpu['kind']}) — local models "
              f"run accelerated")
    else:
        print("GPU: none detected — local models run on CPU")
    print("\nScanners:")
    for name, cls in SCANNERS.items():
        avail = "available" if cls(cfg).available() else "unavailable"
        print(f"  {name:<8} {avail}")
    print("\nAI providers (configured = API key/endpoint present):")
    for name, cls in PROVIDERS.items():
        inst = cls()
        flag = "ready" if inst.available() else "needs config"
        key = cls.api_key_env or "(no key)"
        print(f"  {name:<8} {flag:<12} model={inst.default_model} env={key}")
    print(f"\nState dir: {cfg.state_dir}")
    return 0


def cmd_scan(cfg: Config, args) -> int:
    scanners = _select_scanners(args, cfg)
    print(f"Scanning {_hostname()} ...")
    had_prev = os.path.isfile(cfg.findings_path)
    previous = _load_findings_silent(cfg) if had_prev else []
    findings = do_scan(cfg, scanners, enrich=not args.no_enrich and cfg.enrich,
                       extra_ignores=args.ignore)
    findings = _filter_severity(findings, args.min_severity or cfg.min_severity)
    _save_findings(cfg, findings)
    print()
    _print_findings(findings)
    if had_prev:
        added, resolved = diff_findings(previous, findings)
        _print_diff(added, resolved)
    print(f"\nSaved to {cfg.findings_path}")
    for target in (args.pdf, args.json, args.sarif):
        if target:
            out = write_report(findings, target, _hostname(), _now())
            print(f"Wrote {out}")
    return 0


def _approve(finding: Finding, auto: bool) -> str:
    """Prompt the operator. Returns 'yes' | 'no' | 'all' | 'quit'."""
    rem = finding.remediation
    print("\n" + "=" * 70)
    print(f"[{finding.severity.upper()}] {finding.title}")
    if finding.cve_ids:
        print(f"CVEs: {', '.join(finding.cve_ids)}")
    if rem:
        print(f"Plan: {rem.summary}  (risk={rem.risk}, "
              f"confidence={rem.confidence:.0%}, "
              f"reboot={'yes' if rem.requires_reboot else 'no'})")
        if rem.backup_paths or rem.service or rem.validate_cmd:
            print("    [transactional] backup -> apply -> validate -> "
                  f"{rem.restart_mode or 'none'} -> rollback on failure")
            if rem.backup_paths:
                print(f"      backup:   {', '.join(rem.backup_paths)}")
            if rem.validate_cmd:
                print(f"      validate: {rem.validate_cmd}")
            if rem.service:
                print(f"      service:  systemctl {rem.restart_mode} {rem.service}")
        for c in rem.commands:
            blocked = remediation.screen_command(c)
            mark = "  [BLOCKED]" if blocked else ""
            print(f"    $ {c}{mark}")
        for s in rem.config_changes:
            print(f"    • {s}")
    if auto:
        return "yes"
    try:
        ans = input("Apply this fix? [y]es / [n]o / [i]gnore / [a]ll / [q]uit: "
                    ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return "quit"
    return {"y": "yes", "a": "all", "q": "quit", "i": "ignore"}.get(ans, "no")


def _baseline_ignore(finding: Finding) -> str:
    """Persist a finding to the baseline so future scans suppress it.

    Appends a readable comment plus the finding's stable id to
    ~/.config/vulnscan-ai/ignore (the file Config.load reads). Returns its path.
    """
    path = os.path.expanduser("~/.config/vulnscan-ai/ignore")
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y-%m-%d")
    title = (finding.title or finding.id).replace("\n", " ")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"# {title}  (ignored {stamp})\n{finding.id}\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def _print_step(r: dict) -> None:
    """Stream one apply step (command + its output) to the operator, live."""
    status = str(r.get("status", "?"))
    print(f"    [{status}] {r.get('command', '')}", flush=True)
    detail = str(r.get("detail") or "").strip()
    # Skip the noise lines; show real command output / errors / block reasons.
    if detail and detail != "not executed":
        for line in detail.splitlines():
            print(f"        {line}", flush=True)


def cmd_fix(cfg: Config, args) -> int:
    if args.scan:
        print(f"Scanning {_hostname()} ...")
        findings = do_scan(cfg, _select_scanners(args, cfg),
                           enrich=not args.no_enrich and cfg.enrich,
                           extra_ignores=getattr(args, "ignore", None))
    else:
        findings = _load_findings(cfg)
        # The saved findings may predate a patch (or this filter): re-check so we
        # don't ask the AI to "fix" — or no-op apply — advisories the host has
        # already resolved (the lingering-old-kernel case).
        if getattr(cfg, "patched_filter", True) and findings:
            enricher = PatchedStateEnricher(cfg)
            if enricher.available():
                enricher.enrich(findings)
                findings, patched = apply_patched_states(findings)
                if patched:
                    _eprint(f"  - {patched} already-patched finding(s) skipped "
                            f"(no installable update)")
    if not findings:
        return 1
    findings = _filter_severity(findings, args.min_severity or cfg.min_severity)

    provider = get_provider(args.provider or cfg.provider, args.model or cfg.model,
                            timeout=cfg.timeout, effort=cfg.claude_effort)
    if not provider.available():
        _eprint(f"Provider '{provider.name}' is not configured "
                f"(missing {provider.api_key_env or 'endpoint'}).")
        return 2

    print(f"Requesting remediation from {provider.name}/{provider.model} "
          f"for {len(findings)} finding(s)...")

    def progress(i, total, f):
        _eprint(f"  [{i}/{total}] {f.package or f.primary_cve or f.title}")

    remediation.propose_all(provider, findings, on_progress=progress)

    # Export-only mode: write a bash script and/or Ansible playbook, do not apply.
    if args.export_script or args.export_ansible:
        if args.export_script:
            with open(args.export_script, "w", encoding="utf-8") as fh:
                fh.write(export_fix.to_bash_script(findings))
            # The user explicitly asked for a runnable fix script; 0755 is the point.
            os.chmod(args.export_script, 0o755)  # nosec B103
            print(f"Wrote bash script: {args.export_script}")
        if args.export_ansible:
            with open(args.export_ansible, "w", encoding="utf-8") as fh:
                fh.write(export_fix.to_ansible_playbook(findings))
            print(f"Wrote Ansible playbook: {args.export_ansible}")
        _save_findings(cfg, findings)
        return 0

    dry = args.dry_run or cfg.dry_run
    auto = args.yes or cfg.auto_approve
    applied = 0
    rolled = 0
    approve_all = auto
    ignored_ids: set = set()
    for f in findings:
        decision = "all" if approve_all else _approve(f, auto=False)
        if decision == "quit":
            print("Aborted by operator.")
            break
        if decision == "all":
            approve_all = True
            decision = "yes"
        if decision == "ignore":
            path = _baseline_ignore(f)
            ignored_ids.add(f.id)
            print(f"  ignored — won't be reported again (baseline: {path})")
            continue
        if decision != "yes":
            print("  skipped.")
            continue
        print(f"  {'(dry-run) ' if dry else ''}Applying ...")
        ok = remediation.apply(f, dry_run=dry, state_dir=cfg.state_dir,
                               on_step=_print_step)
        applied += 1 if ok else 0
        if f.remediation and f.remediation.rolled_back:
            rolled += 1
            print("    ROLLED BACK — change reverted, service left healthy.")

    # Drop just-ignored findings so the saved set (and the dashboard) reflect it
    # immediately, not only on the next scan.
    if ignored_ids:
        findings = [f for f in findings if f.id not in ignored_ids]
    _save_findings(cfg, findings)
    print(f"\n{'(dry-run) ' if dry else ''}Processed; "
          f"{applied} fix(es) applied successfully"
          f"{f', {rolled} rolled back' if rolled else ''}"
          f"{f', {len(ignored_ids)} ignored' if ignored_ids else ''}.")
    reboot = [f for f in findings if f.remediation and f.remediation.applied
              and f.remediation.requires_reboot]
    if reboot:
        print(f"NOTE: {len(reboot)} applied fix(es) require a reboot to take effect.")
    if args.pdf:
        out = write_report(findings, args.pdf, _hostname(), _now())
        print(f"Report written to {out}")
    return 0


def cmd_rollback(cfg: Config, args) -> int:
    findings = _load_findings(cfg)
    if not findings:
        return 1
    restorable = [f for f in findings
                  if f.remediation and f.remediation.backup_dir]
    if args.list or not args.id:
        if not restorable:
            print("No restorable fixes (none have a stored backup).")
            return 0
        print("Restorable fixes (backup available):")
        for f in restorable:
            rem = f.remediation
            state = "rolled-back" if rem.rolled_back else (
                "applied" if rem.applied else "pending")
            print(f"  {f.id}  [{state}]  {f.title}")
            print(f"        backup: {rem.backup_dir}")
        if not args.id:
            print("\nRun 'vulnscan-ai rollback <id>' to restore one.")
        return 0
    target = next((f for f in findings if f.id == args.id), None)
    if target is None or not (target.remediation and target.remediation.backup_dir):
        _eprint(f"No restorable fix with id {args.id!r}.")
        return 1
    print(f"Rolling back {args.id}: {target.title}")
    ok = remediation.restore_backup(target)
    for r in (target.remediation.apply_results if target.remediation else []):
        print(f"    [{r['status']}] {r['command']}")
    _save_findings(cfg, findings)
    print("Rollback complete." if ok else "Rollback failed.")
    return 0 if ok else 1


def cmd_report(cfg: Config, args) -> int:
    findings = _load_findings(cfg)
    if not findings:
        return 1
    findings = _filter_severity(findings, args.min_severity or cfg.min_severity)
    out = write_report(findings, args.output, _hostname(), _now())
    print(f"Report written to {out}")
    return 0


def _rotate_reports(reports_dir: str, keep: int) -> int:
    """Keep only the newest `keep` generated reports. Returns count removed."""
    if keep <= 0:
        return 0
    pattern = os.path.join(reports_dir, "vulnscan-*.*")
    files = [p for p in glob.glob(pattern)
             if p.endswith((".pdf", ".html"))]
    files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    removed = 0
    for old in files[keep:]:
        try:
            os.remove(old)
            removed += 1
        except OSError:
            pass
    return removed


def cmd_scheduled(cfg: Config, args) -> int:
    """Non-interactive scan + dated report, for the systemd timer/cron.

    This NEVER applies fixes. With --plan it asks the AI for remediation
    proposals and embeds them in the report (still no execution).
    """
    host = _hostname()
    print(f"[{_now()}] scheduled scan on {host}")
    scanners = _select_scanners(args, cfg)
    previous = _load_findings_silent(cfg)
    findings = do_scan(cfg, scanners, enrich=not args.no_enrich and cfg.enrich)
    findings = _filter_severity(findings, args.min_severity or cfg.min_severity)
    added, resolved = diff_findings(previous, findings)
    _save_findings(cfg, findings)
    print(f"  drift: {len(added)} new, {len(resolved)} resolved since last scan")

    if args.plan and findings:
        provider = get_provider(args.provider or cfg.provider,
                                args.model or cfg.model, timeout=cfg.timeout,
                                effort=cfg.claude_effort)
        if provider.available():
            print(f"  generating remediation plan via {provider.name}/{provider.model}")
            remediation.propose_all(provider, findings)
        else:
            _eprint(f"  --plan requested but provider '{provider.name}' is not "
                    f"configured; writing scan-only report")

    reports_dir = cfg.ensure_reports_dir()
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_host = re.sub(r"[^A-Za-z0-9_.-]", "_", host)
    ext = "html" if args.html else "pdf"
    out = os.path.join(reports_dir, f"vulnscan-{safe_host}-{stamp}.{ext}")
    written = write_report(findings, out, host, _now())
    try:
        os.chmod(written, 0o640)
    except OSError:
        pass
    print(f"  {len(findings)} finding(s); report: {written}")

    removed = _rotate_reports(reports_dir, args.keep)
    if removed:
        print(f"  rotated out {removed} old report(s)")

    # Email summary (only when configured and there is something worth sending).
    if cfg.notify_email:
        from .notify import send_scan_email
        sent, info = send_scan_email(cfg, findings, added, resolved, host, _now())
        print(f"  email: {info}")

    # Optional non-zero exit so monitoring can alert on severe findings.
    if args.fail_on:
        floor = severity_rank(args.fail_on)
        hits = [f for f in findings if severity_rank(f.severity) >= floor]
        if hits:
            print(f"  {len(hits)} finding(s) at or above '{args.fail_on}'")
            return 3
    return 0


def cmd_update_oval(cfg: Config, args) -> int:
    distro_id, major = detect_distro()
    print(f"Detected distribution: {distro_id} {major}")
    print("Downloading OVAL security feed (this can be tens of MB)...")
    try:
        path = download_oval(cfg, timeout=max(cfg.timeout, 180))
    except RuntimeError as exc:
        _eprint(str(exc))
        return 1
    size = os.path.getsize(path)
    print(f"Staged OVAL feed: {path} ({size // 1024} KiB)")
    oscap_ok = SCANNERS["oscap"](cfg).available()
    if oscap_ok:
        print("OpenSCAP is now usable: vulnscan-ai scan --scanner oscap")
    else:
        print("Note: install 'openscap-scanner' to use this feed "
              "(dnf install openscap-scanner).")
    return 0


def cmd_setup(cfg: Config, args) -> int:
    from .wizard import run_setup
    return run_setup(cfg, force=True)


def cmd_dashboard(cfg: Config, args) -> int:
    from . import dashboard as D
    if args.set_password:
        import getpass
        try:
            pw = getpass.getpass("New dashboard password: ")
            pw2 = getpass.getpass("Repeat password: ")
        except (EOFError, KeyboardInterrupt):
            print()
            return 1
        if not pw or pw != pw2:
            _eprint("Passwords are empty or do not match.")
            return 1
        user = args.user or cfg.dashboard_user
        path = cfg.write_user_config({"dashboard_password_hash": D.hash_password(pw),
                                      "dashboard_user": user})
        print(f"Dashboard password set for user '{user}'. Saved to {path}")
        return 0
    if args.allow or args.deny:
        allow = list(cfg.dashboard_allow)
        for ip in (args.allow or []):
            if not D.valid_allow_entry(ip):
                _eprint(f"  ! invalid IP/CIDR, skipping: {ip}")
            elif ip not in allow:
                allow.append(ip)
        for ip in (args.deny or []):
            if ip in allow:
                allow.remove(ip)
        path = cfg.write_user_config({"dashboard_allow": allow})
        print(f"Allowed network clients: {allow or '(localhost only)'}")
        print(f"Saved to {path}")
        return 0
    if args.list:
        pw = "set" if cfg.dashboard_password_hash else "NOT set (run --set-password)"
        print(f"user:     {cfg.dashboard_user}")
        print(f"password: {pw}")
        print(f"port:     {cfg.dashboard_port}")
        print(f"bind:     {cfg.dashboard_bind}  (auto 0.0.0.0 when an allow-list is set)")
        print(f"allow:    {cfg.dashboard_allow or '(localhost only)'}")
        print(f"apply-fix: {'enabled' if cfg.dashboard_allow_fix else 'off (preview only)'}")
        return 0
    try:
        return D.serve(cfg, port=args.port, bind=args.bind)
    except D.DashboardError as exc:
        _eprint(str(exc))
        return 1
    except OSError as exc:
        _eprint(f"dashboard failed to start: {exc}")
        return 1


def cmd_menu(cfg: Config, args) -> int:
    """Launch the interactive, menu-driven front-end."""
    from .menu import run_menu
    return run_menu(cfg, build_parser())


def cmd_providers(cfg: Config, args) -> int:
    for name, cls in PROVIDERS.items():
        inst = cls()
        flag = "ready" if inst.available() else "needs config"
        print(f"{name:<8} {flag:<12} default-model={inst.default_model} "
              f"key-env={cls.api_key_env or '(none)'}")
    return 0


def cmd_news(cfg: Config, args) -> int:
    """Show recent vulnerability advisories (CISA KEV, NVD, distro errata)."""
    from . import feeds
    sources = [args.source] if args.source else cfg.news_sources
    if args.refresh:
        print("Fetching latest advisories ...")
        items, fetched_at = feeds.refresh_news(cfg, sources, limit_per=args.limit)
    else:
        items, fetched_at = feeds.load_cache(cfg)
        if not items:
            print("No cached advisories; fetching ...")
            items, fetched_at = feeds.refresh_news(cfg, sources, limit_per=args.limit)
    if args.source == "distro":
        items = [i for i in items if i.source in feeds.DISTRO_SOURCES]
    elif args.source:
        items = [i for i in items if i.source == args.source]
    # Cross-reference the last scan so locally-relevant advisories stand out.
    relevant = set()
    try:
        with open(cfg.findings_path, encoding="utf-8") as fh:
            relevant = {c.upper() for f in findings_from_json(fh.read())
                        for c in (f.cve_ids or [])}
    except OSError:
        pass
    color = _use_color()
    print(f"Advisories (updated {fetched_at or 'never'}):\n")
    for it in items[:args.limit]:
        sev = (it.severity or "unknown").lower()
        tag = f"{_SEV_TAG.get(sev, 'UNK'):<5}"
        if color:
            tag = _SEV_ANSI.get(sev, "") + tag + _RESET
        flags = ""
        if it.exploited:
            kev = "[KEV]"
            flags += " " + ((_SEV_ANSI["critical"] + kev + _RESET) if color else kev)
        if it.epss is not None and it.epss >= 0.5:
            flags += f" [EPSS {it.epss:.0%}]"
        if relevant and any(c.upper() in relevant for c in it.cve_ids):
            flags += " [on-host]"
        date = (it.published or "")[:10]
        print(f"{tag} {date:<10} {it.title[:70]}{flags}")
    print(f"\n{len(items)} advisory(ies) from: {', '.join(sorted({i.source for i in items})) or '-'}")
    return 0


# --------------------------------------------------------------------------- #
# argument parsing
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vulnscan-ai",
        description="RHEL vulnerability scanner with AI-assisted remediation "
                    "(FIPS-aware).",
    )
    p.add_argument("--version", action="version",
                   version=f"vulnscan-ai {__version__}")
    p.add_argument("--no-banner", action="store_true",
                   help="suppress the startup banner")
    p.add_argument("--config", help="path to config JSON")
    p.add_argument("--state-dir", help="override state/cache directory")
    p.add_argument("--provider",
                   help="AI provider (claude|openai|gemini|kimi|deepseek|mistral|local)")
    p.add_argument("--model", help="model id override")
    p.add_argument("--effort", choices=["low", "medium", "high", "xhigh", "max"],
                   help="Claude reasoning effort (turns on adaptive thinking; "
                        "other providers ignore it)")
    # Optional: bare `vulnscan-ai` on a terminal opens the interactive menu.
    sub = p.add_subparsers(dest="command", required=False)

    sp = sub.add_parser("menu",
                        help="interactive menu (also the default with no command)")
    sp.set_defaults(func=cmd_menu)

    sp = sub.add_parser("info", help="show host/FIPS/scanner/provider status")
    sp.set_defaults(func=cmd_info)

    sp = sub.add_parser("scan", help="scan for vulnerabilities")
    sp.add_argument("--scanner", action="append",
                    help="scanner to run (repeatable): dnf, oscap, ssh, systemd, ports, webroot, container")
    sp.add_argument("--all", action="store_true",
                    help="run every available scanner (overrides --scanner)")
    sp.add_argument("--min-severity", help="floor: low|moderate|important|critical")
    sp.add_argument("--no-enrich", action="store_true",
                    help="skip CVE-feed enrichment")
    sp.add_argument("--pdf", help="also write a PDF report to this path")
    sp.add_argument("--json", help="also write a JSON export to this path")
    sp.add_argument("--sarif", help="also write a SARIF 2.1.0 file to this path")
    sp.add_argument("--ignore", action="append", metavar="PATTERN",
                    help="suppress findings matching id/CVE/advisory/package/"
                         "title (glob, repeatable); augments the baseline")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("fix", help="propose and (with approval) apply fixes")
    sp.add_argument("--scan", action="store_true",
                    help="scan first instead of using saved findings")
    sp.add_argument("--scanner", action="append")
    sp.add_argument("--all", action="store_true",
                    help="with --scan: run every available scanner")
    sp.add_argument("--no-enrich", action="store_true")
    sp.add_argument("--min-severity")
    sp.add_argument("--yes", action="store_true",
                    help="auto-approve every fix (non-interactive)")
    sp.add_argument("--dry-run", action="store_true",
                    help="plan only; never execute")
    sp.add_argument("--pdf", help="write a PDF report after fixing")
    sp.add_argument("--export-script", metavar="PATH",
                    help="write a ready-to-run bash fix script (does not apply)")
    sp.add_argument("--export-ansible", metavar="PATH",
                    help="write an Ansible playbook of the fixes (does not apply)")
    sp.add_argument("--ignore", action="append", metavar="PATTERN",
                    help="with --scan: suppress findings matching this pattern "
                         "(glob, repeatable)")
    sp.set_defaults(func=cmd_fix)

    sp = sub.add_parser(
        "rollback",
        help="restore a previously-applied transactional fix from its backup")
    sp.add_argument("id", nargs="?", help="finding id to roll back")
    sp.add_argument("--list", action="store_true",
                    help="list fixes that have a stored backup")
    sp.set_defaults(func=cmd_rollback)

    sp = sub.add_parser("report", help="render a report from saved findings")
    sp.add_argument("-o", "--output", default="vulnscan-ai-report.pdf",
                    help="output path; format by extension: "
                         ".pdf .html .json .sarif")
    sp.add_argument("--min-severity")
    sp.set_defaults(func=cmd_report)

    sp = sub.add_parser("providers", help="list AI providers")
    sp.set_defaults(func=cmd_providers)

    sp = sub.add_parser(
        "news", help="show recent vulnerability advisories (CISA KEV, NVD, errata)")
    sp.add_argument("--source", choices=["kev", "nvd", "distro"],
                    help="only show one feed source")
    sp.add_argument("--refresh", action="store_true",
                    help="fetch fresh data instead of using the cache")
    sp.add_argument("--limit", type=int, default=30,
                    help="max advisories to show (default 30)")
    sp.set_defaults(func=cmd_news)

    sp = sub.add_parser(
        "setup", help="interactive first-run wizard: pick an offline AI model")
    sp.set_defaults(func=cmd_setup)

    sp = sub.add_parser("update-oval",
                        help="download the OpenSCAP OVAL feed for this distro")
    sp.set_defaults(func=cmd_update_oval)

    sp = sub.add_parser(
        "scheduled",
        help="non-interactive scan + dated report (for systemd timer/cron)")
    sp.add_argument("--scanner", action="append")
    sp.add_argument("--all", action="store_true",
                    help="run every available scanner")
    sp.add_argument("--no-enrich", action="store_true")
    sp.add_argument("--min-severity")
    sp.add_argument("--plan", action="store_true",
                    help="embed AI remediation proposals (no execution)")
    sp.add_argument("--html", action="store_true",
                    help="write an HTML report instead of PDF")
    sp.add_argument("--keep", type=int, default=30,
                    help="how many past reports to retain (default 30)")
    sp.add_argument("--fail-on", metavar="SEVERITY",
                    help="exit 3 if any finding is at/above this severity")
    sp.set_defaults(func=cmd_scheduled)

    sp = sub.add_parser("dashboard",
                        help="serve saved findings over an HTTPS login dashboard")
    sp.add_argument("--set-password", action="store_true",
                    help="set the admin password (prompts), then exit")
    sp.add_argument("--user", help="admin username (default: admin)")
    sp.add_argument("--allow", action="append", metavar="IP/CIDR",
                    help="permit a network client besides localhost (repeatable), then exit")
    sp.add_argument("--deny", action="append", metavar="IP/CIDR",
                    help="remove a permitted client (repeatable), then exit")
    sp.add_argument("--list", action="store_true",
                    help="show dashboard settings, then exit")
    sp.add_argument("--port", type=int, help="listen port (default: 65101)")
    sp.add_argument("--bind",
                    help="bind address (default: 127.0.0.1; auto 0.0.0.0 with an allow-list)")
    sp.set_defaults(func=cmd_dashboard)
    return p


def _apply_overrides(cfg: Config, args) -> None:
    if args.state_dir:
        cfg.state_dir = args.state_dir
    if args.provider:
        cfg.provider = args.provider
    if args.model:
        cfg.model = args.model
    if getattr(args, "effort", None):
        cfg.claude_effort = args.effort


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cfg = Config.load(args.config)
    _apply_overrides(cfg, args)

    if getattr(args, "no_banner", False):
        os.environ["VULNSCANAI_NO_BANNER"] = "1"
    print_banner(getattr(args, "command", None), _hostname())

    # First run on an interactive terminal: offer the offline-model wizard,
    # then reload config so the just-made choice applies to this command.
    from .wizard import should_offer_setup, run_setup
    if should_offer_setup(cfg, getattr(args, "command", None)):
        run_setup(cfg)
        cfg = Config.load(args.config)
        _apply_overrides(cfg, args)

    # No subcommand: open the interactive menu on a real terminal, otherwise
    # (pipes, scripts, cron) show help and exit non-zero.
    if not getattr(args, "command", None):
        if sys.stdin.isatty() and sys.stdout.isatty():
            from .menu import run_menu
            try:
                return run_menu(cfg, parser)
            except KeyboardInterrupt:
                _eprint("\nInterrupted.")
                return 130
        parser.print_help()
        return 1

    try:
        return args.func(cfg, args)
    except ProviderError as exc:
        _eprint(f"AI provider error: {exc}")
        return 2
    except KeyboardInterrupt:
        _eprint("\nInterrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
