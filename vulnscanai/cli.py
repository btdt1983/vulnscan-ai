"""Command line interface for vulnscan-ai."""

from __future__ import annotations

import argparse
import datetime
import glob
import os
import re
import socket
import sys
from typing import List, Optional

from . import __version__, export_fix, remediation
from .ai import PROVIDERS, ProviderError, get_provider
from .config import Config
from .fips import status_line
from .models import (
    Finding, apply_ignores, dedup_cross_scanner, findings_from_json,
    findings_to_json, merge_findings, severity_rank,
)
from .report import write_report
from .scanners import SCANNERS, NvdEnricher, detect_distro, download_oval


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


def _print_findings(findings: List[Finding]) -> None:
    if not findings:
        print("No vulnerabilities found.")
        return
    findings = sorted(findings, key=lambda f: (-severity_rank(f.severity),
                                               -(f.cvss_score or 0)))
    print(f"{'SEV':<5} {'CVSS':<5} {'PACKAGE / ISSUE':<45} {'ADVISORY':<14} CVEs")
    print("-" * 90)
    for f in findings:
        tag = _SEV_TAG.get(f.severity.lower(), "UNK")
        cvss = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "-"
        # Package findings show the package; config findings (ssh, systemd, ...)
        # have no package, so fall back to the title.
        subject = (f.package or f.title or "-")[:44]
        adv = (f.advisory or "-")[:13]
        cves = ", ".join(f.cve_ids[:3]) + ("…" if len(f.cve_ids) > 3 else "")
        print(f"{tag:<5} {cvss:<5} {subject:<45} {adv:<14} {cves}")
    print("-" * 90)
    print(f"{len(findings)} finding(s).")


def _filter_severity(findings: List[Finding], minimum: str) -> List[Finding]:
    floor = severity_rank(minimum)
    return [f for f in findings if severity_rank(f.severity) >= floor]


# --------------------------------------------------------------------------- #
# scanning
# --------------------------------------------------------------------------- #
def do_scan(cfg: Config, scanners: List[str], enrich: bool,
            extra_ignores: Optional[List[str]] = None) -> List[Finding]:
    findings: List[Finding] = []
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
    scanners = args.scanner or cfg.scanners
    print(f"Scanning {_hostname()} ...")
    findings = do_scan(cfg, scanners, enrich=not args.no_enrich and cfg.enrich,
                       extra_ignores=args.ignore)
    findings = _filter_severity(findings, args.min_severity or cfg.min_severity)
    _save_findings(cfg, findings)
    print()
    _print_findings(findings)
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
        ans = input("Apply this fix? [y]es / [n]o / [a]ll / [q]uit: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return "quit"
    return {"y": "yes", "a": "all", "q": "quit"}.get(ans, "no")


def cmd_fix(cfg: Config, args) -> int:
    if args.scan:
        print(f"Scanning {_hostname()} ...")
        findings = do_scan(cfg, args.scanner or cfg.scanners,
                           enrich=not args.no_enrich and cfg.enrich,
                           extra_ignores=getattr(args, "ignore", None))
    else:
        findings = _load_findings(cfg)
    if not findings:
        return 1
    findings = _filter_severity(findings, args.min_severity or cfg.min_severity)

    provider = get_provider(args.provider or cfg.provider, args.model or cfg.model,
                            timeout=cfg.timeout)
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
            os.chmod(args.export_script, 0o755)
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
    for f in findings:
        decision = "all" if approve_all else _approve(f, auto=False)
        if decision == "quit":
            print("Aborted by operator.")
            break
        if decision == "all":
            approve_all = True
            decision = "yes"
        if decision != "yes":
            print("  skipped.")
            continue
        ok = remediation.apply(f, dry_run=dry, state_dir=cfg.state_dir)
        applied += 1 if ok else 0
        for r in (f.remediation.apply_results if f.remediation else []):
            print(f"    [{r['status']}] {r['command']}")
        if f.remediation and f.remediation.rolled_back:
            rolled += 1
            print("    ROLLED BACK — change reverted, service left healthy.")

    _save_findings(cfg, findings)
    print(f"\n{'(dry-run) ' if dry else ''}Processed; "
          f"{applied} fix(es) applied successfully"
          f"{f', {rolled} rolled back' if rolled else ''}.")
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
    scanners = args.scanner or cfg.scanners
    findings = do_scan(cfg, scanners, enrich=not args.no_enrich and cfg.enrich)
    findings = _filter_severity(findings, args.min_severity or cfg.min_severity)
    _save_findings(cfg, findings)

    if args.plan and findings:
        provider = get_provider(args.provider or cfg.provider,
                                args.model or cfg.model, timeout=cfg.timeout)
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


def cmd_providers(cfg: Config, args) -> int:
    for name, cls in PROVIDERS.items():
        inst = cls()
        flag = "ready" if inst.available() else "needs config"
        print(f"{name:<8} {flag:<12} default-model={inst.default_model} "
              f"key-env={cls.api_key_env or '(none)'}")
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
    p.add_argument("--config", help="path to config JSON")
    p.add_argument("--state-dir", help="override state/cache directory")
    p.add_argument("--provider",
                   help="AI provider (claude|openai|gemini|kimi|deepseek|mistral|local)")
    p.add_argument("--model", help="model id override")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("info", help="show host/FIPS/scanner/provider status")
    sp.set_defaults(func=cmd_info)

    sp = sub.add_parser("scan", help="scan for vulnerabilities")
    sp.add_argument("--scanner", action="append",
                    help="scanner to run (repeatable): dnf, oscap, ssh, systemd, ports")
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
        "setup", help="interactive first-run wizard: pick an offline AI model")
    sp.set_defaults(func=cmd_setup)

    sp = sub.add_parser("update-oval",
                        help="download the OpenSCAP OVAL feed for this distro")
    sp.set_defaults(func=cmd_update_oval)

    sp = sub.add_parser(
        "scheduled",
        help="non-interactive scan + dated report (for systemd timer/cron)")
    sp.add_argument("--scanner", action="append")
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
    return p


def _apply_overrides(cfg: Config, args) -> None:
    if args.state_dir:
        cfg.state_dir = args.state_dir
    if args.provider:
        cfg.provider = args.provider
    if args.model:
        cfg.model = args.model


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cfg = Config.load(args.config)
    _apply_overrides(cfg, args)

    # First run on an interactive terminal: offer the offline-model wizard,
    # then reload config so the just-made choice applies to this command.
    from .wizard import should_offer_setup, run_setup
    if should_offer_setup(cfg, getattr(args, "command", None)):
        run_setup(cfg)
        cfg = Config.load(args.config)
        _apply_overrides(cfg, args)

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
