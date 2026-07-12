# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Configuration loading and defaults.

Config precedence (highest first):
    1. command line flags
    2. environment variables (VULNSCANAI_*)
    3. config file (--config, or /etc/vulnscan-ai/config.json, or
       ~/.config/vulnscan-ai/config.json)
    4. built-in defaults
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

CONFIG_PATHS = [
    "/etc/vulnscan-ai/config.json",
    os.path.expanduser("~/.config/vulnscan-ai/config.json"),
]

DEFAULT_PROVIDER = "claude"
# Default work/cache directory for findings and report artifacts.
DEFAULT_STATE_DIR = os.path.expanduser("~/.local/state/vulnscan-ai")


@dataclass
class Config:
    provider: str = DEFAULT_PROVIDER
    model: Optional[str] = None              # provider default if None
    claude_effort: Optional[str] = None      # Claude reasoning effort: low|medium|high|xhigh|max
    scanners: List[str] = field(default_factory=lambda: ["dnf"])
    state_dir: str = DEFAULT_STATE_DIR
    min_severity: str = "low"                # low|moderate|important|critical
    enrich: bool = True                      # query CVE web feeds for detail
    vendor_state_filter: bool = True         # drop Red Hat "not affected" CVEs
    service_state_filter: bool = True        # downgrade dormant-daemon findings
    patched_filter: bool = True              # drop findings already patched (no installable update)
    offline_catalog: bool = True             # deterministic dnf plan for package fixes (no AI)
    exploit_enrich: bool = True              # KEV/EPSS exploitation intel (network)
    oval_auto_update: bool = True            # auto-refresh a stale OVAL feed on scan
    oval_max_age_days: int = 7               # OVAL considered stale past this age
    fips_required: bool = False              # treat a non-FIPS host as a finding (fips scanner)
    # Compliance benchmark scanning (scan --compliance <profile>).
    compliance_profile: str = "cis-l1"       # default XCCDF profile (alias or id)
    compliance_datastream: Optional[str] = None  # SCAP datastream path; None = auto-detect
    # Dashboard "Advisories" news tab (vulnscanai/feeds.py).
    news_enabled: bool = True                # show the news tab + allow refresh
    news_sources: List[str] = field(default_factory=lambda: ["kev", "nvd", "distro"])
    news_refresh_hours: int = 12             # cache TTL before a background refresh
    redhat_api: str = "https://access.redhat.com/hydra/rest/securitydata"
    nvd_api: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: Optional[str] = None
    auto_approve: bool = False               # skip the per-fix confirmation
    dry_run: bool = False                    # never execute, only plan
    timeout: int = 30
    reports_dir: Optional[str] = None        # default: <state_dir>/reports
    ignore: List[str] = field(default_factory=list)  # baseline suppression
    # Provider API keys captured by the setup wizard, keyed by env-var name
    # (e.g. {"ANTHROPIC_API_KEY": "sk-ant-..."}). Injected into the environment
    # on load so the providers pick them up; a real env var always wins.
    api_keys: Dict[str, str] = field(default_factory=dict)
    # Email notifications for scheduled scans (configured via the wizard).
    notify_email: Optional[str] = None       # recipient; enables email when set
    notify_min_severity: str = "important"   # email only if findings >= this
    smtp_host: str = "localhost"
    smtp_port: int = 25
    smtp_from: Optional[str] = None           # default: notify_email
    smtp_user: Optional[str] = None           # set to enable SMTP auth
    smtp_password: Optional[str] = None       # prefer VULNSCANAI_SMTP_PASSWORD
    smtp_starttls: bool = False
    # Web dashboard (vulnscan-ai dashboard).
    dashboard_user: str = "admin"
    dashboard_password_hash: Optional[str] = None  # set via --set-password
    dashboard_port: int = 65101            # avoid browser-blocked ports (e.g. 6666)
    dashboard_bind: str = "127.0.0.1"               # localhost unless allow-list
    dashboard_allow: List[str] = field(default_factory=list)  # client IPs/CIDRs
    dashboard_cert: Optional[str] = None            # default: <state_dir>/dashboard-cert.pem
    dashboard_key: Optional[str] = None             # default: <state_dir>/dashboard-key.pem
    dashboard_allow_fix: bool = False               # allow applying fixes from the dashboard UI
    extra: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        data: Dict[str, Any] = {}
        # Merge in precedence order so later files win: system (/etc) first,
        # then the per-user config (where the setup wizard saves its choice).
        candidates = [path] if path else CONFIG_PATHS
        for p in candidates:
            if p and os.path.isfile(p):
                # A corrupt or unreadable config file must not brick every
                # command: warn and fall back to defaults / the other files.
                try:
                    with open(p, "r", encoding="utf-8") as fh:
                        loaded = json.load(fh)
                    if isinstance(loaded, dict):
                        data.update(loaded)
                    else:
                        print(f"warning: ignoring config {p}: not a JSON object",
                              file=sys.stderr)
                except (OSError, ValueError) as exc:
                    print(f"warning: ignoring unreadable config {p}: {exc}",
                          file=sys.stderr)
        cfg = cls(**{k: v for k, v in data.items()
                     if k in cls.__dataclass_fields__})  # type: ignore[attr-defined]
        # Merge a newline-delimited baseline file (one pattern per line).
        ignore_file = os.path.expanduser("~/.config/vulnscan-ai/ignore")
        if os.path.isfile(ignore_file):
            with open(ignore_file, "r", encoding="utf-8") as fh:
                cfg.ignore.extend(ln.strip() for ln in fh
                                  if ln.strip() and not ln.startswith("#"))
        cfg._apply_env()
        # Make wizard-stored API keys visible to the providers (which read
        # os.environ). A key already set in the real environment always wins.
        for env_name, value in (cfg.api_keys or {}).items():
            if value and env_name not in os.environ:
                os.environ[env_name] = value
        return cfg

    @staticmethod
    def user_config_path() -> str:
        return os.path.expanduser("~/.config/vulnscan-ai/config.json")

    def write_user_config(self, updates: Dict[str, Any]) -> str:
        """Merge `updates` into the per-user config file and return its path."""
        path = self.user_config_path()
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        data: Dict[str, Any] = {}
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        data.update(updates)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.chmod(path, 0o600)
        return path

    def _apply_env(self) -> None:
        env = os.environ
        if env.get("VULNSCANAI_PROVIDER"):
            self.provider = env["VULNSCANAI_PROVIDER"]
        if env.get("VULNSCANAI_MODEL"):
            self.model = env["VULNSCANAI_MODEL"]
        if env.get("VULNSCANAI_CLAUDE_EFFORT"):
            self.claude_effort = env["VULNSCANAI_CLAUDE_EFFORT"]
        if env.get("VULNSCANAI_STATE_DIR"):
            self.state_dir = env["VULNSCANAI_STATE_DIR"]
        if env.get("NVD_API_KEY"):
            self.nvd_api_key = env["NVD_API_KEY"]
        if env.get("VULNSCANAI_IGNORE"):
            self.ignore.extend(p.strip() for p in
                               env["VULNSCANAI_IGNORE"].split(",") if p.strip())
        if env.get("VULNSCANAI_NOTIFY_EMAIL"):
            self.notify_email = env["VULNSCANAI_NOTIFY_EMAIL"]
        if env.get("VULNSCANAI_SMTP_PASSWORD"):
            self.smtp_password = env["VULNSCANAI_SMTP_PASSWORD"]

    def ensure_state_dir(self) -> str:
        os.makedirs(self.state_dir, mode=0o700, exist_ok=True)
        return self.state_dir

    @property
    def findings_path(self) -> str:
        return os.path.join(self.state_dir, "findings.json")

    @property
    def compliance_path(self) -> str:
        return os.path.join(self.state_dir, "compliance.json")

    # -- first-run wizard bookkeeping -------------------------------------- #
    @property
    def setup_marker(self) -> str:
        return os.path.join(self.state_dir, ".setup-done")

    def is_setup_done(self) -> bool:
        return os.path.exists(self.setup_marker)

    def mark_setup_done(self) -> None:
        try:
            self.ensure_state_dir()
            with open(self.setup_marker, "w", encoding="ascii") as fh:
                fh.write("1\n")
        except OSError:
            pass  # best effort; never block on the marker

    @property
    def resolved_reports_dir(self) -> str:
        return self.reports_dir or os.path.join(self.state_dir, "reports")

    def ensure_reports_dir(self) -> str:
        path = self.resolved_reports_dir
        os.makedirs(path, mode=0o750, exist_ok=True)
        return path
