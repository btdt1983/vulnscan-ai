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
    scanners: List[str] = field(default_factory=lambda: ["dnf"])
    state_dir: str = DEFAULT_STATE_DIR
    min_severity: str = "low"                # low|moderate|important|critical
    enrich: bool = True                      # query CVE web feeds for detail
    vendor_state_filter: bool = True         # drop Red Hat "not affected" CVEs
    service_state_filter: bool = True        # downgrade dormant-daemon findings
    redhat_api: str = "https://access.redhat.com/hydra/rest/securitydata"
    nvd_api: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: Optional[str] = None
    auto_approve: bool = False               # skip the per-fix confirmation
    dry_run: bool = False                    # never execute, only plan
    timeout: int = 30
    reports_dir: Optional[str] = None        # default: <state_dir>/reports
    ignore: List[str] = field(default_factory=list)  # baseline suppression
    extra: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        data: Dict[str, Any] = {}
        # Merge in precedence order so later files win: system (/etc) first,
        # then the per-user config (where the setup wizard saves its choice).
        candidates = [path] if path else CONFIG_PATHS
        for p in candidates:
            if p and os.path.isfile(p):
                with open(p, "r", encoding="utf-8") as fh:
                    data.update(json.load(fh))
        cfg = cls(**{k: v for k, v in data.items()
                     if k in cls.__dataclass_fields__})  # type: ignore[attr-defined]
        # Merge a newline-delimited baseline file (one pattern per line).
        ignore_file = os.path.expanduser("~/.config/vulnscan-ai/ignore")
        if os.path.isfile(ignore_file):
            with open(ignore_file, "r", encoding="utf-8") as fh:
                cfg.ignore.extend(ln.strip() for ln in fh
                                  if ln.strip() and not ln.startswith("#"))
        cfg._apply_env()
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
        if env.get("VULNSCANAI_STATE_DIR"):
            self.state_dir = env["VULNSCANAI_STATE_DIR"]
        if env.get("NVD_API_KEY"):
            self.nvd_api_key = env["NVD_API_KEY"]
        if env.get("VULNSCANAI_IGNORE"):
            self.ignore.extend(p.strip() for p in
                               env["VULNSCANAI_IGNORE"].split(",") if p.strip())

    def ensure_state_dir(self) -> str:
        os.makedirs(self.state_dir, mode=0o700, exist_ok=True)
        return self.state_dir

    @property
    def findings_path(self) -> str:
        return os.path.join(self.state_dir, "findings.json")

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
