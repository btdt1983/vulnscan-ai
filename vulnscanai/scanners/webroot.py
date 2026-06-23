# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Web document-root exposure scanner.

Finds files sitting inside a web server's document root that a visitor could
fetch over HTTP but that should never be public: database dumps (*.sql), env
and config files with secrets (.env, wp-config.php), version-control dirs
(.git/), editor/backup leftovers (*.bak, *~), archives, private keys — plus
world-writable files in the webroot (tampering/defacement risk).

Document roots are read from the server config (nginx `root`, Apache
`DocumentRoot`, lighttpd `server.document-root`, LiteSpeed `docRoot`) and from
well-known defaults that exist on disk. Detection is filesystem-only and
conservative: it matches high-signal sensitive names, and notes that the server
config *might* still block a path. Each finding carries enough context for the
AI to propose a fix (move the file out of the root, deny it in the server, or
tighten permissions).
"""

from __future__ import annotations

import glob
import os
import re
import stat
from typing import Dict, List, Optional, Tuple

from ..models import Finding
from .base import Scanner

# Where to look for server configs and the directive that names a doc root.
_NGINX_CONFS = ["/etc/nginx/nginx.conf", "/etc/nginx/conf.d/*.conf",
                "/etc/nginx/sites-enabled/*"]
_APACHE_CONFS = ["/etc/httpd/conf/httpd.conf", "/etc/httpd/conf.d/*.conf",
                 "/etc/apache2/apache2.conf", "/etc/apache2/sites-enabled/*",
                 "/etc/apache2/conf-enabled/*.conf"]
_LIGHTTPD_CONFS = ["/etc/lighttpd/lighttpd.conf",
                   "/etc/lighttpd/conf-enabled/*.conf"]
_LITESPEED_CONFS = ["/usr/local/lsws/conf/httpd_config.conf",
                    "/usr/local/lsws/conf/vhosts/*/vhconf.conf"]

# Default roots to also check when present (covers a default install).
_DEFAULT_ROOTS = [
    "/var/www/html", "/var/www", "/usr/share/nginx/html", "/srv/www",
    "/srv/http", "/var/www/lighttpd", "/usr/local/lsws/DEFAULT/html",
]

_NGINX_ROOT_RE = re.compile(r"^\s*root\s+([^;]+);", re.MULTILINE)
_APACHE_ROOT_RE = re.compile(r'^\s*DocumentRoot\s+"?([^"\n]+?)"?\s*$', re.MULTILINE)
_LIGHTTPD_ROOT_RE = re.compile(r'server\.document-root\s*=\s*"([^"]+)"')
_LITESPEED_ROOT_RE = re.compile(r'docRoot\s+(\S+)|<docRoot>([^<]+)</docRoot>')

# Caps so a huge site can't make the scan run away.
_MAX_FILES = 120_000
_MAX_FINDINGS = 200

_VCS_DIRS = (".git", ".svn", ".hg", ".bzr")
_DB_EXT = (".sql", ".sql.gz", ".sqlite", ".sqlite3", ".db", ".dump", ".mdb", ".bak.sql")
_ARCHIVE_EXT = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".rar", ".7z")
_BACKUP_SUFFIX = (".bak", ".old", ".orig", ".save", ".swp", ".swo", "~", ".tmp")
_KEY_EXT = (".pem", ".key", ".pfx", ".p12", ".keystore", ".jks", ".ppk")
_KEY_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".htpasswd", ".netrc"}
_SECRET_NAMES = {".env", "wp-config.php", "config.php", "configuration.php",
                 "settings.py", "local_settings.py", "secrets.json",
                 "database.yml", "credentials", ".pgpass", ".my.cnf"}
_INFO_NAMES = {".ds_store", "composer.lock", "package-lock.json", "yarn.lock",
               "phpinfo.php", "info.php", ".gitignore"}


def parse_nginx_roots(text: str) -> List[str]:
    return [m.strip().strip('"\'') for m in _NGINX_ROOT_RE.findall(text)]


def parse_apache_roots(text: str) -> List[str]:
    return [m.strip() for m in _APACHE_ROOT_RE.findall(text)]


def parse_lighttpd_roots(text: str) -> List[str]:
    return [m.strip() for m in _LIGHTTPD_ROOT_RE.findall(text)]


def parse_litespeed_roots(text: str) -> List[str]:
    out = []
    for a, b in _LITESPEED_ROOT_RE.findall(text):
        val = (a or b).strip()
        # LiteSpeed uses $VH_ROOT etc.; keep only concrete absolute paths.
        if val.startswith("/"):
            out.append(val)
    return out


def classify(name: str) -> Optional[Tuple[str, str, str]]:
    """Map a filename to (category, severity, reason), or None if not sensitive."""
    low = name.lower()
    if name in _KEY_NAMES or low.endswith(_KEY_EXT):
        return ("private key / credential", "critical",
                "private keys or credential files must never be web-served")
    if low == ".env" or low.startswith(".env."):
        return ("environment secrets", "critical",
                ".env files hold credentials and app secrets")
    if low in _SECRET_NAMES:
        return ("app config with secrets", "important",
                "application config often contains database/API credentials")
    if low.endswith(_DB_EXT):
        return ("database dump / data", "important",
                "a database export served over HTTP leaks all of its data")
    if low.endswith(_ARCHIVE_EXT):
        return ("archive (possible backup)", "moderate",
                "archives in the webroot are often full-site or DB backups")
    if low.endswith(_BACKUP_SUFFIX):
        return ("editor / backup leftover", "moderate",
                "backup copies can expose source or credentials")
    if low.endswith(".log"):
        return ("log file", "low",
                "logs can leak paths, tokens and internal detail")
    if low in _INFO_NAMES:
        return ("information disclosure", "low",
                "reveals stack/dependencies useful to an attacker")
    return None


def _world_writable(mode: int) -> bool:
    return bool(mode & stat.S_IWOTH)


def audit_root(root: str, server: str = "",
               budget: Optional[List[int]] = None) -> List[Finding]:
    """Walk one document root and return exposure findings.

    `budget` is a one-element list [files_remaining] shared across roots so the
    global file cap holds; pass None to use a fresh per-root budget.
    """
    if budget is None:
        budget = [_MAX_FILES]
    findings: List[Finding] = []

    def _add(path: str, category: str, severity: str, reason: str,
             mode: Optional[int]) -> None:
        rel = os.path.relpath(path, root)
        findings.append(Finding(
            source="webroot",
            title=f"{category}: {rel}",
            severity=severity,
            description=(f"{path} sits inside the web document root "
                        f"({root}) and {reason}. A visitor may be able to "
                        f"download it over HTTP unless the server config "
                        f"explicitly denies it. Move it out of the webroot, "
                        f"delete it, or deny access in the server."),
            references=[],
            raw={"path": path, "webroot": root, "server": server,
                 "category": category, "reason": reason,
                 "mode": oct(mode) if mode is not None else None},
        ))

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Version-control directories: flag once, don't descend into them.
        for vcs in list(dirnames):
            if vcs in _VCS_DIRS:
                _add(os.path.join(dirpath, vcs), "version-control directory",
                     "important",
                     "exposes source code and full history (e.g. .git/config, "
                     "objects)", None)
                dirnames.remove(vcs)
        for fn in filenames:
            if budget[0] <= 0 or len(findings) >= _MAX_FINDINGS:
                return findings
            budget[0] -= 1
            full = os.path.join(dirpath, fn)
            cat = classify(fn)
            try:
                mode = os.lstat(full).st_mode
            except OSError:
                mode = 0
            if cat:
                _add(full, cat[0], cat[1], cat[2], mode)
            elif stat.S_ISREG(mode) and _world_writable(mode):
                _add(full, "world-writable file", "moderate",
                     "is writable by any local user, allowing tampering or "
                     "defacement", mode)
    return findings


class WebrootScanner(Scanner):
    name = "webroot"

    def _discover_roots(self) -> List[Tuple[str, str]]:
        """Return [(root, server), ...] of existing, de-duplicated doc roots."""
        found: Dict[str, str] = {}

        def _collect(globs: List[str], parser, server: str) -> None:
            for pattern in globs:
                for path in glob.glob(pattern):
                    try:
                        with open(path, "r", encoding="utf-8", errors="replace") as fh:
                            text = fh.read()
                    except OSError:
                        continue
                    for root in parser(text):
                        if os.path.isdir(root):
                            found.setdefault(os.path.realpath(root), server)

        _collect(_NGINX_CONFS, parse_nginx_roots, "nginx")
        _collect(_APACHE_CONFS, parse_apache_roots, "apache")
        _collect(_LIGHTTPD_CONFS, parse_lighttpd_roots, "lighttpd")
        _collect(_LITESPEED_CONFS, parse_litespeed_roots, "litespeed")
        for root in _DEFAULT_ROOTS:
            if os.path.isdir(root):
                found.setdefault(os.path.realpath(root), "default")

        # Drop a root that is nested under another collected root (avoid double
        # scanning); keep the shallowest.
        roots = sorted(found)
        kept: List[Tuple[str, str]] = []
        for r in roots:
            if any(r != k and r.startswith(k.rstrip("/") + "/") for k in found):
                continue
            kept.append((r, found[r]))
        return kept

    def available(self) -> bool:
        return bool(self._discover_roots())

    def scan(self) -> List[Finding]:
        budget = [_MAX_FILES]
        out: List[Finding] = []
        for root, server in self._discover_roots():
            out.extend(audit_root(root, server, budget))
            if len(out) >= _MAX_FINDINGS or budget[0] <= 0:
                break
        return out[:_MAX_FINDINGS]
