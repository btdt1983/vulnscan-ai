# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""A small, dependency-free HTTPS dashboard for scan results.

stdlib only (`http.server` + `ssl`), in the spirit of the rest of the tool:

  * TLS with a self-signed certificate generated on first run (system OpenSSL),
  * a single shared admin login (username + PBKDF2-SHA256 password hash, both
    FIPS-approved), with in-memory sessions over a Secure/HttpOnly cookie,
  * bound to localhost by default; specific client IPs/CIDRs can be allowed
    (managed from the CLI or the dashboard), and the server then also listens
    on the network for exactly those hosts,
  * read-only view of the saved findings with their explanations.

It never starts without a password configured, so scan data is never exposed
unauthenticated.
"""

from __future__ import annotations

import html
import http.server
import ipaddress
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import threading
import time
from hashlib import pbkdf2_hmac
from hmac import compare_digest
from http.cookies import SimpleCookie
from typing import List, Optional
from urllib.parse import parse_qs

from . import __version__
from .models import Finding, findings_from_json, severity_rank

PBKDF2_ITERS = 200_000
SESSION_TTL = 8 * 3600           # seconds
HTTPStatusForbidden = 403
HTTPStatusNotFound = 404
HTTPStatusSeeOther = 303

# Ports browsers refuse to open (Chrome ERR_UNSAFE_PORT / Firefox banned list).
# Not exhaustive, but covers the ones a dashboard might plausibly land on.
BROWSER_BLOCKED_PORTS = {
    1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77,
    79, 87, 95, 101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123,
    135, 137, 139, 143, 161, 179, 389, 427, 465, 512, 513, 514, 515, 526, 530,
    531, 532, 540, 548, 554, 556, 563, 587, 601, 636, 989, 990, 993, 995,
    1719, 1720, 1723, 2049, 3659, 4045, 5060, 5061, 6000, 6566, 6665, 6666,
    6667, 6668, 6669, 6697, 10080,
}
_SEV_COLOR = {
    "critical": "#b3261e", "important": "#d1410c", "high": "#d1410c",
    "moderate": "#b58900", "medium": "#b58900", "low": "#1a7f37",
    "unknown": "#5b6675",
}


class DashboardError(Exception):
    pass


# --------------------------------------------------------------------------- #
# password hashing (PBKDF2-HMAC-SHA256 — FIPS approved)
# --------------------------------------------------------------------------- #
def hash_password(password: str, *, iterations: int = PBKDF2_ITERS,
                  salt: Optional[bytes] = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = pbkdf2_hmac("sha256", password.encode("utf-8"),
                         bytes.fromhex(salt_hex), int(iters))
        return compare_digest(dk.hex(), hash_hex)
    except (ValueError, AttributeError):
        return False


# --------------------------------------------------------------------------- #
# client allow-list (loopback is always allowed)
# --------------------------------------------------------------------------- #
def client_allowed(client_ip: str, allow_entries: List[str]) -> bool:
    try:
        ip = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    if ip.is_loopback:
        return True
    for entry in allow_entries:
        try:
            if ip in ipaddress.ip_network(entry.strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


def valid_allow_entry(entry: str) -> bool:
    try:
        ipaddress.ip_network(entry.strip(), strict=False)
        return True
    except ValueError:
        return False


def firewall_hint(port: int, bind: str, allow: List[str]) -> Optional[str]:
    """Best-effort: when serving on the network behind a running firewalld that
    doesn't open this port, return a copy-paste rule to allow the clients.

    Returns None when it doesn't apply (localhost only, no firewalld, or the
    port is already open / covered by a rich rule). Never raises.
    """
    if bind in ("127.0.0.1", "::1", "localhost") and not allow:
        return None  # not reachable from the network anyway
    if not shutil.which("firewall-cmd"):
        return None
    try:
        st = subprocess.run(["firewall-cmd", "--state"], capture_output=True,
                            text=True, timeout=5)
        if st.returncode != 0 or "running" not in st.stdout:
            return None
        q = subprocess.run(["firewall-cmd", f"--query-port={port}/tcp"],
                          capture_output=True, text=True, timeout=5)
        if q.returncode == 0:                       # port already open
            return None
        rr = subprocess.run(["firewall-cmd", "--list-rich-rules"],
                           capture_output=True, text=True, timeout=5)
        if f'port="{port}"' in rr.stdout or f"port={port}" in rr.stdout:
            return None                             # covered by a rich rule
    except (OSError, subprocess.SubprocessError):
        return None
    src = allow[0] if allow else f"{bind}/24"
    return (f"port {port}/tcp looks closed in firewalld. To let your network "
            f"clients reach the dashboard:\n"
            f"    sudo firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" "
            f"source address=\"{src}\" port port=\"{port}\" protocol=\"tcp\" accept'\n"
            f"    sudo firewall-cmd --reload")


# --------------------------------------------------------------------------- #
# self-signed certificate (system OpenSSL)
# --------------------------------------------------------------------------- #
def ensure_cert(cert_path: str, key_path: str, host: str) -> None:
    if os.path.isfile(cert_path) and os.path.isfile(key_path):
        return
    os.makedirs(os.path.dirname(cert_path), mode=0o700, exist_ok=True)
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key_path, "-out", cert_path, "-days", "825",
         "-subj", f"/CN={host}",
         "-addext", f"subjectAltName=DNS:{host},DNS:localhost,IP:127.0.0.1"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.chmod(key_path, 0o600)
    os.chmod(cert_path, 0o644)


# --------------------------------------------------------------------------- #
# sessions (in memory; lost on restart, which just forces re-login)
# --------------------------------------------------------------------------- #
class _Sessions:
    def __init__(self) -> None:
        self._tokens: dict = {}

    def create(self) -> str:
        tok = secrets.token_urlsafe(32)
        self._tokens[tok] = time.time() + SESSION_TTL
        return tok

    def valid(self, tok: Optional[str]) -> bool:
        if not tok:
            return False
        exp = self._tokens.get(tok)
        if exp is None:
            return False
        if exp < time.time():
            self._tokens.pop(tok, None)
            return False
        return True

    def drop(self, tok: Optional[str]) -> None:
        if tok:
            self._tokens.pop(tok, None)


# --------------------------------------------------------------------------- #
# HTML rendering
# --------------------------------------------------------------------------- #
_STYLE = """
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;
  background:#f6f8fa;color:#10151c;line-height:1.5}
.wrap{max-width:60rem;margin:0 auto;padding:1.5rem 1.25rem}
header{background:#0d1424;color:#e8edf6;padding:1rem 0}
header .wrap{display:flex;align-items:center;gap:1rem;flex-wrap:wrap}
header b{font-weight:700}.spacer{flex:1}
a{color:#1f6feb;text-decoration:none}a:hover{text-decoration:underline}
header a{color:#9fb0c8}
.tiles{display:flex;gap:.6rem;flex-wrap:wrap;margin:1.25rem 0}
.tile{background:#fff;border:1px solid #e6e9ee;border-radius:10px;padding:.6rem 1rem;
  min-width:6rem}
.tile .n{font-size:1.5rem;font-weight:700}.tile .l{font-size:.78rem;color:#5b6675;
  text-transform:uppercase;letter-spacing:.03em}
.f{background:#fff;border:1px solid #e6e9ee;border-left:4px solid #ccc;border-radius:8px;
  padding:.8rem 1rem;margin:.6rem 0}
.f h3{margin:.1rem 0 .3rem;font-size:1.02rem}
.badge{display:inline-block;color:#fff;font-size:.72rem;font-weight:700;padding:.1rem .5rem;
  border-radius:999px;text-transform:uppercase;vertical-align:middle;margin-right:.4rem}
.meta{font-size:.85rem;color:#5b6675;margin:.2rem 0}
.desc{font-size:.92rem;margin:.5rem 0 0;white-space:pre-wrap}
.rem{background:#f6f8fa;border-radius:6px;padding:.5rem .7rem;margin-top:.5rem;font-size:.9rem}
.rem code{background:#eef1f6;padding:.1rem .3rem;border-radius:4px}
code{font-family:ui-monospace,Menlo,Consolas,monospace}
form.inline{display:inline}
input[type=text],input[type=password]{padding:.45rem .6rem;border:1px solid #cdd3dc;
  border-radius:6px;font-size:.95rem}
button{background:#1f6feb;color:#fff;border:0;border-radius:6px;padding:.5rem .9rem;
  font-size:.92rem;cursor:pointer}button:hover{background:#0a4bbf}
.login{max-width:22rem;margin:5rem auto;background:#fff;border:1px solid #e6e9ee;
  border-radius:12px;padding:1.75rem 1.5rem}
.login input{width:100%;margin:.3rem 0 .8rem}
.brandmark{display:flex;align-items:center;justify-content:center;gap:.55rem;margin-bottom:.4rem}
.brandmark .wm{font-size:1.5rem;font-weight:800;letter-spacing:-.02em;color:#10151c}
.brandmark .wm .dot{color:#1f6feb}
.login .tag{text-align:center;color:#5b6675;font-size:.84rem;margin:0 0 1.3rem;
  text-transform:uppercase;letter-spacing:.06em}
.login label{font-size:.85rem;color:#5b6675}
.err{color:#b3261e;font-size:.9rem;margin:.3rem 0}
.allow{font-size:.85rem;color:#5b6675;margin-top:1.5rem;border-top:1px solid #e6e9ee;
  padding-top:1rem}
.allow code{margin-right:.3rem}
.actions{margin-top:.6rem;display:flex;gap:.5rem;flex-wrap:wrap}
.btn-sm{font-size:.82rem;padding:.35rem .7rem;border-radius:6px;border:1px solid #cdd3dc;
  background:#fff;color:#10151c;cursor:pointer}
.btn-sm:hover{background:#f0f3f7}
.btn-apply{background:#b3261e;color:#fff;border-color:#b3261e}
.btn-apply:hover{background:#911e18}
.scanbtn{background:#1f6feb;color:#fff;border:0;border-radius:6px;padding:.45rem .9rem;
  font-size:.88rem;cursor:pointer}.scanbtn:hover{background:#0a4bbf}
.scanbtn[disabled]{opacity:.6;cursor:default}
.flash{background:#eef4ff;border:1px solid #cfe0ff;border-radius:8px;padding:.6rem .9rem;
  margin:1rem 0;font-size:.92rem}
.ok{color:#1a7f37}.bad{color:#b3261e}
"""


def logo_svg(px: int = 40) -> str:
    """Inline SVG brand logo: a security shield with a verified check."""
    return (
        f'<svg width="{px}" height="{px}" viewBox="0 0 48 48" fill="none" '
        f'xmlns="http://www.w3.org/2000/svg" aria-hidden="true" '
        f'style="vertical-align:middle">'
        f'<path d="M24 3.5 41 9.2V23c0 11-7.4 18.4-17 21.8C14.4 41.4 7 34 7 23V9.2z" '
        f'fill="#1f6feb"/>'
        f'<path d="M24 3.5 41 9.2V23c0 11-7.4 18.4-17 21.8z" fill="#1856c4"/>'
        f'<path d="M15.5 24.2l6 6 11-13" stroke="#fff" stroke-width="3.2" '
        f'stroke-linecap="round" stroke-linejoin="round"/>'
        f'</svg>')


def render_login(error: str = "") -> str:
    err = f'<div class="err">{html.escape(error)}</div>' if error else ""
    return f"""<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>vulnscan-ai dashboard — sign in</title><style>{_STYLE}</style></head><body>
<div class="login">
  <div class="brandmark">{logo_svg(40)}
    <span class="wm">vulnscan<span class="dot">&middot;</span>ai</span></div>
  <div class="tag">dashboard</div>{err}
  <form method=post action="/login">
    <label>Username</label><input type=text name=username autofocus>
    <label>Password</label><input type=password name=password>
    <button type=submit>Sign in</button>
  </form>
</div></body></html>"""


def _finding_html(f: Finding, allow_fix: bool = False) -> str:
    sev = (f.severity or "unknown").lower()
    color = _SEV_COLOR.get(sev, "#5b6675")
    parts = [f'<div class="f" style="border-left-color:{color}">']
    parts.append(f'<h3><span class="badge" style="background:{color}">'
                 f'{html.escape(sev)}</span>{html.escape(f.title or "(untitled)")}</h3>')
    meta = []
    if f.package:
        ver = f" {f.installed_version} → {f.fixed_version}" if f.fixed_version else ""
        meta.append(f"package: <code>{html.escape(f.package)}</code>{html.escape(ver)}")
    if f.advisory:
        meta.append(f"advisory: {html.escape(f.advisory)}")
    if f.cve_ids:
        links = ", ".join(
            f'<a href="https://access.redhat.com/security/cve/{html.escape(c)}" '
            f'target=_blank rel=noopener>{html.escape(c)}</a>' for c in f.cve_ids[:8])
        meta.append("CVEs: " + links)
    if f.source:
        meta.append(f"source: {html.escape(f.source)}")
    if meta:
        parts.append('<div class="meta">' + " &middot; ".join(meta) + "</div>")
    flags = []
    if f.vendor_fix_state:
        flags.append(f"vendor: {html.escape(f.vendor_fix_state)}")
    if f.runtime_state and f.runtime_state != "active":
        flags.append(f"runtime: {html.escape(f.runtime_state)}")
    if flags:
        parts.append('<div class="meta">' + " &middot; ".join(flags) + "</div>")
    if f.description:
        parts.append(f'<div class="desc">{html.escape(f.description)}</div>')
    rem = f.remediation
    if rem and (rem.summary or rem.commands):
        body = []
        if rem.summary:
            body.append(f"<b>Fix:</b> {html.escape(rem.summary)} "
                        f"<span class=meta>(risk {html.escape(rem.risk)}, "
                        f"confidence {rem.confidence:.0%})</span>")
        for c in rem.commands[:8]:
            body.append(f"<div><code>{html.escape(c)}</code></div>")
        parts.append('<div class="rem">' + "".join(body) + "</div>")
    # Per-finding actions: Preview (AI plan, dry-run) always; Apply only when
    # the operator opted in via dashboard_allow_fix.
    apply_btn = (f'<button class="btn-sm btn-apply" name="mode" value="apply">'
                 f'Apply fix</button>' if allow_fix else "")
    parts.append(
        f'<form method="post" action="/fix" class="actions">'
        f'<input type="hidden" name="id" value="{html.escape(f.id)}">'
        f'<button class="btn-sm" name="mode" value="preview">Preview fix</button>'
        f'{apply_btn}</form>')
    parts.append("</div>")
    return "".join(parts)


def render_fix_result(title: str, fid: str, rem, allow_fix: bool,
                      *, applied: bool = False, error: str = "") -> str:
    """Render the outcome of a Preview/Apply action."""
    parts = [f'<h2 style="margin:1rem 0 .3rem">{html.escape(title)}</h2>']
    if error:
        parts.append(f'<div class="flash bad">{html.escape(error)}</div>')
    if rem is not None:
        meta = (f'(risk {html.escape(rem.risk)}, '
                f'confidence {rem.confidence:.0%})')
        parts.append(f'<p><b>Proposed fix:</b> {html.escape(rem.summary or "—")} '
                     f'<span class="meta">{meta}</span></p>')
        if rem.commands:
            parts.append('<div class="rem">' + "".join(
                f'<div><code>{html.escape(c)}</code></div>'
                for c in rem.commands) + '</div>')
        results = getattr(rem, "apply_results", None) or []
        if results:
            rows = "".join(
                f'<div>{html.escape(str(r.get("status", "?")))}: '
                f'<code>{html.escape(str(r.get("command", r.get("step", ""))))}</code></div>'
                for r in results)
            label = ('<span class="ok">applied</span>' if applied and not rem.rolled_back
                     else ('<span class="bad">rolled back</span>' if rem.rolled_back
                           else 'dry-run (not executed)'))
            parts.append(f'<p><b>Result:</b> {label}</p><div class="rem">{rows}</div>')
        elif not applied:
            parts.append('<p class="meta">Preview only — nothing was executed.</p>')
    if rem is not None and not applied and not error:
        if allow_fix:
            parts.append(
                f'<form method="post" action="/fix" style="margin-top:1rem">'
                f'<input type="hidden" name="id" value="{html.escape(fid)}">'
                f'<button class="btn-sm btn-apply" name="mode" value="apply">'
                f'Apply this fix now</button></form>')
        else:
            parts.append('<p class="meta">Applying from the dashboard is disabled. '
                         'Set <code>dashboard_allow_fix: true</code> in the config to '
                         'enable it, or apply via <code>vulnscan-ai fix</code>.</p>')
    parts.append('<p style="margin-top:1.2rem"><a href="/">&larr; back to dashboard</a></p>')
    return (f"<!doctype html><html><head><meta charset=utf-8>"
            f'<meta name=viewport content="width=device-width,initial-scale=1">'
            f"<title>vulnscan-ai dashboard — fix</title><style>{_STYLE}</style></head>"
            f'<body><header><div class="wrap">{logo_svg(22)} '
            f'<b>vulnscan&middot;ai</b> dashboard<span class=spacer></span>'
            f'<a href="/">Dashboard</a></div></header>'
            f'<div class="wrap">{"".join(parts)}</div></body></html>')


def render_dashboard(findings: List[Finding], host: str, scanned_at: str,
                     allow_entries: List[str], *, allow_fix: bool = False,
                     scan_running: bool = False, scan_message: str = "") -> str:
    counts: dict = {}
    for f in findings:
        counts[(f.severity or "unknown").lower()] = counts.get(
            (f.severity or "unknown").lower(), 0) + 1
    tiles = [f'<div class="tile"><div class="n">{len(findings)}</div>'
             f'<div class="l">total</div></div>']
    for sev in ("critical", "important", "moderate", "low"):
        if counts.get(sev):
            tiles.append(
                f'<div class="tile"><div class="n" style="color:{_SEV_COLOR[sev]}">'
                f'{counts[sev]}</div><div class="l">{sev}</div></div>')
    order = sorted(findings, key=lambda f: severity_rank(f.severity), reverse=True)
    body = "".join(_finding_html(f, allow_fix) for f in order) or \
        "<p>No findings saved yet. Run a scan to populate the dashboard.</p>"
    allow_rows = "".join(
        f'<code>{html.escape(e)}</code>'
        f'<form class="inline" method=post action="/deny">'
        f'<input type=hidden name=ip value="{html.escape(e)}">'
        f'<button title="remove">&times;</button></form> ' for e in allow_entries)
    # Auto-refresh while a scan runs so results appear without a manual reload.
    refresh = '<meta http-equiv="refresh" content="5">' if scan_running else ""
    scan_btn = ('<button class="scanbtn" disabled>Scanning…</button>'
                if scan_running else
                '<button class="scanbtn">Scan now</button>')
    flash = (f'<div class="flash">{html.escape(scan_message)}</div>'
             if scan_message and not scan_running else "")
    return f"""<!doctype html><html><head><meta charset=utf-8>{refresh}
<meta name=viewport content="width=device-width,initial-scale=1">
<title>vulnscan-ai dashboard — {html.escape(host)}</title><style>{_STYLE}</style></head>
<body>
<header><div class="wrap">{logo_svg(22)} <b>vulnscan&middot;ai</b> dashboard
  <span class=meta style="color:#9fb0c8">{html.escape(host)} &middot; {html.escape(scanned_at)} &middot; v{__version__}</span>
  <span class=spacer></span>
  <form class="inline" method=post action="/scan">{scan_btn}</form>
  &nbsp;<a href="/logout">Sign out</a></div></header>
<div class="wrap">
  {flash}
  <div class="tiles">{''.join(tiles)}</div>
  {body}
  <div class="allow">
    <b>Allowed network clients</b> (besides localhost): {allow_rows or '<i>none</i>'}
    <form class="inline" method=post action="/allow">
      <input type=text name=ip placeholder="10.0.0.5 or 10.0.0.0/24">
      <button>Add host</button>
    </form>
  </div>
</div></body></html>"""


# --------------------------------------------------------------------------- #
# HTTP server
# --------------------------------------------------------------------------- #
class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "vulnscan-ai-dashboard"

    def log_message(self, fmt, *args):  # quieter, to stderr
        return

    # -- helpers -------------------------------------------------------------
    def _cfg(self):
        return self.server.cfg  # type: ignore[attr-defined]

    def _denied_by_allowlist(self) -> bool:
        ip = self.client_address[0]
        if not client_allowed(ip, self.server.allow):  # type: ignore[attr-defined]
            self._text(HTTPStatusForbidden, "Forbidden: client not allowed")
            return True
        return False

    def _session_token(self) -> Optional[str]:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:  # noqa: BLE001
            return None
        c = jar.get("vsid")
        return c.value if c else None

    def _authed(self) -> bool:
        return self.server.sessions.valid(self._session_token())  # type: ignore[attr-defined]

    def _body_params(self) -> dict:
        length = int(self.headers.get("Content-Length", 0) or 0)
        data = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        return {k: v[0] for k, v in parse_qs(data).items()}

    def _html(self, status: int, body: str, cookie: Optional[str] = None):
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(raw)

    def _text(self, status: int, msg: str):
        raw = msg.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _redirect(self, location: str, cookie: Optional[str] = None):
        self.send_response(HTTPStatusSeeOther)
        self.send_header("Location", location)
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", "0")
        self.end_headers()

    # -- routes --------------------------------------------------------------
    def do_GET(self):
        if self._denied_by_allowlist():
            return
        path = self.path.split("?", 1)[0]
        if path == "/login":
            return self._html(200, render_login())
        if path == "/logout":
            self.server.sessions.drop(self._session_token())  # type: ignore[attr-defined]
            return self._redirect("/login", cookie="vsid=; Max-Age=0; Path=/")
        if not self._authed():
            return self._redirect("/login")
        if path == "/api/findings.json":
            return self._serve_findings_json()
        if path == "/":
            return self._serve_dashboard()
        return self._text(HTTPStatusNotFound, "Not found")

    def do_POST(self):
        if self._denied_by_allowlist():
            return
        path = self.path.split("?", 1)[0]
        if path == "/login":
            return self._do_login()
        if not self._authed():
            return self._redirect("/login")
        if path == "/allow":
            return self._do_allow(add=True)
        if path == "/deny":
            return self._do_allow(add=False)
        if path == "/scan":
            return self._do_scan()
        if path == "/fix":
            return self._do_fix()
        return self._text(HTTPStatusNotFound, "Not found")

    # -- handlers ------------------------------------------------------------
    def _do_login(self):
        p = self._body_params()
        cfg = self._cfg()
        user_ok = compare_digest(p.get("username", ""), cfg.dashboard_user or "admin")
        pass_ok = verify_password(p.get("password", ""),
                                  cfg.dashboard_password_hash or "")
        if user_ok and pass_ok:
            tok = self.server.sessions.create()  # type: ignore[attr-defined]
            cookie = f"vsid={tok}; HttpOnly; Secure; SameSite=Strict; Path=/"
            return self._redirect("/", cookie=cookie)
        time.sleep(1.0)  # slow down brute force
        return self._html(401, render_login("Invalid username or password."))

    def _load_findings(self):
        cfg = self._cfg()
        try:
            with open(cfg.findings_path, "r", encoding="utf-8") as fh:
                return findings_from_json(fh.read()), os.path.getmtime(cfg.findings_path)
        except (OSError, ValueError):
            return [], 0.0

    def _serve_dashboard(self):
        findings, mtime = self._load_findings()
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(mtime)) if mtime else "no scan yet"
        host = socket.gethostname()
        srv = self.server  # type: ignore[attr-defined]
        self._html(200, render_dashboard(
            findings, host, when, srv.allow,
            allow_fix=bool(getattr(srv.cfg, "dashboard_allow_fix", False)),
            scan_running=srv.scan_running, scan_message=srv.scan_message))

    def _serve_findings_json(self):
        findings, _ = self._load_findings()
        raw = json.dumps([f.to_dict() for f in findings], indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _do_allow(self, *, add: bool):
        ip = self._body_params().get("ip", "").strip()
        cfg = self._cfg()
        allow = list(self.server.allow)  # type: ignore[attr-defined]
        if add and valid_allow_entry(ip) and ip not in allow:
            allow.append(ip)
        elif not add and ip in allow:
            allow.remove(ip)
        self.server.allow = allow  # type: ignore[attr-defined]
        cfg.write_user_config({"dashboard_allow": allow})
        return self._redirect("/")

    # -- scan / fix actions --------------------------------------------------
    def _do_scan(self):
        srv = self.server  # type: ignore[attr-defined]
        with srv.scan_lock:
            if srv.scan_running:
                return self._redirect("/")     # already running; ignore
            srv.scan_running = True
            srv.scan_message = ""
        threading.Thread(target=_run_scan, args=(srv,), daemon=True).start()
        return self._redirect("/")

    def _do_fix(self):
        cfg = self._cfg()
        p = self._body_params()
        fid = p.get("id", "")
        mode = p.get("mode", "preview")
        allow_fix = bool(getattr(cfg, "dashboard_allow_fix", False))
        findings, _ = self._load_findings()
        target = next((f for f in findings if f.id == fid), None)
        if target is None:
            return self._html(HTTPStatusNotFound,
                              render_fix_result("Finding not found", "", None,
                                                allow_fix, error="No such finding."))

        from .ai import ProviderError, get_provider
        from . import remediation
        try:
            provider = get_provider(cfg.provider, cfg.model, timeout=cfg.timeout,
                                    effort=getattr(cfg, "claude_effort", None))
        except ProviderError as exc:
            return self._html(200, render_fix_result(
                target.title, fid, None, allow_fix, error=str(exc)))
        if not provider.available():
            return self._html(200, render_fix_result(
                target.title, fid, None, allow_fix,
                error=(f"AI provider '{cfg.provider}' is not configured "
                       f"(no API key). Set one with 'vulnscan-ai setup' or an "
                       f"environment variable.")))
        try:
            rem = remediation.propose(provider, target)
        except Exception as exc:  # noqa: BLE001
            return self._html(200, render_fix_result(
                target.title, fid, None, allow_fix,
                error=f"Could not propose a fix: {exc}"))
        target.remediation = rem

        applied = False
        if mode == "apply" and allow_fix:
            try:
                remediation.apply(target, dry_run=False, state_dir=cfg.state_dir)
                applied = True
            except Exception as exc:  # noqa: BLE001
                return self._html(200, render_fix_result(
                    target.title, fid, rem, allow_fix,
                    error=f"Apply failed: {exc}"))
            # Persist the remediation + results back into findings.json.
            for i, f in enumerate(findings):
                if f.id == target.id:
                    findings[i] = target
            from .cli import _save_findings
            _save_findings(cfg, findings)
        else:
            # Preview: screen the commands (dry-run) without executing anything.
            try:
                remediation.apply(target, dry_run=True, state_dir=cfg.state_dir)
            except Exception:  # noqa: BLE001
                pass
        return self._html(200, render_fix_result(
            target.title, fid, rem, allow_fix, applied=applied))


def _run_scan(srv) -> None:
    """Background full scan: runs the configured scanners and saves findings."""
    cfg = srv.cfg
    try:
        from .cli import _filter_severity, _save_findings, do_scan
        findings = do_scan(cfg, cfg.scanners, enrich=cfg.enrich)
        findings = _filter_severity(findings, cfg.min_severity)
        _save_findings(cfg, findings)
        srv.scan_message = f"Scan complete: {len(findings)} finding(s)."
    except Exception as exc:  # noqa: BLE001
        srv.scan_message = f"Scan failed: {exc}"
    finally:
        srv.scan_running = False


class DashboardServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, cfg, sessions, allow):
        super().__init__(addr, _Handler)
        self.cfg = cfg
        self.sessions = sessions
        self.allow = allow
        self.scan_running = False
        self.scan_message = ""
        self.scan_lock = threading.Lock()


def serve(cfg, *, port: Optional[int] = None,
          bind: Optional[str] = None) -> int:
    if not getattr(cfg, "dashboard_password_hash", None):
        raise DashboardError(
            "no dashboard password set — run: vulnscan-ai dashboard --set-password")
    cfg.ensure_state_dir()
    port = port or cfg.dashboard_port
    if port in BROWSER_BLOCKED_PORTS:
        print(f"WARNING: port {port} is blocked by most browsers "
              f"(ERR_UNSAFE_PORT). Use a safe port, e.g. --port 65101.")
    allow = [e for e in (cfg.dashboard_allow or []) if valid_allow_entry(e)]
    # Localhost-only unless explicit bind or an allow-list opens it to the network.
    if bind is None:
        bind = "0.0.0.0" if allow else cfg.dashboard_bind
    host = socket.gethostname()
    cert = cfg.dashboard_cert or os.path.join(cfg.state_dir, "dashboard-cert.pem")
    key = cfg.dashboard_key or os.path.join(cfg.state_dir, "dashboard-key.pem")
    ensure_cert(cert, key, host)

    httpd = DashboardServer((bind, port), cfg, _Sessions(), allow)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except (ValueError, AttributeError):
        pass
    ctx.load_cert_chain(cert, key)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    where = "localhost only" if (bind in ("127.0.0.1", "::1") and not allow) \
        else f"bind {bind}, allow {allow or 'loopback only'}"
    print(f"vulnscan-ai dashboard: https://{host}:{port}/  ({where})")
    print(f"Sign in as user '{cfg.dashboard_user}'  "
          f"(change the password with: vulnscan-ai dashboard --set-password)")
    if getattr(cfg, "dashboard_allow_fix", False):
        print("Apply-from-dashboard is ENABLED (dashboard_allow_fix=true): the "
              "Fix button can change this host.")
    else:
        print("Apply-from-dashboard is off (read-only + preview). Set "
              "dashboard_allow_fix=true in the config to enable the Apply button.")
    hint = firewall_hint(port, bind, allow)
    if hint:
        print("Hint: " + hint)
    print("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        httpd.server_close()
    return 0
