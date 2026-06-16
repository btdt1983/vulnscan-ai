"""SSH server hardening scanner.

Reports common sshd misconfigurations (root login, weak ciphers/MACs/KEX,
password auth, X11 forwarding, legacy protocol). These are config findings, not
package CVEs, so they carry no package/CVE/advisory — just enough context in
`raw` (directive, current value, recommended value) for the AI to propose a
transactional fix that backs up sshd_config, validates with `sshd -t`, and
reloads sshd with automatic rollback.
"""

from __future__ import annotations

import os
from typing import Dict, List

from ..models import Finding
from .base import Scanner, have, run

SSHD_CONFIG = "/etc/ssh/sshd_config"

# Strong defaults to recommend (modern OpenSSH, FIPS-friendly).
_REC_CIPHERS = ("chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,"
                "aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr")
_REC_MACS = ("hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,"
             "umac-128-etm@openssh.com")
_REC_KEX = ("curve25519-sha256,curve25519-sha256@libssh.org,"
            "ecdh-sha2-nistp256,diffie-hellman-group16-sha512,"
            "diffie-hellman-group18-sha512")

# Substrings that mark an algorithm as weak/deprecated.
_WEAK_CIPHER = ("-cbc", "3des", "arcfour", "blowfish", "cast128", "rc4")
_WEAK_MAC = ("hmac-sha1", "hmac-md5", "umac-64", "-96")
_WEAK_KEX = ("group1-sha1", "group14-sha1", "group-exchange-sha1", "gss-")


def parse_sshd_config(text: str) -> Dict[str, str]:
    """Parse `sshd -T` output or an sshd_config file into {lowercased key: value}.

    Mirrors sshd semantics: the FIRST occurrence of a keyword wins. `sshd -T`
    already emits one resolved line per keyword, so this also handles that.
    """
    cfg: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        key = parts[0].lower()
        if key not in cfg:           # first occurrence wins
            cfg[key] = parts[1].strip()
    return cfg


def _weak_items(value: str, markers) -> List[str]:
    items = [v.strip() for v in value.replace(" ", ",").split(",") if v.strip()]
    return [it for it in items if any(m in it.lower() for m in markers)]


def audit_sshd_config(cfg: Dict[str, str],
                      config_file: str = SSHD_CONFIG) -> List[Finding]:
    """Apply the hardening ruleset to a parsed config, returning findings."""
    out: List[Finding] = []

    def add(title, severity, desc, directive, current, recommended):
        out.append(Finding(
            source="ssh", title=title, severity=severity, description=desc,
            raw={"config_file": config_file, "directive": directive,
                 "current": current, "recommended": recommended},
        ))

    prl = cfg.get("permitrootlogin")
    if prl and prl.lower() == "yes":
        add("SSH permits direct root login", "important",
            "PermitRootLogin is 'yes', allowing direct remote root logins. "
            "Restrict to key-only ('prohibit-password') or disable ('no').",
            "PermitRootLogin", prl, "prohibit-password")

    if cfg.get("protocol", "").strip() == "1":
        add("SSH legacy protocol 1 enabled", "important",
            "SSH protocol 1 is cryptographically broken and must not be used.",
            "Protocol", cfg.get("protocol", ""), "2")

    for key, label, markers, rec in (
        ("ciphers", "ciphers", _WEAK_CIPHER, _REC_CIPHERS),
        ("macs", "MACs", _WEAK_MAC, _REC_MACS),
        ("kexalgorithms", "key-exchange algorithms", _WEAK_KEX, _REC_KEX),
    ):
        val = cfg.get(key)
        if not val:
            continue
        weak = _weak_items(val, markers)
        if weak:
            add(f"SSH offers weak {label}", "moderate",
                f"sshd is configured with weak {label}: {', '.join(weak)}. "
                f"Restrict to strong algorithms only.",
                key.capitalize() if key != "macs" else "MACs",
                val, rec)

    if cfg.get("passwordauthentication", "").lower() == "yes":
        add("SSH password authentication enabled", "low",
            "Password authentication is enabled; key-based auth is stronger and "
            "resists brute force. Disable only after keys are deployed.",
            "PasswordAuthentication", cfg["passwordauthentication"], "no")

    if cfg.get("x11forwarding", "").lower() == "yes":
        add("SSH X11 forwarding enabled", "low",
            "X11Forwarding broadens the attack surface; disable if not needed.",
            "X11Forwarding", cfg["x11forwarding"], "no")

    return out


class SshConfigScanner(Scanner):
    name = "ssh"

    def available(self) -> bool:
        return os.path.isfile(SSHD_CONFIG)

    def scan(self) -> List[Finding]:
        text = ""
        # Prefer the effective config (`sshd -T`) which resolves Match/defaults.
        if have("sshd"):
            try:
                rc, out, _ = run(["sshd", "-T"], timeout=30)
                if rc == 0 and out.strip():
                    text = out
            except Exception:  # noqa: BLE001 - fall back to the file
                text = ""
        if not text:
            try:
                with open(SSHD_CONFIG, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                return []
        return audit_sshd_config(parse_sshd_config(text))
