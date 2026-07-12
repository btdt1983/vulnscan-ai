# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""FIPS-mode detection and crypto/TLS helpers.

The tool never bundles its own cryptography. It relies entirely on the
system OpenSSL provided by the RHEL crypto policy, which is what is
FIPS 140 validated. This module:

  * detects whether the host kernel is in FIPS mode,
  * exposes a hashing helper that refuses non-approved digests,
  * builds a TLS context that requires TLS 1.2+ for every outbound call.
"""

from __future__ import annotations

import hashlib
import ssl
from functools import lru_cache
from typing import Optional

FIPS_FLAG = "/proc/sys/crypto/fips_enabled"

# The system-wide crypto policy (crypto-policies). ``state/current`` is the
# policy actually applied to OpenSSL/GnuTLS/OpenSSH/etc.; ``config`` is the one
# configured (they differ when a change has not been applied/rebooted yet).
CRYPTO_POLICY_CURRENT = "/etc/crypto-policies/state/current"
CRYPTO_POLICY_CONFIG = "/etc/crypto-policies/config"

# Digests permitted under FIPS 140-3 (SHA-2 / SHA-3 families).
_FIPS_APPROVED_HASHES = {
    "sha224", "sha256", "sha384", "sha512",
    "sha3_224", "sha3_256", "sha3_384", "sha3_512",
}


@lru_cache(maxsize=1)
def fips_enabled() -> bool:
    """Return True when the kernel reports FIPS mode is active."""
    try:
        with open(FIPS_FLAG, "r", encoding="ascii") as fh:
            return fh.read().strip() == "1"
    except OSError:
        return False


def approved_hash(name: str = "sha256"):
    """Return a hashlib constructor, rejecting non-approved digests in FIPS mode.

    Using this everywhere (instead of, say, md5) keeps the tool usable on a
    host where the FIPS crypto policy disables legacy digests.
    """
    name = name.lower()
    if fips_enabled() and name not in _FIPS_APPROVED_HASHES:
        raise ValueError(
            f"hash {name!r} is not FIPS-approved; use one of {sorted(_FIPS_APPROVED_HASHES)}"
        )
    return hashlib.new(name)


def tls_context() -> ssl.SSLContext:
    """A hardened default TLS context for all HTTPS requests.

    create_default_context() already honours the system crypto policy (so in
    FIPS mode only validated cipher suites are offered). We additionally pin
    the minimum protocol to TLS 1.2.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except (ValueError, AttributeError):  # pragma: no cover - very old python
        pass
    return ctx


def active_crypto_policy() -> Optional[str]:
    """The system-wide crypto policy currently applied, e.g. ``FIPS`` or
    ``DEFAULT:SHA1`` — or None when crypto-policies is not in use.

    Reads ``/etc/crypto-policies/state/current`` (the applied policy) directly,
    so no subprocess or ``crypto-policies-scripts`` package is required.
    """
    try:
        with open(CRYPTO_POLICY_CURRENT, encoding="ascii", errors="replace") as fh:
            value = fh.read().strip()
    except OSError:
        return None
    return value or None


def status_line() -> str:
    state = "ENABLED" if fips_enabled() else "disabled"
    policy = active_crypto_policy()
    policy_part = f" | crypto-policy: {policy}" if policy else ""
    return (f"FIPS mode: {state}{policy_part} "
            f"(crypto provided by system OpenSSL)")
