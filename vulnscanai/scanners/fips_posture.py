# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""FIPS-posture scanner: is the host's cryptography actually hardened?

The tool calls itself FIPS-aware, yet a host can *look* FIPS-enabled while being
silently half-configured — the classic trap where the kernel is in FIPS mode but
userspace still follows a permissive crypto-policy (so OpenSSL/GnuTLS/OpenSSH keep
negotiating non-approved algorithms), or the reverse. This scanner audits the
real crypto posture from ground-truth signals and reports only genuine gaps:

  * **Inconsistencies** — kernel FIPS on but the crypto-policy is not FIPS (or the
    reverse), or ``fips-mode-setup --check`` reports an inconsistent state. These
    are objectively broken regardless of whether the host *wants* FIPS.
  * **Weakened crypto-policy** — the system-wide policy is ``LEGACY`` (re-enables
    SHA-1 signatures, 3DES/CBC, TLS 1.0/1.1, small DH groups) or carries a
    SHA-1-restoring sub-policy. Valuable on ANY host, FIPS or not.
  * **Pending policy change** — the configured crypto-policy differs from the
    applied one (a change on disk that is not yet active — the crypto analogue of
    the effective-state scanner's "a patch on disk is not a patch in RAM").
  * **FIPS required but not enabled** — only when the operator has declared this a
    FIPS host via ``fips_required=true``; otherwise a consistent non-FIPS host is
    a legitimate configuration and produces NO findings (no false positives).

Pure stdlib: reads ``/proc/sys/crypto/fips_enabled``, ``/proc/cmdline`` and the
crypto-policies state files; ``fips-mode-setup --check`` is used only as an extra
inconsistency signal when the tool is present. The rule engine (``audit_fips``)
is a pure function over gathered signals, so it is fully unit-testable without any
FIPS tooling.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List, Optional

from ..fips import (
    CRYPTO_POLICY_CONFIG,
    FIPS_FLAG,
    active_crypto_policy,
)
from ..models import Finding
from .base import Scanner, have, run

CMDLINE = "/proc/cmdline"


@dataclass
class FipsState:
    """Ground-truth crypto-posture signals gathered from the host."""

    kernel_fips: Optional[bool] = None     # /proc/sys/crypto/fips_enabled == 1
    mode_check: Optional[str] = None       # enabled|disabled|inconsistent|None
    policy: Optional[str] = None           # applied policy, e.g. "FIPS:OSPP"
    configured_policy: Optional[str] = None  # /etc/crypto-policies/config
    cmdline_fips: Optional[bool] = None    # fips=1 present in /proc/cmdline
    required: bool = False                 # config: this host must be FIPS


# --------------------------------------------------------------------------- #
# pure parsers (unit-testable without any FIPS tooling)
# --------------------------------------------------------------------------- #
def parse_fips_mode_check(text: str) -> Optional[str]:
    """Interpret ``fips-mode-setup --check`` output.

    The command exits 0 whether FIPS is on or off, so the verdict lives in the
    text. Returns "inconsistent" | "enabled" | "disabled" | None.
    """
    low = text.lower()
    if "inconsist" in low:
        return "inconsistent"
    if "fips mode is enabled" in low:
        return "enabled"
    if "fips mode is disabled" in low:
        return "disabled"
    return None


def parse_cmdline_fips(text: str) -> bool:
    """True when the kernel command line requests FIPS mode (``fips=1``)."""
    return "fips=1" in text.split()


def _policy_parts(policy: Optional[str]):
    """(base, [subpolicies]) uppercased, e.g. 'FIPS:OSPP' -> ('FIPS', ['OSPP'])."""
    if not policy:
        return "", []
    parts = [p for p in policy.strip().split(":") if p]
    if not parts:
        return "", []
    return parts[0].upper(), [p.upper() for p in parts[1:]]


# --------------------------------------------------------------------------- #
# rule engine (pure)
# --------------------------------------------------------------------------- #
def audit_fips(state: FipsState) -> List[Finding]:
    """Apply the crypto-posture ruleset to gathered signals, returning findings.

    A consistent host — either fully FIPS or plainly non-FIPS with a sound
    crypto-policy — and ``required=False`` yields an empty list.
    """
    out: List[Finding] = []
    base, subs = _policy_parts(state.policy)
    policy_is_fips = base == "FIPS"
    kernel = state.kernel_fips
    shown_policy = state.policy or "DEFAULT"

    def add(title, severity, desc, category, **extra):
        raw = {"category": category}
        raw.update(extra)
        out.append(Finding(source="fips", title=title, severity=severity,
                           description=desc, raw=raw))

    # 1) fips-mode-setup itself reports the configuration is inconsistent.
    if state.mode_check == "inconsistent":
        add("FIPS configuration is inconsistent",
            "important",
            "fips-mode-setup --check reports the FIPS configuration is "
            "inconsistent: some components are in FIPS mode and others are not. "
            "Reconcile the host by re-running `fips-mode-setup --enable` (then "
            "reboot) or `fips-mode-setup --disable`.",
            "mode-inconsistent")

    # 2/3) kernel FIPS and userspace crypto-policy disagree — a half-enabled
    # state where applications may still negotiate non-approved algorithms.
    if kernel is True and state.policy and not policy_is_fips:
        add(f"Kernel is in FIPS mode but the crypto-policy is {shown_policy}",
            "important",
            f"The kernel runs in FIPS mode, yet the system-wide crypto-policy is "
            f"{shown_policy}, so userspace crypto (OpenSSL, GnuTLS, OpenSSH, ...) "
            f"is NOT restricted to FIPS-approved algorithms and may still "
            f"negotiate non-approved ones. Align them with "
            f"`update-crypto-policies --set FIPS` (or `fips-mode-setup --enable`).",
            "kernel-on-policy-off", policy=shown_policy)
    elif policy_is_fips and kernel is False:
        add("Crypto-policy is FIPS but the kernel is not in FIPS mode",
            "important",
            "The system-wide crypto-policy is FIPS but the kernel is not running "
            "in FIPS mode, so kernel-level enforcement (module self-tests, the "
            "/proc/sys/crypto/fips_enabled flag) is absent. Enable FIPS fully with "
            "`fips-mode-setup --enable` and reboot.",
            "policy-on-kernel-off")

    # 4) Declared a FIPS host but plainly not enabled (no inconsistency above).
    if state.required and not kernel and not policy_is_fips \
            and state.mode_check != "inconsistent":
        add("FIPS mode is required but is not enabled on this host",
            "important",
            f"This host is configured to require FIPS 140 (fips_required=true) but "
            f"the kernel is not in FIPS mode and the crypto-policy is "
            f"{shown_policy}. Enable it with `fips-mode-setup --enable` and reboot.",
            "required-off", policy=shown_policy)

    # 5) LEGACY re-enables broken primitives system-wide — flag on any host.
    if base == "LEGACY":
        add("System-wide crypto-policy is LEGACY (weak algorithms enabled)",
            "important",
            "The LEGACY crypto-policy re-enables cryptographically weak primitives "
            "system-wide — SHA-1 signatures, 3DES/CBC ciphers, TLS 1.0/1.1 and "
            "small DH groups — for OpenSSL, GnuTLS and OpenSSH. Move to DEFAULT "
            "(or FIPS) unless a legacy peer strictly requires it: "
            "`update-crypto-policies --set DEFAULT`.",
            "policy-legacy", policy=shown_policy)

    # 6) A SHA-1-restoring sub-policy (e.g. DEFAULT:SHA1) on a non-LEGACY base.
    if "SHA1" in subs and base != "LEGACY":
        add(f"Crypto-policy re-enables SHA-1 ({shown_policy})",
            "moderate",
            f"The crypto-policy {shown_policy} carries the SHA1 sub-policy, which "
            f"restores SHA-1 in signatures — a collision-broken primitive. Remove "
            f"it unless a specific legacy peer requires it.",
            "policy-sha1", policy=shown_policy)

    # 7) Kernel reports FIPS but fips=1 is missing from the boot command line —
    # the state was likely not set through the supported path and may not persist.
    if kernel is True and state.cmdline_fips is False:
        add("FIPS mode is active but 'fips=1' is absent from the kernel command line",
            "moderate",
            "The kernel reports FIPS mode, yet /proc/cmdline contains no fips=1, so "
            "the state may not have been set via the supported mechanism "
            "(fips-mode-setup) and might not survive a reboot. Re-run "
            "`fips-mode-setup --enable` and verify the boot loader configuration.",
            "cmdline-missing")

    # 8) The configured crypto-policy differs from the applied one — a change on
    # disk that is not yet active (crypto analogue of "patched on disk, not live").
    if state.configured_policy and state.policy \
            and state.configured_policy.strip().upper() != state.policy.strip().upper():
        add(f"Crypto-policy change pending: configured {state.configured_policy}, "
            f"active {state.policy}",
            "moderate",
            f"/etc/crypto-policies/config selects {state.configured_policy} but the "
            f"applied policy is {state.policy}. Run `update-crypto-policies` (or "
            f"reboot) to activate the configured policy so the two do not drift.",
            "policy-pending", configured=state.configured_policy,
            active=state.policy)

    return out


# --------------------------------------------------------------------------- #
# host signal gathering (thin, impure)
# --------------------------------------------------------------------------- #
def _read_kernel_fips() -> Optional[bool]:
    """True/False from /proc/sys/crypto/fips_enabled, or None when unreadable."""
    try:
        with open(FIPS_FLAG, encoding="ascii") as fh:
            return fh.read().strip() == "1"
    except OSError:
        return None


def _read_cmdline_fips() -> Optional[bool]:
    try:
        with open(CMDLINE, encoding="ascii", errors="replace") as fh:
            return parse_cmdline_fips(fh.read())
    except OSError:
        return None


def _read_configured_policy() -> Optional[str]:
    try:
        with open(CRYPTO_POLICY_CONFIG, encoding="ascii", errors="replace") as fh:
            value = fh.read().strip()
    except OSError:
        return None
    return value or None


def _read_mode_check() -> Optional[str]:
    if not have("fips-mode-setup"):
        return None
    try:
        _rc, out, err = run(["fips-mode-setup", "--check"], timeout=30)
    except Exception:  # noqa: BLE001 - degrade to "no verdict"
        return None
    return parse_fips_mode_check(out + "\n" + err)


def gather_state(required: bool) -> FipsState:
    """Collect all crypto-posture signals from the host."""
    return FipsState(
        kernel_fips=_read_kernel_fips(),
        mode_check=_read_mode_check(),
        policy=active_crypto_policy(),
        configured_policy=_read_configured_policy(),
        cmdline_fips=_read_cmdline_fips(),
        required=required,
    )


class FipsPostureScanner(Scanner):
    """Audits the host's FIPS / crypto-policy posture for real gaps."""

    name = "fips"

    def available(self) -> bool:
        # Linux with the kernel crypto flag or the crypto-policies framework.
        return os.path.exists(FIPS_FLAG) or os.path.isdir("/etc/crypto-policies")

    def scan(self) -> List[Finding]:
        required = bool(getattr(self.config, "fips_required", False))
        return audit_fips(gather_state(required))
