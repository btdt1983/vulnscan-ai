# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Deterministic, offline remediation catalog.

For package/advisory findings (the `dnf` and `oscap` scanners) this builds a
reproducible ``Remediation`` LOCALLY — no AI call, no network — so ``fix`` works
fully air-gapped and every package CVE gets the same canonical ``dnf`` plan on
every run. Config/service findings (ssh, systemd, ports, webroot, container)
genuinely need reasoning or a manual change and are left to the AI provider:
:func:`build` returns ``None`` for them so the caller falls back to the model.

The plans are intentionally conservative and mirror what a RHEL admin would run
by hand:

  * a finding with a well-formed advisory -> ``dnf update -y --advisory=<id>`` —
    Red Hat's own scoped patch, which updates only the packages that advisory
    fixes;
  * a finding with a valid package name + fixed version but no advisory ->
    ``dnf update -y <package>`` — a single-package update; ``dnf`` will not do an
    unrelated major bump of the rest of the system.

**Command construction is injection-safe.** The advisory is accepted only when
the WHOLE field is a well-formed id (``re.fullmatch`` — start-anchored alone
would let ``RHSA-2026:1 --nogpgcheck evilpkg`` through and inject extra ``dnf``
arguments), and the package name is validated against a strict RPM-name
allowlist. A field that fails validation is treated as absent, so no
metacharacter-bearing string is ever placed into a command — in-process (the
no-shell runner) or via ``export_fix`` (which writes into a real shell). Both
commands still pass through the deny-list / no-shell screen at apply time too.

The Remediation is stamped with a ``catalog``/``offline`` provider/model so the
approval prompt, the report and the audit log make clear the plan is
deterministic, not AI-generated.
"""

from __future__ import annotations

import re
from typing import Optional

from .models import Finding, Remediation
from .remediation import _ADVISORY_RE

# Scanners whose findings are package CVEs the catalog can plan deterministically.
# Everything else (ssh/systemd/ports/webroot/container) needs AI reasoning or a
# manual change.
_PACKAGE_SOURCES = {"dnf", "oscap"}

# Strict RPM package-name allowlist: a letter/digit, then name characters only.
# Rejects whitespace and every shell/argument metacharacter, so a crafted
# findings.json cannot inject extra dnf arguments through the package field.
_PKG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")

# Provider/model labels stamped on a catalog-built Remediation.
CATALOG_PROVIDER = "catalog"
CATALOG_MODEL = "offline"

# Summary sentinel for a finding the catalog cannot plan and for which no AI
# provider is available. Carries a human-readable reason in ``.explanation`` and
# has no commands, so the applier treats it as nothing-to-do and cmd_fix skips
# it (never a false "applied").
NO_PLAN = "(no offline plan available)"

# Package names whose update only takes full effect after a reboot. Used for a
# conservative ``requires_reboot`` heuristic. The effective-state engine would
# make this an observed fact (via ``needs-restarting -r``); until then, flag the
# well-known cases so the operator knows to reboot. Matched exactly or as a
# ``<name>-...`` sub-package (e.g. ``kernel-core``, ``glibc-common``).
_REBOOT_PACKAGES = (
    "kernel", "kernel-core", "kernel-rt", "glibc", "openssl", "openssl-libs",
    "systemd", "dbus", "glib2", "linux-firmware", "microcode_ctl", "grub2",
    "shim", "shim-x64",
)
# Keywords for the package-less case (oscap findings carry no package name). This
# is a best-effort heuristic on free text — a generic advisory title can miss it;
# the reboot note is informational and does not gate the fix.
_REBOOT_KEYWORDS = ("kernel", "glibc", "openssl", "systemd")


def _clean_advisory(finding: Finding) -> Optional[str]:
    """Return the finding's advisory only if the whole field is a well-formed id."""
    advisory = (finding.advisory or "").strip()
    if advisory and _ADVISORY_RE.fullmatch(advisory):
        return advisory
    return None


def _clean_package(finding: Finding) -> Optional[str]:
    """Return the finding's package name only if it is a valid RPM name."""
    pkg = (finding.package or "").strip()
    if pkg and _PKG_RE.match(pkg):
        return pkg
    return None


def _requires_reboot(finding: Finding) -> bool:
    """Conservative reboot heuristic for a package finding."""
    pkg = (finding.package or "").lower()
    if pkg:
        return any(pkg == p or pkg.startswith(p + "-") for p in _REBOOT_PACKAGES)
    # oscap findings carry no package; sniff the title/description text instead.
    hay = f"{finding.title} {finding.description}".lower()
    return any(k in hay for k in _REBOOT_KEYWORDS)


def build(finding: Finding) -> Optional[Remediation]:
    """Return a deterministic Remediation for a package/advisory finding, or
    ``None`` when the catalog cannot handle it (a non-package scanner, or a
    finding carrying neither a well-formed advisory nor a valid package + fixed
    version) — in which case the caller falls back to the AI provider."""
    if finding.source not in _PACKAGE_SOURCES:
        return None

    advisory = _clean_advisory(finding)
    package = _clean_package(finding)

    if advisory:
        cmd = f"dnf update -y --advisory={advisory}"
        summary = f"Apply {advisory} via dnf (offline catalog)"
        scope = (f"Runs the scoped errata update for {advisory}, which updates "
                 f"only the package(s) that advisory fixes")
    elif package and finding.fixed_version:
        cmd = f"dnf update -y {package}"
        summary = f"Update {package} via dnf (offline catalog)"
        scope = (f"Updates {package} to the fixed build ({finding.fixed_version}) "
                 f"available in the configured repositories")
    else:
        return None

    cves = ", ".join(finding.cve_ids) if finding.cve_ids else "the reported CVE(s)"
    explanation = (
        f"Deterministic offline remediation (no AI). {scope}, resolving {cves}. "
        f"Re-running produces the same plan; dnf reports 'Nothing to do' if the "
        f"host is already patched.")
    return Remediation(
        summary=summary,
        explanation=explanation,
        commands=[cmd],
        verification=None,
        requires_reboot=_requires_reboot(finding),
        risk="low",
        confidence=0.95,
        provider=CATALOG_PROVIDER,
        model=CATALOG_MODEL,
    )


def unsupported(finding: Finding, *, offline: bool,
                provider_available: bool) -> Remediation:
    """A no-op Remediation for a finding the catalog cannot plan and that has no
    AI provider to fall back to.

    It carries a clear reason and NO commands, so :func:`remediation.apply`
    treats it as nothing-to-do and ``cmd_fix`` skips it rather than reporting a
    false success. Only reached when the AI path is unavailable (offline, or no
    provider configured).
    """
    if finding.source in _PACKAGE_SOURCES:
        reason = ("This finding carries no advisory or fixed package version the "
                  "offline catalog can act on")
    else:
        reason = (f"This {finding.source} finding needs a config/service or manual "
                  f"change that the offline catalog cannot generate")
    if offline:
        reason += "; offline mode is set, so no AI plan was requested."
    else:  # provider not available (the only other way we reach here)
        reason += ("; no AI provider is configured. Run 'vulnscan-ai setup' to "
                   "configure one, or fix it manually.")
    return Remediation(
        summary=NO_PLAN,
        explanation=reason,
        risk="unknown",
        provider=CATALOG_PROVIDER,
        model=CATALOG_MODEL,
    )
