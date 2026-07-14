# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""AI-driven remediation: propose fixes, gate on approval, then apply.

Design choices (per the tool's safety posture):
  * The model only *proposes* shell commands; it never executes anything.
  * Proposed commands are screened against a deny-list before they can run.
  * Nothing runs without explicit per-finding approval unless --yes is given.
  * --dry-run produces the full plan and report but executes nothing.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import time
from typing import Callable, Dict, List, Optional

from .ai import AIProvider, ProviderError, extract_json
from .models import Finding, Remediation

SYSTEM_PROMPT = """You are a senior RHEL security engineer producing remediation \
plans for vulnerability findings on Red Hat Enterprise Linux based systems \
(RHEL, AlmaLinux, Rocky, CentOS Stream).

Rules:
- Prefer the package manager (dnf/yum) for patching. Be specific: pin the exact \
package when sensible (e.g. `dnf update -y --advisory=RHSA-2024:1234`).
- Only propose commands that are safe, idempotent and standard. Never propose \
destructive commands (rm -rf, mkfs, dd to a device, disabling SELinux/firewall, \
piping curl into a shell, force-removing packages).
- Respect FIPS: do not weaken crypto policy; if a fix touches crypto, note it.
- If a reboot is required (e.g. kernel/glibc/openssl), set requires_reboot true.
- Keep the plan minimal and scoped to the finding.
- When the fix edits a configuration file, set "backup_paths" to the exact \
file(s) you change so they can be snapshotted and rolled back. Provide a \
"validate_cmd" that checks the new config WITHOUT restarting (e.g. `sshd -t`, \
`nginx -t`, `visudo -cf <file>`), and set "service" + "restart_mode" to apply it. \
PREFER "reload" over "restart" to avoid dropping live connections. For sshd \
always use validate_cmd `sshd -t`, service `sshd`, restart_mode `reload`.
- To CREATE or fully REPLACE a file (a drop-in or a new config file), put it in \
"write_files" as {"path": "<file>", "content": "<full file content>"} — the tool \
writes it safely and snapshots it for rollback. NEVER write a file with a shell \
redirect (`>`), a pipe or a here-doc: commands run WITHOUT a shell, so such a \
command does nothing. Editing a few lines of an EXISTING file is fine with a \
command like `sed -i` (no redirection).
- For a systemd service hardening finding, create a drop-in at \
`/etc/systemd/system/<unit>.d/10-hardening.conf` (the path is given as `dropin`) \
by putting it in "write_files" as {"path": "<dropin>", "content": \
"[Service]\\n<directives>"}. Set "backup_paths" to that same path, make \
`systemctl daemon-reload` the command (it picks up the new drop-in), set \
"validate_cmd" to `systemd-analyze verify <unit>`, "service" to the unit, \
"restart_mode" to `restart`, and add `systemctl daemon-reload` to \
"rollback_commands". Apply only conservative directives that will not break the \
service.
- For an exposed-port finding, prefer the least-disruptive fix: bind the service \
to localhost in its own config (transactional: backup the config, validate, \
reload), otherwise restrict the port with the firewall (`firewall-cmd`), \
otherwise stop+disable the service if it is unused. Never block the SSH port you \
are connected through.
- The user message may include a "Reference (optional, from the host's SCAP \
Security Guide hardening benchmark...)" block: a peer-reviewed script for a \
LEXICALLY SIMILAR rule, not necessarily an exact match for this finding. Use it \
only as inspiration for what a correct fix looks like, and TRANSLATE it into \
this schema — a full-file rewrite becomes "write_files", a one-line edit \
becomes a non-shell "commands" entry (e.g. `sed -i`). Never copy the \
reference's shell syntax (heredocs, `>`, `||`, `&&`) into "commands" verbatim; \
it will be rejected by the no-shell runner. If the reference does not actually \
match this finding, ignore it and reason from the finding's own details instead.

Respond with ONLY a JSON object, no prose. Replace every <...> placeholder with
a real value (or null where it says "or null"); never echo a placeholder back.
Schema:
{
  "summary": "<one-line summary>",
  "explanation": "<why this fixes it and any caveats>",
  "commands": ["<shell command>"],
  "config_changes": ["<human-readable non-command step>"],
  "verification": "<command that confirms the fix, or null>",
  "requires_reboot": false,
  "risk": "low",
  "confidence": 0.0,
  "backup_paths": ["<exact file you edit>"],
  "write_files": [{"path": "<file to create/replace>", "content": "<full content>"}],
  "validate_cmd": "<non-destructive config check e.g. sshd -t, or null>",
  "service": "<systemd unit to reload, or null>",
  "restart_mode": "none",
  "rollback_commands": ["<optional non-file rollback, e.g. dnf history undo last>"]
}"""

# restart_mode must be exactly one of these; anything else (incl. a model that
# echoes the "reload|restart|none" menu) is normalised to "none".
_VALID_RESTART = {"reload", "restart", "none"}

# Finding sources whose fix legitimately edits a config file or manages a
# service, and may therefore carry transactional metadata (backup_paths /
# validate_cmd / service / restart_mode). Package-CVE sources (dnf, oscap) must
# NOT: their fix is a `dnf update`, so any backup/validate/service the model
# attaches — e.g. backing up sshd_config and "validating" by restarting sshd to
# update a Python library — is a hallucination and is stripped.
_CONFIG_SOURCES = {"ssh", "systemd", "ports", "webroot"}

# Recognised advisory id shapes (Red Hat / AlmaLinux / Oracle / Rocky families).
_ADVISORY_RE = re.compile(
    r"^(?:RH[SBE]A|AL[SBE]A|ELSA|RLSA|CESA)-?\d{4}[:\-]\d+", re.I)
# Same shape, unanchored, for pulling ids out of a command string.
_ADVISORY_TOKEN_RE = re.compile(
    r"(?:RH[SBE]A|AL[SBE]A|ELSA|RLSA|CESA)-?\d{4}[:\-]\d+", re.I)

# "dnf/yum update" prints this when the targeted advisory/package changes
# nothing — exit code is still 0, which would otherwise read as a real success.
_NOTHING_DONE_RE = re.compile(r"\bnothing to do\b", re.I)

# Literal placeholder strings from older/example schemas that a weak model may
# echo verbatim. Matched case-insensitively after stripping; always discarded.
_PLACEHOLDER_TEXTS = {
    "one line", "why this fixes it and any caveats",
    "command to confirm the fix", "shell command",
    "human-readable non-command step", "reload|restart|none",
    "optional non-file rollback, e.g. dnf history undo last",
}

# Commands we refuse to run regardless of what the model proposes.
_DENY_PATTERNS = [
    r"\brm\s+-rf?\b.*\s/(?:\s|$)",      # rm -rf /
    r"\bmkfs\b",
    r"\bdd\b.*\bof=/dev/",
    r"\b(curl|wget)\b.*\|\s*(sudo\s+)?(ba)?sh",
    r"setenforce\s+0",
    r"--nodeps",
    r"\bdnf\b.*\bremove\b",
    r"\byum\b.*\bremove\b",
    r"update-crypto-policies\s+--set\s+LEGACY",
    r":\(\)\s*\{",                       # fork bomb
    r"\bchmod\s+-R\s+777\b",
    # A fix must never take the host down itself. The effective-state scanner
    # flags when a reboot is needed; rebooting is the operator's call, on their
    # schedule — not something `fix --yes` should do mid-run. Anchored to the
    # command verb so a service *named* e.g. "reboot-guard" isn't caught.
    r"^\s*(sudo\s+)?(reboot|poweroff|halt|shutdown|kexec)\b",
    r"^\s*(sudo\s+)?init\s+[06]\b",
    r"\bsystemctl\s+(reboot|poweroff|halt|kexec|emergency|rescue)\b",
]
_DENY_RE = [re.compile(p) for p in _DENY_PATTERNS]


# Shell operators that change what a command does but are meaningless to our
# no-shell runner (subprocess without shell=True). A model that emits e.g.
# `echo "[Service]..." > /etc/systemd/system/x.d/10.conf` would, under
# shlex.split, run `echo` with `>` as a literal argument: nothing is written,
# exit 0 — a silent no-op that would otherwise be reported as a successful fix.
# We refuse such commands so the failure is honest (export them with
# `fix --export-script`/`--export-ansible` to run them in a real shell instead).
_SHELL_OP_TOKENS = {">", ">>", ">|", "<", "<<", "<<<", "|", "|&", "||", "&&", "&"}


def _needs_shell(cmd: str) -> bool:
    """True if the command relies on shell features our runner does not provide
    (redirection, pipes, command substitution, chaining)."""
    if "`" in cmd or "$(" in cmd or "${" in cmd:
        return True
    try:
        toks = shlex.split(cmd)
    except ValueError:
        return True                      # unbalanced quotes: can't run safely
    return any(t in _SHELL_OP_TOKENS for t in toks)


def screen_command(cmd: str) -> Optional[str]:
    """Return a reason string if the command is disallowed, else None."""
    for rx in _DENY_RE:
        if rx.search(cmd):
            return f"blocked by safety policy (matched /{rx.pattern}/)"
    if _needs_shell(cmd):
        return ("blocked: uses a shell redirect/pipe/substitution, which the "
                "no-shell runner cannot execute as written — export it with "
                "'fix --export-script' to run it in a real shell")
    return None


# Locations a remediation must never write a file to. Config fixes legitimately
# write drop-ins / service config under /etc; the auth databases and the pseudo
# filesystems are out of scope and dangerous to overwrite.
_WRITE_DENY_EXACT = {"/etc/shadow", "/etc/gshadow", "/etc/passwd", "/etc/group",
                     "/etc/sudoers", "/etc/fstab"}
_WRITE_DENY_PREFIXES = ("/dev/", "/proc/", "/sys/", "/boot/")


def _screen_write_path(path: str) -> Optional[str]:
    """Return a reason if a fix must not write this path, else None."""
    if not path or not os.path.isabs(path):
        return "refused: write path is not absolute"
    norm = os.path.normpath(path)
    if norm in _WRITE_DENY_EXACT:
        return f"refused: writing {norm} is not allowed"
    if norm.startswith(_WRITE_DENY_PREFIXES) or norm in ("/dev", "/proc", "/sys", "/boot"):
        return f"refused: writing under a system/pseudo path is not allowed ({norm})"
    if os.path.isdir(norm):
        return f"refused: {norm} is a directory"
    return None


def _parse_write_files(val: object) -> List[Dict[str, str]]:
    """Coerce the model's `write_files` into [{path, content, mode?}].

    Drops entries without a real absolute path or with placeholder content, so a
    weak model that echoes the schema can't turn into a bogus file write.
    """
    out: List[Dict[str, str]] = []
    for item in _as_list(val):
        if not isinstance(item, dict):
            continue
        path = _scrub(item.get("path"))
        if not path or not os.path.isabs(path):
            continue
        content = item.get("content")
        if content is None:                       # "" is a valid empty file
            continue
        content = str(content)
        stripped = content.strip()
        if stripped.startswith("<") and stripped.endswith(">"):
            continue                              # echoed <placeholder>
        entry: Dict[str, str] = {"path": path, "content": content}
        mode = item.get("mode")
        if isinstance(mode, str) and re.fullmatch(r"0?[0-7]{3,4}", mode.strip()):
            entry["mode"] = mode.strip()
        out.append(entry)
    return out


def _write_file(path: str, content: str, mode: int = 0o644) -> Dict[str, object]:
    """Write one file (no shell), creating parent dirs. Returns a result dict."""
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.chmod(path, mode)
        return {"command": f"write {path} ({len(content)} bytes)",
                "status": "ok", "detail": f"mode {oct(mode)}"}
    except OSError as exc:
        return {"command": f"write {path}", "status": "error", "detail": str(exc)}


def _finding_brief(f: Finding) -> str:
    lines = [
        f"Source scanner: {f.source}",
        f"Title: {f.title}",
        f"Severity: {f.severity}",
        f"CVEs: {', '.join(f.cve_ids) or 'n/a'}",
        f"Advisory: {f.advisory or 'n/a'}",
        f"Package: {f.package or 'n/a'}",
        f"Installed version: {f.installed_version or 'n/a'}",
        f"Fixed version: {f.fixed_version or 'n/a'}",
        f"CVSS: {f.cvss_score if f.cvss_score is not None else 'n/a'}",
        "",
        "Description:",
        (f.description or "n/a")[:2000],
    ]
    # Surface scanner hints (e.g. systemd drop-in path, recommended directives)
    # so the model can produce a precise transactional plan.
    for key in ("dropin", "recommended", "config_file", "directive",
                "current", "service", "address", "port", "category"):
        val = f.raw.get(key) if isinstance(f.raw, dict) else None
        if val:
            lines.append(f"{key}: {val}")
    return "\n".join(lines)


def _as_list(val: object) -> List[object]:
    """Coerce a model field to a list. `dict.get(k, [])` returns None when the
    key is present but null (`"config_changes": null`), so guard every list
    field through here: list stays as-is, None/empty -> [], a scalar -> [scalar].
    """
    if isinstance(val, list):
        return val
    if val is None or val == "":
        return []
    return [val]


def _scrub(val: object) -> Optional[str]:
    """Drop a model echo of a schema placeholder.

    Placeholders are written as <...>; a weak/small model sometimes copies them
    verbatim (e.g. returns the literal "command to confirm the fix"). Returns a
    clean non-empty string, or None when the value is empty or an echoed
    placeholder.
    """
    if val is None:
        return None
    s = str(val).strip()
    if not s:
        return None
    if s.startswith("<") and s.endswith(">"):
        return None
    if s.lower() in _PLACEHOLDER_TEXTS:
        return None
    return s


def _real_command(cmd: Optional[str]) -> Optional[str]:
    """Return cmd only if its first token resolves to a real executable.

    Guards validate_cmd / verification: prose like "validate nginx version" or a
    leftover placeholder must never be executed as if it were a command.
    """
    cmd = _scrub(cmd)
    if cmd is None:
        return None
    try:
        toks = shlex.split(cmd)
    except ValueError:
        return None
    if not toks:
        return None
    # Search the sbin dirs too: validate binaries (sshd, nginx, visudo) live in
    # /usr/sbin, which isn't always on PATH. Over-dropping a real validate_cmd
    # would mean restarting a service unvalidated, so resolve generously.
    search = (os.environ.get("PATH", "") + ":/usr/sbin:/sbin:/usr/local/sbin")
    if shutil.which(toks[0], path=search) is None:
        return None
    return cmd


def _rewrite_advisory(commands: List[str], advisory: Optional[str]) -> List[str]:
    """Normalise the `--advisory=` argument of any dnf/yum command.

    Two failure modes from weak models are fixed:
    * an invented/malformed id (e.g. `ALSAA2026:28973`) — replaced with the
      finding's own well-formed advisory when it has one;
    * several ids emitted space-separated (`--advisory=RHSA-1, RHSA-2`), which
      `dnf` rejects ("No match for argument: RHSA-2") — collapsed into one
      comma-joined argument so the command at least parses.
    Garbage tokens that don't look like an advisory id are dropped.
    """
    adv = (advisory or "").strip()
    finding_adv = adv if _ADVISORY_RE.match(adv) else None
    out: List[str] = []
    for c in commands:
        if "--advisory" not in c:
            out.append(c)
            continue
        try:
            toks = shlex.split(c)
        except ValueError:
            out.append(c)
            continue
        ids = ([finding_adv] if finding_adv
               else list(dict.fromkeys(_ADVISORY_TOKEN_RE.findall(c))))
        if not ids:
            out.append(c)
            continue
        new_toks: List[str] = []
        i = 0
        while i < len(toks):
            if toks[i].split("=", 1)[0] == "--advisory":
                new_toks.append("--advisory=" + ",".join(ids))
                i += 1
                # Absorb the model's extra id / bare-comma tokens that followed.
                while i < len(toks):
                    nxt = toks[i].strip(",")
                    if nxt == "" or _ADVISORY_TOKEN_RE.search(toks[i]):
                        i += 1
                    else:
                        break
                continue
            new_toks.append(toks[i])
            i += 1
        out.append(" ".join(shlex.quote(t) for t in new_toks))
    return out


def _grounding_text(f: Finding) -> str:
    """Compact text for lexical matching against SCAP Security Guide rules:
    title + description + the same scanner-hint keys _finding_brief surfaces.

    Deliberately NOT the full _finding_brief() output — its constant field-label
    boilerplate ("Source scanner:", "CVEs: n/a", "Advisory: n/a", ...) is
    identical across every finding and would dilute the bag-of-words vector for
    every query alike without adding any discriminating signal.
    """
    parts = [f.title, f.description or ""]
    for key in ("directive", "recommended", "current", "category", "reason",
               "service", "process"):
        val = f.raw.get(key) if isinstance(f.raw, dict) else None
        if val:
            parts.append(str(val))
    return "\n".join(parts)


def propose(provider: AIProvider, finding: Finding, *,
           ground: bool = True, datastream: Optional[str] = None) -> Remediation:
    """Ask the model for a remediation plan for one finding, then sanitise it.

    For config/service findings (``_CONFIG_SOURCES``), ``ground`` optionally
    appends a vetted SCAP Security Guide reference snippet to the prompt (see
    ``scap_kb.ground``) to reduce hallucination. Package/CVE findings never get
    one — SSG rules are hardening guidance, not CVE patches, and those findings
    are catalog-first (no AI call) in the common path anyway.
    """
    brief = _finding_brief(finding)
    if ground and finding.source in _CONFIG_SOURCES:
        from . import scap_kb  # local import, mirrors the catalog import below
        block = scap_kb.ground(_grounding_text(finding), datastream=datastream)
        if block:
            brief = brief + "\n\n" + block
    text = provider.complete(SYSTEM_PROMPT, brief)
    data = extract_json(text)

    commands = [str(c) for c in _as_list(data.get("commands")) if str(c).strip()]
    commands = _rewrite_advisory(commands, finding.advisory)

    restart_mode = str(data.get("restart_mode", "none") or "none").lower().strip()
    if restart_mode not in _VALID_RESTART:
        restart_mode = "none"

    backup_paths = [str(p) for p in _as_list(data.get("backup_paths")) if str(p).strip()]
    service = _scrub(data.get("service"))
    validate_cmd = _real_command(data.get("validate_cmd"))
    write_files = _parse_write_files(data.get("write_files"))

    # Transactional scaffolding only makes sense for config/service findings.
    # Strip it from package-CVE findings, where the model tends to hallucinate
    # unrelated config backups / service restarts / file writes.
    if finding.source not in _CONFIG_SOURCES:
        backup_paths, validate_cmd, service, restart_mode = [], None, None, "none"
        write_files = []

    rem = Remediation(
        summary=_scrub(data.get("summary")) or "",
        explanation=_scrub(data.get("explanation")) or "",
        commands=commands,
        config_changes=[s for s in (_scrub(c) for c in _as_list(data.get("config_changes")))
                        if s],
        verification=_real_command(data.get("verification")),
        requires_reboot=bool(data.get("requires_reboot", False)),
        risk=str(data.get("risk") or "unknown").lower(),
        confidence=float(data.get("confidence", 0.0) or 0.0),
        provider=provider.name,
        model=provider.model,
        backup_paths=backup_paths,
        service=service,
        validate_cmd=validate_cmd,
        restart_mode=restart_mode,
        rollback_commands=[str(c) for c in _as_list(data.get("rollback_commands"))
                           if str(c).strip()],
        write_files=write_files,
    )
    return rem


# Sentinel summary for a remediation whose AI proposal raised — callers can
# detect a failed proposal (and read .explanation for the reason) without
# string-scanning ad hoc.
PROPOSAL_FAILED = "(AI proposal failed)"


def propose_all(provider: AIProvider, findings: List[Finding],
                on_progress: Optional[Callable[[int, int, Finding], None]] = None,
                *, offline: bool = False, use_catalog: bool = True,
                ground: bool = True, datastream: Optional[str] = None) -> None:
    """Fill in ``finding.remediation`` for every finding.

    By default the deterministic offline catalog plans package/advisory findings
    (``dnf`` scanner and ``oscap`` advisories) with no AI call; findings it can't
    handle (config/service findings, or a finding with neither an advisory nor a
    package + fixed version) fall through to the AI provider. This makes package
    fixes reproducible and free, and reserves the model for findings that truly
    need reasoning.

    ``offline`` forces catalog-only: an unhandleable finding gets a clear no-plan
    Remediation instead of an AI call, so ``fix`` runs fully air-gapped.
    ``use_catalog=False`` restores the old AI-for-everything behaviour (the
    ``fix --no-catalog`` escape hatch). ``ground``/``datastream`` are forwarded
    to :func:`propose` (see there for the SCAP grounding behaviour).
    """
    from . import catalog  # local import avoids an import cycle (catalog -> us)

    total = len(findings)
    for i, f in enumerate(findings, 1):
        if on_progress:
            on_progress(i, total, f)
        rem = catalog.build(f) if use_catalog else None
        if rem is not None:
            f.remediation = rem
            continue
        can_ai = provider is not None and provider.available() and not offline
        if not can_ai:
            f.remediation = catalog.unsupported(
                f, offline=offline,
                provider_available=bool(provider is not None
                                        and provider.available()))
            continue
        try:
            f.remediation = propose(provider, f, ground=ground, datastream=datastream)
        except ProviderError as exc:
            f.remediation = Remediation(
                summary=PROPOSAL_FAILED,
                explanation=str(exc),
                provider=provider.name,
                model=provider.model,
                risk="unknown",
            )


# --------------------------------------------------------------------------- #
# Low-level execution + backup/restore helpers.
# --------------------------------------------------------------------------- #
def _run(cmd: str, timeout: int = 1800) -> Dict[str, object]:
    """Run a command (no shell), returning a result dict. Does not screen."""
    try:
        proc = subprocess.run(
            shlex.split(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
        status = "ok" if proc.returncode == 0 else "failed"
        detail = proc.stdout[-4000:]
        # A dnf/yum update that exits 0 but reports "Nothing to do" changed
        # nothing (often a malformed/irrelevant advisory) — not a real success.
        if (status == "ok" and ("dnf" in cmd or "yum" in cmd)
                and _NOTHING_DONE_RE.search(proc.stdout)):
            status = "no-change"
            detail = ("dnf reported 'Nothing to do' — no package was updated "
                      "(the advisory may not apply to this host).\n" + detail)
        return {"command": cmd, "status": status,
                "returncode": proc.returncode, "detail": detail}
    except Exception as exc:  # noqa: BLE001
        return {"command": cmd, "status": "error", "detail": str(exc)}


def _systemctl(action: str, unit: str, timeout: int = 120) -> Dict[str, object]:
    res = _run(f"systemctl {action} {shlex.quote(unit)}", timeout=timeout)
    res["command"] = f"systemctl {action} {unit}"
    return res


def _snapshot(paths: List[str], dest: str) -> Dict[str, object]:
    """Copy each existing path under dest (preserving mode/mtime) and write a
    manifest so the originals can be restored later."""
    os.makedirs(dest, mode=0o700, exist_ok=True)
    manifest = []
    for p in paths:
        if os.path.isfile(p):
            stored = os.path.join(dest, p.lstrip("/"))
            os.makedirs(os.path.dirname(stored), exist_ok=True)
            shutil.copy2(p, stored)  # preserves mode + mtime
            manifest.append({"original": p, "stored": stored, "existed": True})
        else:
            manifest.append({"original": p, "existed": False})
    with open(os.path.join(dest, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    return {"command": f"backup {len(paths)} file(s) -> {dest}",
            "status": "ok", "detail": dest}


def _restore(backup_dir: str) -> List[Dict[str, object]]:
    """Restore files recorded in <backup_dir>/manifest.json."""
    try:
        with open(os.path.join(backup_dir, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError) as exc:
        return [{"command": f"restore from {backup_dir}", "status": "error",
                 "detail": f"no manifest: {exc}"}]
    out: List[Dict[str, object]] = []
    for item in manifest:
        orig = item.get("original")
        try:
            if item.get("existed"):
                shutil.copy2(item["stored"], orig)
                out.append({"command": f"rollback: restore {orig}",
                            "status": "rolled-back", "detail": "from backup"})
            elif orig and os.path.exists(orig):
                os.remove(orig)  # file was created by the fix; remove it
                out.append({"command": f"rollback: remove {orig}",
                            "status": "rolled-back", "detail": "was absent"})
        except OSError as exc:
            out.append({"command": f"rollback: {orig}", "status": "error",
                        "detail": str(exc)})
    return out


def _restore_clean(results: List[Dict[str, object]]) -> bool:
    """True if a restore result set represents a fully successful rollback:
    at least one step ran and none errored (a missing manifest or a failed
    per-file copy shows up as status 'error')."""
    return bool(results) and all(r.get("status") != "error" for r in results)


def _is_transactional(rem: Remediation) -> bool:
    return bool(rem.backup_paths or rem.service or rem.validate_cmd
                or rem.rollback_commands or rem.write_files)


# --------------------------------------------------------------------------- #
# Apply: simple (package) and transactional (config/service) paths.
# --------------------------------------------------------------------------- #
StepCallback = Optional[Callable[[Dict[str, object]], None]]


def apply(finding: Finding, dry_run: bool = False,
          state_dir: Optional[str] = None, on_step: StepCallback = None) -> bool:
    """Apply the approved remediation for a finding.

    Package fixes (no transactional metadata) run command-by-command as before.
    Config/service fixes (backup_paths/service/validate_cmd present) run
    transactionally: snapshot -> commands -> validate -> reload -> verify, with
    automatic rollback on any failure. Returns True on success (or dry-run).

    `on_step`, if given, is called with each result dict the moment that step
    finishes (backup, every command, validate, reload, health check, rollback),
    so a caller can stream live progress instead of waiting for the whole apply.
    """
    rem = finding.remediation
    if rem is None:
        return False
    rem.apply_results = []
    rem.rolled_back = False
    if _is_transactional(rem):
        return _apply_transactional(finding, dry_run, state_dir, on_step)
    ok = _apply_simple(rem, dry_run, on_step)
    # A package fix's reboot need is a FACT once it has actually run, not the
    # AI/catalog prediction: overwrite requires_reboot with the effective-state
    # verdict (running-vs-installed kernel / superseded core libs / needs-
    # restarting). Only for real, applied package fixes; a no-op or dry-run keeps
    # the prediction. Never let the probe break an otherwise-successful apply.
    if rem.applied:
        try:
            from .scanners.effective_state import reboot_pending
            rem.requires_reboot = reboot_pending()
        except Exception:  # noqa: BLE001
            pass
    return ok


def _emit(results: List[Dict[str, object]], res: Dict[str, object],
          on_step: StepCallback) -> Dict[str, object]:
    """Record a step result and stream it to the callback. Returns the result."""
    results.append(res)
    if on_step is not None:
        on_step(res)
    return res


def _apply_simple(rem: Remediation, dry_run: bool,
                  on_step: StepCallback = None) -> bool:
    ok = True
    for cmd in rem.commands:
        reason = screen_command(cmd)
        if reason:
            _emit(rem.apply_results,
                  {"command": cmd, "status": "blocked", "detail": reason}, on_step)
            ok = False
            continue
        if dry_run:
            _emit(rem.apply_results,
                  {"command": cmd, "status": "dry-run", "detail": "not executed"},
                  on_step)
            continue
        res = _emit(rem.apply_results, _run(cmd), on_step)
        ok = ok and res["status"] == "ok"
    rem.applied = not dry_run and ok
    return ok


def _apply_transactional(finding: Finding, dry_run: bool,
                         state_dir: Optional[str],
                         on_step: StepCallback = None) -> bool:
    rem = finding.remediation
    assert rem is not None
    results = rem.apply_results

    def emit(res: Dict[str, object]) -> Dict[str, object]:
        return _emit(results, res, on_step)

    # Screen every command (incl. validate) up front: a blocked command must
    # abort before we touch anything on disk.
    to_screen = list(rem.commands) + ([rem.validate_cmd] if rem.validate_cmd else [])
    for cmd in to_screen:
        reason = screen_command(cmd)
        if reason:
            emit({"command": cmd, "status": "blocked", "detail": reason})
            rem.applied = False
            return False
    # Screen the write targets too — a disallowed path must abort before we
    # snapshot or write anything.
    for wf in rem.write_files:
        reason = _screen_write_path(wf["path"])
        if reason:
            emit({"command": f"write {wf['path']}", "status": "blocked",
                  "detail": reason})
            rem.applied = False
            return False

    # Files created/replaced are snapshotted alongside backup_paths so a rollback
    # can restore an overwritten file or remove a newly-created one.
    snapshot_paths = list(dict.fromkeys(
        list(rem.backup_paths) + [wf["path"] for wf in rem.write_files]))

    if dry_run:
        if snapshot_paths:
            emit({"command": f"backup {', '.join(snapshot_paths)}",
                  "status": "dry-run", "detail": "not executed"})
        for wf in rem.write_files:
            emit({"command": f"write {wf['path']} ({len(wf['content'])} bytes)",
                  "status": "dry-run", "detail": "not executed"})
        for cmd in rem.commands:
            emit({"command": cmd, "status": "dry-run", "detail": "not executed"})
        if rem.validate_cmd:
            emit({"command": f"validate: {rem.validate_cmd}",
                  "status": "dry-run", "detail": "not executed"})
        if rem.service and rem.restart_mode in ("reload", "restart"):
            emit({"command": f"systemctl {rem.restart_mode} {rem.service}",
                  "status": "dry-run", "detail": "not executed"})
        rem.applied = False
        return True

    # 1. Snapshot the files we are about to change (edited AND written).
    if snapshot_paths:
        dest = os.path.join(state_dir or os.getcwd(), "backups", finding.id,
                            time.strftime("%Y%m%d-%H%M%S"))
        emit(_snapshot(snapshot_paths, dest))
        rem.backup_dir = dest

    def _rollback(reason: str) -> bool:
        emit({"command": "ROLLBACK", "status": "rolled-back", "detail": reason})
        restore_clean = True
        if rem.backup_dir:
            restore_res = _restore(rem.backup_dir)
            for r in restore_res:
                emit(r)
            restore_clean = _restore_clean(restore_res)
        for rc in rem.rollback_commands:
            if not screen_command(rc):
                emit(_run(rc))
        # Revert runtime state from the restored config. daemon-reload first so
        # a removed/restored unit drop-in actually takes effect before restart.
        if rem.service and rem.restart_mode in ("reload", "restart"):
            emit(_run("systemctl daemon-reload"))
            emit(_systemctl(rem.restart_mode, rem.service))
        # If the file restore itself errored, the host may be in a half-reverted
        # state — surface it loudly rather than reporting a clean rollback.
        if not restore_clean:
            emit({"command": "ROLLBACK INCOMPLETE",
                  "status": "error",
                  "detail": "one or more files could not be restored — "
                            "inspect the backup dir and fix manually: "
                            f"{rem.backup_dir}"})
        rem.applied = False
        rem.rolled_back = True
        return False

    # 2. Write the created/replaced files (no shell) BEFORE the commands, so a
    # `systemctl daemon-reload` in the commands picks up a just-written drop-in.
    for wf in rem.write_files:
        mode = int(wf["mode"], 8) if wf.get("mode") else 0o644
        res = emit(_write_file(wf["path"], wf["content"], mode))
        if res["status"] != "ok":
            return _rollback(f"could not write {wf['path']}")

    # 3. Run the change commands. "no-change" (dnf nothing-to-do) is surfaced
    # but is not a failure, so it does not trigger a rollback.
    for cmd in rem.commands:
        res = emit(_run(cmd))
        if res["status"] not in ("ok", "no-change"):
            return _rollback(f"command failed: {cmd}")

    # 3. Validate the new config BEFORE (re)starting — prevents service lockout.
    if rem.validate_cmd:
        res = _run(rem.validate_cmd)
        res["command"] = f"validate: {rem.validate_cmd}"
        emit(res)
        if res["status"] != "ok":
            return _rollback(f"validation failed: {rem.validate_cmd}")

    # 4. Apply via the service manager and confirm it stays healthy.
    if rem.service and rem.restart_mode in ("reload", "restart"):
        res = emit(_systemctl(rem.restart_mode, rem.service))
        if res["status"] != "ok":
            return _rollback(f"{rem.restart_mode} {rem.service} failed")
        health = emit(_systemctl("is-active", rem.service))
        if health["status"] != "ok":
            return _rollback(f"{rem.service} not active after {rem.restart_mode}")

    # 5. Verification (informational only; never triggers rollback).
    if rem.verification and not screen_command(rem.verification):
        res = _run(rem.verification)
        res["command"] = f"verify: {rem.verification}"
        emit(res)

    rem.applied = True
    return True


def restore_backup(finding: Finding) -> bool:
    """Manually roll back a previously-applied transactional fix.

    Used by the `rollback` CLI command. Restores the snapshot and re-applies the
    service so its runtime state matches the restored config. Returns True only
    when the files were actually restored (and the service, if any, came back
    healthy); on a failed/partial restore it returns False and leaves
    ``rolled_back`` False so the caller and the audit log don't report a rollback
    that did not happen.
    """
    rem = finding.remediation
    if rem is None or not rem.backup_dir:
        return False
    restore_res = _restore(rem.backup_dir)
    rem.apply_results = list(restore_res)
    restore_clean = _restore_clean(restore_res)
    service_ok = True
    if rem.service and rem.restart_mode in ("reload", "restart"):
        rem.apply_results.append(_run("systemctl daemon-reload"))
        sc = _systemctl(rem.restart_mode, rem.service)
        rem.apply_results.append(sc)
        service_ok = sc.get("status") == "ok"
    ok = restore_clean and service_ok
    if not ok:
        rem.apply_results.append({
            "command": "ROLLBACK INCOMPLETE", "status": "error",
            "detail": ("restore did not complete cleanly — inspect the backup "
                       f"dir and fix manually: {rem.backup_dir}")})
    rem.rolled_back = ok
    if ok:
        rem.applied = False
    return ok
