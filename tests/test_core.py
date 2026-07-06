# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Dependency-free unit tests (stdlib unittest). Run:  python3 -m unittest -v"""

from __future__ import annotations

import json
import os
import tempfile
import time
import unittest

from vulnscanai import export, export_fix, report
from vulnscanai.ai.base import extract_json
import io

from vulnscanai import branding, dashboard, feeds, notify
from vulnscanai.config import Config
from vulnscanai.models import (
    Finding, Remediation, apply_exploit_priority, apply_ignores,
    apply_service_states, apply_vendor_states, dedup_cross_scanner,
    diff_findings, findings_from_json, findings_to_json, match_ignore,
    merge_findings, severity_rank,
)
from vulnscanai.scanners.runtime_state import ServiceStateEnricher
from vulnscanai.scanners.nvd import (
    NvdEnricher, _cpe_major, _package_matches, select_package_state,
)
from vulnscanai.scanners.openscap import OpenScapScanner, parse_oval_definitions
from vulnscanai.pdfwriter import PdfBuilder
from vulnscanai.remediation import apply, restore_backup, screen_command
from vulnscanai.scanners.dnf_rhsa import parse_nevra, _CVE_LINE, _ADV_LINE
from vulnscanai.scanners.ssh_config import audit_sshd_config, parse_sshd_config
from vulnscanai.scanners.systemd_security import (
    audit_units, parse_security_overview, parse_unit_detail,
)
from vulnscanai.scanners.ports import (
    audit_ports, classify, matchers_to_predicate, parse_nft_ruleset, parse_ss,
)


def _finding(**kw):
    base = dict(source="dnf", title="t", cve_ids=["CVE-2026-0001"],
                severity="critical", package="bash")
    base.update(kw)
    return Finding(**base)


class TestModels(unittest.TestCase):
    def test_id_stable_and_severity(self):
        f1 = _finding()
        f2 = _finding()
        self.assertEqual(f1.id, f2.id)
        self.assertGreater(severity_rank("critical"), severity_rank("low"))
        self.assertEqual(severity_rank("high"), severity_rank("important"))

    def test_merge_dedup_and_union(self):
        # Same id basis (source/advisory/cves/package) -> deduped into one,
        # references unioned and the higher severity kept.
        a = _finding(severity="low", references=["urlA"])
        b = _finding(severity="critical", references=["urlB"])
        self.assertEqual(a.id, b.id)
        merged = merge_findings([a, b])
        self.assertEqual(len(merged), 1)
        self.assertEqual(sorted(merged[0].references), ["urlA", "urlB"])
        self.assertEqual(merged[0].severity, "critical")
        # Different CVE sets are genuinely different findings.
        c = _finding(cve_ids=["CVE-2026-9999"])
        self.assertEqual(len(merge_findings([a, c])), 2)

    def test_json_round_trip(self):
        f = _finding()
        f.remediation = Remediation(summary="x", commands=["dnf update -y bash"])
        back = findings_from_json(findings_to_json([f]))
        self.assertEqual(len(back), 1)
        self.assertEqual(back[0].id, f.id)
        self.assertEqual(back[0].remediation.commands, ["dnf update -y bash"])


class TestNevraAndRegex(unittest.TestCase):
    def test_parse_nevra(self):
        name, evr, arch = parse_nevra("kernel-5.14.0-427.el9.x86_64")
        self.assertEqual(name, "kernel")
        self.assertEqual(evr, "5.14.0-427.el9")
        self.assertEqual(arch, "x86_64")
        # hyphenated name
        n2, _e2, _a2 = parse_nevra("python3-libs-3.9.21-1.el9.x86_64")
        self.assertEqual(n2, "python3-libs")

    def test_cve_and_advisory_lines(self):
        m = _CVE_LINE.match("CVE-2026-1234 Important/Sec. bash-5.1.8-2.el9_1.x86_64")
        self.assertIsNotNone(m)
        self.assertEqual(m.group("cve"), "CVE-2026-1234")
        self.assertEqual(m.group("sev").split("/")[0], "Important")
        a = _ADV_LINE.match("ALSA-2026:19181 Moderate/Sec. golang-1.22.x86_64")
        self.assertIsNotNone(a)
        self.assertTrue(a.group("adv").startswith("ALSA-2026"))


class TestSafety(unittest.TestCase):
    def test_screen_blocks_dangerous(self):
        self.assertIsNone(screen_command("dnf update -y --advisory=ALSA-2026:1"))
        for bad in ["rm -rf /", "curl http://x | sh", "setenforce 0",
                    "dnf remove -y bash", "dnf update --nodeps bash",
                    "mkfs.ext4 /dev/sda1"]:
            self.assertIsNotNone(screen_command(bad), bad)

    def test_apply_dry_run_executes_nothing(self):
        f = _finding()
        f.remediation = Remediation(commands=["dnf update -y bash", "rm -rf /"])
        ok = apply(f, dry_run=True)
        self.assertFalse(ok)  # blocked command makes it not-ok
        statuses = [r["status"] for r in f.remediation.apply_results]
        self.assertEqual(statuses, ["dry-run", "blocked"])
        self.assertFalse(f.remediation.applied)


class TestHttp(unittest.TestCase):
    def test_read_timeout_becomes_httperror(self):
        import socket
        from vulnscanai import http as H
        orig = H.urllib.request.urlopen
        H.urllib.request.urlopen = lambda *a, **k: (_ for _ in ()).throw(
            socket.timeout("timed out"))
        try:
            with self.assertRaises(H.HttpError):
                H._request("GET", "https://example.invalid", retries=0)
        finally:
            H.urllib.request.urlopen = orig


class TestExtractJson(unittest.TestCase):
    def test_fenced_and_bare(self):
        self.assertEqual(extract_json('```json\n{"a": 1}\n```'), {"a": 1})
        self.assertEqual(extract_json('text {"a": 2} trailing')["a"], 2)


class TestProviders(unittest.TestCase):
    def test_registry_includes_all(self):
        from vulnscanai.ai import PROVIDERS, get_provider, ProviderError
        for name in ("claude", "openai", "gemini", "kimi",
                     "deepseek", "mistral", "local"):
            self.assertIn(name, PROVIDERS)
        with self.assertRaises(ProviderError):
            get_provider("nope")

    def test_deepseek_and_mistral_openai_compatible(self):
        from vulnscanai.ai import get_provider
        ds = get_provider("deepseek")
        self.assertEqual(ds.default_model, "deepseek-coder")
        self.assertEqual(ds.api_key_env, "DEEPSEEK_API_KEY")
        self.assertTrue(ds.endpoint.endswith("/chat/completions"))
        ms = get_provider("mistral")
        self.assertEqual(ms.default_model, "open-mixtral-8x7b")
        self.assertEqual(ms.api_key_env, "MISTRAL_API_KEY")
        self.assertTrue(ms.endpoint.endswith("/chat/completions"))


class TestTransactionalApply(unittest.TestCase):
    def _tx_finding(self, tmp, **rem_kw):
        target = os.path.join(tmp, "sshd_config")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write("ORIGINAL\n")
        f = _finding(source="ssh", package=None, cve_ids=[], title="weak sshd")
        f.remediation = Remediation(backup_paths=[target], **rem_kw)
        return f, target

    def test_dry_run_executes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            f, target = self._tx_finding(
                tmp, commands=["sed -i s/X/Y/ " + os.path.join(tmp, "sshd_config")],
                validate_cmd="sshd -t", service="sshd", restart_mode="reload")
            ok = apply(f, dry_run=True, state_dir=tmp)
            self.assertTrue(ok)
            statuses = {r["status"] for r in f.remediation.apply_results}
            self.assertEqual(statuses, {"dry-run"})
            self.assertEqual(open(target).read().strip(), "ORIGINAL")
            self.assertFalse(f.remediation.applied)

    def test_validate_failure_rolls_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "sshd_config")
            f, _ = self._tx_finding(
                tmp, commands=["sed -i s/ORIGINAL/MODIFIED/ " + target],
                validate_cmd="false")  # validation always fails -> rollback
            ok = apply(f, dry_run=False, state_dir=tmp)
            self.assertFalse(ok)
            self.assertTrue(f.remediation.rolled_back)
            self.assertFalse(f.remediation.applied)
            self.assertEqual(open(target).read().strip(), "ORIGINAL")

    def test_success_no_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "sshd_config")
            f, _ = self._tx_finding(
                tmp, commands=["sed -i s/ORIGINAL/HARDENED/ " + target],
                validate_cmd="true")  # no service -> skip systemctl
            ok = apply(f, dry_run=False, state_dir=tmp)
            self.assertTrue(ok)
            self.assertFalse(f.remediation.rolled_back)
            self.assertTrue(f.remediation.applied)
            self.assertEqual(open(target).read().strip(), "HARDENED")

    def test_blocked_command_aborts_before_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "sshd_config")
            f, _ = self._tx_finding(tmp, commands=["rm -rf /"])
            ok = apply(f, dry_run=False, state_dir=tmp)
            self.assertFalse(ok)
            self.assertEqual(f.remediation.apply_results[0]["status"], "blocked")
            self.assertEqual(open(target).read().strip(), "ORIGINAL")

    def test_manual_restore_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "sshd_config")
            f, _ = self._tx_finding(
                tmp, commands=["sed -i s/ORIGINAL/HARDENED/ " + target],
                validate_cmd="true")
            apply(f, dry_run=False, state_dir=tmp)
            self.assertEqual(open(target).read().strip(), "HARDENED")
            self.assertTrue(restore_backup(f))
            self.assertEqual(open(target).read().strip(), "ORIGINAL")
            self.assertTrue(f.remediation.rolled_back)

    def test_on_step_streams_each_result_live(self):
        # The on_step callback must fire once per recorded step, in order, with
        # the same dicts (incl. command output detail) collected in apply_results.
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "sshd_config")
            f, _ = self._tx_finding(
                tmp, commands=["sed -i s/ORIGINAL/HARDENED/ " + target],
                validate_cmd="true")
            seen = []
            ok = apply(f, dry_run=False, state_dir=tmp,
                       on_step=lambda r: seen.append(r))
            self.assertTrue(ok)
            self.assertEqual(seen, f.remediation.apply_results)   # same, in order
            self.assertTrue(any(r["command"].startswith("backup") for r in seen))
            self.assertTrue(any(r["command"].startswith("validate:") for r in seen))

    def test_on_step_simple_path_reports_output(self):
        f = _finding(source="dnf", package="bash", cve_ids=["CVE-1"], title="x")
        f.remediation = Remediation(commands=["echo hello-from-fix"])
        seen = []
        apply(f, dry_run=False, on_step=lambda r: seen.append(r))
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["status"], "ok")
        self.assertIn("hello-from-fix", seen[0]["detail"])   # captured output

    def test_no_change_status_for_dnf_nothing_to_do(self):
        # A dnf/yum command that exits 0 but says "Nothing to do" must be
        # reported as no-change, not a false [ok]. (echo stands in for dnf; the
        # command string contains "dnf" and the output matches the marker.)
        from vulnscanai.remediation import _run
        res = _run("echo dnf: Nothing to do")
        self.assertEqual(res["status"], "no-change")
        self.assertIn("no package was updated", res["detail"])

    def test_no_change_counts_as_not_applied(self):
        f = _finding(source="dnf", package="x", cve_ids=["CVE-1"], title="x")
        f.remediation = Remediation(commands=["echo dnf: Nothing to do"])
        ok = apply(f, dry_run=False)
        self.assertFalse(ok)                       # surfaced as not applied
        self.assertFalse(f.remediation.applied)

    def test_shell_redirect_command_is_blocked(self):
        # A file-writing fix (echo > file) cannot run under the no-shell runner;
        # it must be blocked, not silently no-op'd into a false success.
        for bad in ["echo '[Service]' > /etc/systemd/system/x.d/10.conf",
                    "sysctl -w x=1 | tee /etc/sysctl.d/x.conf",
                    "a && b", "echo $(hostname)", "echo `id`"]:
            self.assertIsNotNone(screen_command(bad), bad)
        # ordinary fix commands stay allowed
        for ok in ["sed -i s/a/b/ /etc/ssh/sshd_config",
                   "dnf update -y --advisory=RHSA-2024:1",
                   "firewall-cmd --remove-port=6379/tcp",
                   "find /var/www -name '*.bak' -delete"]:
            self.assertIsNone(screen_command(ok), ok)

    def test_transactional_redirect_fix_does_not_falsely_succeed(self):
        # Regression: a systemd/ssh fix that writes a drop-in via a redirect used
        # to run `echo` with '>' as a literal arg (no file written, exit 0) and
        # report "applied". It must now abort as blocked, touching nothing.
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "sshd_config")
            f, _ = self._tx_finding(
                tmp, commands=["echo 'PermitRootLogin no' > " + target],
                validate_cmd="true", service=None)
            ok = apply(f, dry_run=False, state_dir=tmp)
            self.assertFalse(ok)
            self.assertFalse(f.remediation.applied)
            self.assertEqual(f.remediation.apply_results[0]["status"], "blocked")
            self.assertEqual(open(target).read().strip(), "ORIGINAL")

    def test_manual_restore_reports_failure_truthfully(self):
        # restore_backup must NOT claim success when the backup is unrestorable
        # (missing manifest) — otherwise the CLI prints "complete" and the audit
        # log records a rollback that never happened.
        f = _finding(source="ssh", package=None, cve_ids=[], title="weak sshd")
        f.remediation = Remediation(backup_paths=["/etc/ssh/sshd_config"])
        f.remediation.backup_dir = "/nonexistent/backup/dir"
        self.assertFalse(restore_backup(f))
        self.assertFalse(f.remediation.rolled_back)
        self.assertEqual(f.remediation.apply_results[-1]["status"], "error")

    def test_auto_rollback_surfaces_incomplete_restore(self):
        # When the file restore during an auto-rollback errors, an explicit
        # ROLLBACK INCOMPLETE error step must be recorded (half-reverted host).
        import vulnscanai.remediation as R
        orig = R._restore
        R._restore = lambda d: [{"command": "restore x", "status": "error",
                                 "detail": "boom"}]
        try:
            with tempfile.TemporaryDirectory() as tmp:
                target = os.path.join(tmp, "sshd_config")
                f, _ = self._tx_finding(
                    tmp, commands=["sed -i s/ORIGINAL/MODIFIED/ " + target],
                    validate_cmd="false")   # force rollback
                ok = apply(f, dry_run=False, state_dir=tmp)
                self.assertFalse(ok)
                self.assertTrue(f.remediation.rolled_back)
                self.assertTrue(any(
                    r["command"] == "ROLLBACK INCOMPLETE" and r["status"] == "error"
                    for r in f.remediation.apply_results))
        finally:
            R._restore = orig

    def test_rollback_runs_daemon_reload_before_restart(self):
        # systemd drop-ins only take effect after daemon-reload; the rollback
        # must reload before restarting. Uses a guaranteed-nonexistent unit so
        # no real service is touched (the systemctl calls fail harmlessly).
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "dropin.conf")
            with open(target, "w", encoding="utf-8") as fh:
                fh.write("[Service]\n")
            f = _finding(source="systemd", package=None, cve_ids=[], title="svc")
            f.remediation = Remediation(
                backup_paths=[target], commands=[],
                validate_cmd="false",  # force rollback
                service="vulnscanai-nonexistent-test.service",
                restart_mode="restart")
            apply(f, dry_run=False, state_dir=tmp)
            cmds = [r["command"] for r in f.remediation.apply_results]
            restart = "systemctl restart vulnscanai-nonexistent-test.service"
            self.assertIn("systemctl daemon-reload", cmds)
            self.assertIn(restart, cmds)
            self.assertLess(cmds.index("systemctl daemon-reload"),
                            cmds.index(restart))
            self.assertTrue(f.remediation.rolled_back)


class TestSshScanner(unittest.TestCase):
    def test_parse_and_audit(self):
        cfg = parse_sshd_config(
            "# comment\nPermitRootLogin yes\nCiphers aes256-ctr,3des-cbc\n"
            "MACs hmac-sha1\nProtocol 2\n")
        self.assertEqual(cfg["permitrootlogin"], "yes")
        findings = audit_sshd_config(cfg)
        titles = {f.title for f in findings}
        self.assertIn("SSH permits direct root login", titles)
        self.assertIn("SSH offers weak ciphers", titles)
        self.assertIn("SSH offers weak MACs", titles)
        # config findings carry no package/cve but must have distinct ids
        self.assertEqual(len({f.id for f in findings}), len(findings))
        for f in findings:
            self.assertEqual(f.source, "ssh")
            self.assertIn("recommended", f.raw)

    def test_clean_config_no_findings(self):
        cfg = parse_sshd_config(
            "PermitRootLogin no\nCiphers aes256-gcm@openssh.com\n"
            "MACs hmac-sha2-256-etm@openssh.com\n")
        self.assertEqual(audit_sshd_config(cfg), [])


class TestSystemdScanner(unittest.TestCase):
    OVERVIEW = (
        "UNIT                  EXPOSURE PREDICATE HAPPY\n"
        "crond.service              9.6 UNSAFE    X\n"
        "getty@tty1.service         9.6 UNSAFE    X\n"
        "chronyd.service            3.9 OK        S\n"
        "abyssfps.service           5.8 MEDIUM    N\n"
        "myapp.service              9.2 UNSAFE    X\n"
        "systemd-journald.service   9.5 UNSAFE    X\n"
    )

    def test_parse_overview(self):
        rows = parse_security_overview(self.OVERVIEW)
        units = {u for u, _, _ in rows}
        self.assertIn("crond.service", units)
        self.assertNotIn("UNIT", units)  # header skipped
        preds = {u: p for u, _, p in rows}
        self.assertEqual(preds["chronyd.service"], "OK")

    def test_audit_policy(self):
        rows = parse_security_overview(self.OVERVIEW)
        findings = audit_units(rows, relevant=lambda u: True, min_exposure=9.0)
        units = {f.raw["unit"] for f in findings}
        self.assertEqual(units, {"crond.service", "myapp.service"})
        # excluded: getty@ (skip-list), chronyd (OK), abyssfps (MEDIUM),
        # systemd-journald (skip-list)
        for f in findings:
            self.assertEqual(f.source, "systemd")
            self.assertEqual(f.severity, "moderate")
            self.assertTrue(f.raw["dropin"].endswith("10-hardening.conf"))

    def test_audit_relevant_filter(self):
        rows = parse_security_overview(self.OVERVIEW)
        findings = audit_units(rows, relevant=lambda u: u == "myapp.service",
                               min_exposure=9.0)
        self.assertEqual({f.raw["unit"] for f in findings}, {"myapp.service"})

    def test_parse_unit_detail(self):
        detail = (
            "  NAME              DESCRIPTION            EXPOSURE\n"
            "✗ NoNewPrivileges=  may acquire new privileges  0.2\n"
            "✓ AmbientCapabilities=  does not receive caps\n"
            "✗ PrivateDevices=   has access to hardware devices  0.4\n"
        )
        items = parse_unit_detail(detail)
        self.assertEqual(len(items), 2)            # only the two scored ✗ lines
        self.assertIn("hardware devices", items[0])  # 0.4 sorts before 0.2


class TestPortScanner(unittest.TestCase):
    SS = (
        "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
        'tcp   LISTEN 0      128    0.0.0.0:23         0.0.0.0:*  users:(("telnetd",pid=1,fd=3))\n'
        'tcp   LISTEN 0      128    0.0.0.0:3306       0.0.0.0:*  users:(("mariadbd",pid=2,fd=4))\n'
        'tcp   LISTEN 0      128    127.0.0.1:6379     0.0.0.0:*  users:(("redis",pid=3,fd=5))\n'
        'tcp   LISTEN 0      511    0.0.0.0:443        0.0.0.0:*  users:(("nginx",pid=4,fd=6))\n'
        'tcp   LISTEN 0      128    [::]:3306          [::]:*     users:(("mariadbd",pid=2,fd=7))\n'
    )

    def test_classify(self):
        self.assertEqual(classify(23)[0], "plaintext")
        self.assertEqual(classify(3306)[0], "sensitive")
        self.assertEqual(classify(5901)[2], "vnc")
        self.assertEqual(classify(6005)[2], "x11")
        self.assertIsNone(classify(443))
        self.assertIsNone(classify(22))

    def test_parse_ss(self):
        socks = parse_ss(self.SS)
        ports = {s["port"] for s in socks}
        self.assertEqual(ports, {23, 3306, 6379, 443})  # header skipped
        telnet = next(s for s in socks if s["port"] == 23)
        self.assertEqual(telnet["process"], "telnetd")

    def test_audit_policy(self):
        findings = audit_ports(parse_ss(self.SS))
        cats = {(f.raw["service"], f.raw["category"]) for f in findings}
        # telnet (plaintext) and mariadb (sensitive) flagged; redis is loopback,
        # nginx/443 is expected-public -> not flagged; IPv4+IPv6 mariadb collapse.
        self.assertEqual(cats, {("telnet", "plaintext"),
                                ("mysql/mariadb", "sensitive")})
        for f in findings:
            self.assertEqual(f.source, "ports")
            self.assertEqual(f.severity, "important")

    def test_loopback_and_public_not_flagged(self):
        ss = ('tcp LISTEN 0 128 127.0.0.1:3306 0.0.0.0:* users:(("db",pid=1,fd=3))\n'
              'tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=2,fd=4))\n')
        self.assertEqual(audit_ports(parse_ss(ss)), [])

    def test_firewall_blocked_port_dropped(self):
        # mysql blocked by firewall -> dropped; telnet still flagged.
        findings = audit_ports(
            parse_ss(self.SS),
            allowed=lambda proto, port: False if port == 3306 else None)
        services = {f.raw["service"] for f in findings}
        self.assertEqual(services, {"telnet"})


class TestNftablesFirewall(unittest.TestCase):
    # inet/filter, input default-deny, with single port, named set, range and
    # an explicit drop rule.
    RULESET = {"nftables": [
        {"metainfo": {"version": "1.0.4"}},
        {"table": {"family": "inet", "name": "filter"}},
        {"set": {"family": "inet", "table": "filter", "name": "webports",
                 "type": "inet_service", "elem": [80, 443]}},
        {"chain": {"family": "inet", "table": "filter", "name": "input",
                   "type": "filter", "hook": "input", "policy": "drop"}},
        {"rule": {"chain": "input", "expr": [
            {"match": {"op": "==",
                       "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                       "right": 22}}, {"accept": None}]}},
        {"rule": {"chain": "input", "expr": [
            {"match": {"op": "==",
                       "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                       "right": "@webports"}}, {"accept": None}]}},
        {"rule": {"chain": "input", "expr": [
            {"match": {"op": "==",
                       "left": {"payload": {"protocol": "udp", "field": "dport"}},
                       "right": {"range": [30000, 30010]}}}, {"accept": None}]}},
        {"rule": {"chain": "input", "expr": [
            {"match": {"op": "==",
                       "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                       "right": 6379}}, {"drop": None}]}},
    ]}

    def test_parse_and_predicate(self):
        accept, drop, deny = parse_nft_ruleset(self.RULESET)
        self.assertTrue(deny)
        allowed = matchers_to_predicate(accept, drop, deny)
        self.assertTrue(allowed("tcp", 22))            # explicit accept
        self.assertTrue(allowed("tcp", 80))            # named set
        self.assertTrue(allowed("tcp", 443))           # named set
        self.assertTrue(allowed("udp", 30005))         # range
        self.assertFalse(allowed("tcp", 6379))         # explicit drop
        self.assertFalse(allowed("tcp", 3306))         # default-deny, no accept
        self.assertFalse(allowed("udp", 53))           # default-deny
        # proto matters: 80 was accepted for tcp, not udp.
        self.assertFalse(allowed("udp", 80))

    def test_drop_rule_without_default_deny(self):
        # No input drop policy: only the explicit drop is "blocked"; the rest
        # is unknown (None) so findings are kept.
        rs = {"nftables": [
            {"chain": {"name": "input", "hook": "input", "policy": "accept"}},
            {"rule": {"chain": "input", "expr": [
                {"match": {"op": "==",
                           "left": {"payload": {"protocol": "tcp",
                                                "field": "dport"}},
                           "right": 23}}, {"drop": None}]}},
        ]}
        accept, drop, deny = parse_nft_ruleset(rs)
        self.assertFalse(deny)
        allowed = matchers_to_predicate(accept, drop, deny)
        self.assertFalse(allowed("tcp", 23))           # explicit drop
        self.assertIsNone(allowed("tcp", 3306))        # unknown -> keep finding

    def test_blocked_port_suppressed_end_to_end(self):
        # mariadb (3306) is default-denied -> dropped; telnet (23) has no rule
        # but default-deny blocks it too, so only services with an accept stay.
        accept, drop, deny = parse_nft_ruleset(self.RULESET)
        allowed = matchers_to_predicate(accept, drop, deny)
        findings = audit_ports(parse_ss(TestPortScanner.SS), allowed=allowed)
        # Everything sensitive/plaintext in SS is default-denied -> none kept.
        self.assertEqual(findings, [])


_OVAL_DEFS = """<?xml version="1.0"?>
<oval_definitions>
 <definitions>
  <definition id="def:patch1" class="patch">
   <metadata>
    <title>ALSA-2025:0001: kernel security update (Moderate)</title>
    <reference source="CVE" ref_id="CVE-2025-1111"/>
    <reference source="CVE" ref_id="CVE-2025-2222"/>
   </metadata>
  </definition>
  <definition id="def:inv1" class="inventory">
   <metadata><title>AlmaLinux 9 is installed</title></metadata>
  </definition>
  <definition id="def:patch2" class="patch">
   <metadata>
    <title>ALSA-2025:0002: bash fix (Important)</title>
    <reference source="CVE" ref_id="CVE-2025-3333"/>
   </metadata>
  </definition>
 </definitions>
</oval_definitions>
"""

_OVAL_RESULTS = """<?xml version="1.0"?>
<oval_results xmlns="http://oval.mitre.org/XMLSchema/oval-results-5">
 <results><system><definitions>
  <definition definition_id="def:patch1" result="true"/>
  <definition definition_id="def:inv1" result="true"/>
  <definition definition_id="def:patch2" result="false"/>
 </definitions></system></results>
</oval_results>
"""


class TestOvalScanner(unittest.TestCase):
    def test_parse_definitions(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "defs.xml")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(_OVAL_DEFS)
            d = parse_oval_definitions(p)
            self.assertEqual(d["def:patch1"]["class"], "patch")
            self.assertEqual(d["def:patch1"]["severity"], "moderate")
            self.assertEqual(d["def:patch1"]["advisory"], "ALSA-2025:0001")
            self.assertEqual(d["def:patch1"]["cves"],
                             ["CVE-2025-1111", "CVE-2025-2222"])
            self.assertEqual(d["def:inv1"]["class"], "inventory")

    def test_results_filter_class_and_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            defs = os.path.join(tmp, "defs.xml")
            res = os.path.join(tmp, "results.xml")
            with open(defs, "w", encoding="utf-8") as fh:
                fh.write(_OVAL_DEFS)
            with open(res, "w", encoding="utf-8") as fh:
                fh.write(_OVAL_RESULTS)
            scanner = OpenScapScanner(config=None)
            findings = scanner._parse_results(res, defs)
            # only def:patch1 survives: inv1 is inventory, patch2 is false
            self.assertEqual(len(findings), 1)
            f = findings[0]
            self.assertEqual(f.source, "oscap")
            self.assertEqual(f.severity, "moderate")
            self.assertEqual(f.advisory, "ALSA-2025:0001")
            self.assertEqual(len(f.cve_ids), 2)


class TestCrossScannerDedup(unittest.TestCase):
    def test_merge_shared_advisory(self):
        dnf = Finding(source="dnf", package="kernel", advisory="RHSA-2025:1",
                      cve_ids=["CVE-2025-1"], severity="important")
        oscap = Finding(source="oscap", advisory="RHSA-2025:1",
                        cve_ids=["CVE-2025-1", "CVE-2025-2"], severity="moderate")
        merged = dedup_cross_scanner([dnf, oscap])
        self.assertEqual(len(merged), 1)
        m = merged[0]
        self.assertEqual(m.package, "kernel")             # richer record kept
        self.assertEqual(m.severity, "important")          # max severity
        self.assertEqual(set(m.cve_ids), {"CVE-2025-1", "CVE-2025-2"})

    def test_unrelated_and_config_findings_stay_separate(self):
        a = Finding(source="ssh", title="weak A")
        b = Finding(source="ssh", title="weak B")
        c = Finding(source="dnf", package="bash", cve_ids=["CVE-2025-9"])
        self.assertEqual(len(dedup_cross_scanner([a, b, c])), 3)


class TestBaseline(unittest.TestCase):
    def test_match_and_apply(self):
        f1 = _finding(cve_ids=["CVE-2026-0001"], package="bash")
        f2 = _finding(cve_ids=["CVE-2026-9999"], advisory="RHSA-2026:9",
                      package="kernel")
        kept, sup = apply_ignores([f1, f2], ["CVE-2026-0001"])
        self.assertEqual((kept, sup), ([f2], 1))
        kept, sup = apply_ignores([f1, f2], ["kern*"])      # package glob
        self.assertEqual((kept, sup), ([f1], 1))
        kept, sup = apply_ignores([f1, f2], ["RHSA-2026:9"])  # advisory
        self.assertEqual((kept, sup), ([f1], 1))
        kept, sup = apply_ignores([f1, f2], ["# comment", "", "   "])
        self.assertEqual(sup, 0)
        self.assertTrue(match_ignore(f1, [f1.id]))           # by id
        self.assertTrue(match_ignore(_finding(title="weak sshd"), ["weak*"]))


class TestVendorState(unittest.TestCase):
    def test_cpe_major_and_package_match(self):
        self.assertEqual(_cpe_major("cpe:/o:redhat:enterprise_linux:9"), "9")
        self.assertEqual(_cpe_major("cpe:/a:redhat:enterprise_linux:9::appstream"), "9")
        self.assertEqual(_cpe_major("cpe:/o:redhat:enterprise_linux:10"), "10")
        self.assertIsNone(_cpe_major("cpe:/o:redhat:openshift:4"))
        self.assertTrue(_package_matches("openssl", "openssl"))
        self.assertTrue(_package_matches("openssl", "openssl-libs"))  # subpackage
        self.assertFalse(_package_matches("openssl", "libssl"))
        self.assertFalse(_package_matches("ssl", "openssl"))          # not reverse

    def test_select_picks_most_affected(self):
        ps = [
            {"cpe": "cpe:/o:redhat:enterprise_linux:9", "package_name": "kernel",
             "fix_state": "Not affected"},
            {"cpe": "cpe:/a:redhat:enterprise_linux:9::appstream",
             "package_name": "kernel", "fix_state": "Affected"},
            {"cpe": "cpe:/o:redhat:enterprise_linux:8", "package_name": "kernel",
             "fix_state": "Will not fix"},
        ]
        # On 9 both not-affected and affected match -> keep the affected verdict.
        self.assertEqual(select_package_state(ps, "9", "kernel"), "affected")
        # On 8 only the won't-fix entry matches.
        self.assertEqual(select_package_state(ps, "8", "kernel"), "will not fix")
        # No entry for the package / no major -> None.
        self.assertIsNone(select_package_state(ps, "9", "bash"))
        self.assertIsNone(select_package_state(ps, None, "kernel"))

    def test_apply_vendor_states_drops_only_not_affected(self):
        a = _finding(package="kernel", vendor_fix_state="not affected")
        b = _finding(package="openssl", vendor_fix_state="will not fix")
        c = _finding(package="bash", vendor_fix_state=None)
        kept, dropped = apply_vendor_states([a, b, c])
        self.assertEqual(dropped, 1)
        self.assertEqual([f.package for f in kept], ["openssl", "bash"])

    def test_enricher_annotates_and_records(self):
        f = _finding(package="kernel", description="base")
        enr = NvdEnricher.__new__(NvdEnricher)
        enr._major = "9"
        data = {"package_state": [
            {"cpe": "cpe:/o:redhat:enterprise_linux:9", "package_name": "kernel",
             "fix_state": "Will not fix"}]}
        enr._annotate_vendor_state(f, data)
        self.assertEqual(f.vendor_fix_state, "will not fix")
        self.assertIn("no dnf security update will ship", f.description)


class TestServiceState(unittest.TestCase):
    def _enricher(self, units_map, sysstate):
        enr = ServiceStateEnricher.__new__(ServiceStateEnricher)
        enr._unit_cache = {}
        enr._package_units = lambda pkg: units_map.get(pkg, [])
        enr._systemctl = lambda verb, unit: sysstate.get((verb, unit), "")
        return enr

    def test_apply_downgrades_only_inactive(self):
        a = _finding(package="httpd", severity="important",
                     runtime_state="inactive")
        a.raw["service_units"] = ["httpd.service"]
        b = _finding(package="openssl", severity="critical",
                     runtime_state="no-service")
        c = _finding(package="nginx", severity="important",
                     runtime_state="active")
        d = _finding(package="bash", severity="high", runtime_state=None)
        out, n = apply_service_states([a, b, c, d])
        self.assertEqual(n, 1)
        self.assertEqual(a.severity, "low")
        self.assertEqual(a.raw["severity_before_runtime"], "important")
        self.assertIn("httpd.service", a.description)
        self.assertIn("not exposed", a.description)
        # Everything else is left exactly as it was.
        self.assertEqual([b.severity, c.severity, d.severity],
                         ["critical", "important", "high"])

    def test_apply_skips_already_low(self):
        f = _finding(package="httpd", severity="low", runtime_state="inactive")
        _out, n = apply_service_states([f])
        self.assertEqual(n, 0)
        self.assertEqual(f.severity, "low")
        self.assertNotIn("severity_before_runtime", f.raw)

    def test_exposure_classification(self):
        units = {"httpd": ["httpd.service"], "openssl": [],
                 "chrony": ["chronyd.service"]}
        st = {}
        enr = self._enricher(units, st)
        # No units shipped -> library/CLI level, untouched.
        self.assertEqual(enr._exposure("openssl"), ("no-service", []))
        # Running service -> exposed.
        st[("is-active", "httpd.service")] = "active"
        self.assertEqual(enr._exposure("httpd")[0], "active")
        # Stopped AND disabled -> dormant.
        st[("is-active", "chronyd.service")] = "inactive"
        st[("is-enabled", "chronyd.service")] = "disabled"
        self.assertEqual(enr._exposure("chrony"), ("inactive", ["chronyd.service"]))
        # Stopped but enabled -> still exposed (starts on boot).
        st[("is-enabled", "chronyd.service")] = "enabled"
        self.assertEqual(enr._exposure("chrony")[0], "active")
        # Stopped, unknown enable state -> exposed (never guess exposure away).
        st[("is-enabled", "chronyd.service")] = ""
        self.assertEqual(enr._exposure("chrony")[0], "active")

    def test_multi_unit_all_dormant(self):
        # A package is only inactive when ALL its units are dormant.
        units = {"cups": ["cups.service", "cups.socket"]}
        st = {("is-active", "cups.service"): "inactive",
              ("is-enabled", "cups.service"): "disabled",
              ("is-active", "cups.socket"): "active"}  # socket still listening
        enr = self._enricher(units, st)
        self.assertEqual(enr._exposure("cups")[0], "active")
        st[("is-active", "cups.socket")] = "inactive"
        st[("is-enabled", "cups.socket")] = "disabled"
        self.assertEqual(enr._exposure("cups")[0], "inactive")

    def test_enrich_sets_state_and_units(self):
        enr = self._enricher(
            {"chrony": ["chronyd.service"]},
            {("is-active", "chronyd.service"): "inactive",
             ("is-enabled", "chronyd.service"): "disabled"})
        enr.available = lambda: True
        f = _finding(package="chrony", severity="moderate")
        enr.enrich([f])
        self.assertEqual(f.runtime_state, "inactive")
        self.assertEqual(f.raw["service_units"], ["chronyd.service"])

    def test_package_units_parses_rpm_ql(self):
        enr = ServiceStateEnricher.__new__(ServiceStateEnricher)
        enr._unit_cache = {}
        listing = "\n".join([
            "/usr/lib/systemd/system/httpd.service",
            "/usr/lib/systemd/system/httpd.socket",
            "/usr/lib/systemd/system/httpd@.service",  # template -> skipped
            "/usr/sbin/httpd",
            "/etc/httpd/conf/httpd.conf",
        ])
        enr_run = lambda *a, **k: (0, listing, "")
        import vulnscanai.scanners.runtime_state as rs
        orig = rs.run
        rs.run = enr_run
        try:
            self.assertEqual(enr._package_units("httpd"),
                             ["httpd.service", "httpd.socket"])
        finally:
            rs.run = orig


class TestFixExport(unittest.TestCase):
    def _tx_finding(self):
        f = _finding(source="ssh", package=None, cve_ids=[], title="weak sshd")
        f.remediation = Remediation(
            summary="harden sshd", commands=["sed -i s/a/b/ /etc/ssh/sshd_config"],
            backup_paths=["/etc/ssh/sshd_config"], validate_cmd="sshd -t",
            service="sshd", restart_mode="reload")
        return f

    def test_bash_script(self):
        script = export_fix.to_bash_script([self._tx_finding()])
        self.assertTrue(script.startswith("#!/usr/bin/env bash"))
        for token in ("set -euo pipefail", "backup /etc/ssh/sshd_config",
                      "trap", "sshd -t", "systemctl reload sshd"):
            self.assertIn(token, script)

    def test_ansible_playbook_is_valid_yaml(self):
        play_text = export_fix.to_ansible_playbook([self._tx_finding()])
        data = json.loads(play_text[play_text.index("["):])  # JSON == valid YAML
        self.assertEqual(data[0]["hosts"], "all")
        self.assertTrue(data[0]["become"])
        self.assertEqual(data[0]["handlers"][0]["name"], "reload sshd")
        self.assertTrue(any("validate" in t["name"] for t in data[0]["tasks"]))


class TestPdf(unittest.TestCase):
    def test_valid_pdf_bytes(self):
        pdf = PdfBuilder()
        pdf.text("Hello", size=14, style="bold")
        for i in range(120):  # force multiple pages
            pdf.text(f"line {i} " + "word " * 20)
        data = pdf.build()
        self.assertTrue(data.startswith(b"%PDF-1.4"))
        self.assertIn(b"%%EOF", data[-16:])
        self.assertIn(b"/Type /Catalog", data)
        self.assertIn(b"startxref", data)


class TestSarif(unittest.TestCase):
    def test_sarif_structure_and_level(self):
        findings = [
            _finding(severity="critical", cvss_score=9.8),
            _finding(severity="low", cve_ids=["CVE-2026-0003"], package="zlib"),
        ]
        doc = export.build_sarif(findings)
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "vulnscan-ai")
        results = run["results"]
        self.assertEqual(len(results), 2)
        levels = {r["ruleId"]: r["level"] for r in results}
        self.assertEqual(levels["CVE-2026-0001"], "error")
        self.assertEqual(levels["CVE-2026-0003"], "note")
        # security-severity present and numeric-looking
        sev = results[0]["properties"]["security-severity"]
        float(sev)  # raises if not numeric
        # whole doc must be JSON-serialisable
        json.dumps(doc)

    def test_write_report_dispatch(self):
        findings = [_finding()]
        with tempfile.TemporaryDirectory() as d:
            for name, key in [("out.sarif", "$schema"), ("out.json", "tool")]:
                p = os.path.join(d, name)
                report.write_report(findings, p, "host", "2026-01-01")
                with open(p) as fh:
                    obj = json.load(fh)
                self.assertIn(key, obj)
            # pdf path
            p = os.path.join(d, "out.pdf")
            report.write_report(findings, p, "host", "2026-01-01")
            with open(p, "rb") as fh:
                self.assertTrue(fh.read(8).startswith(b"%PDF"))


class TestHardware(unittest.TestCase):
    def test_detect_gpu_and_budget_shape(self):
        from vulnscanai import hardware
        gpu = hardware.detect_gpu()
        self.assertEqual(set(gpu), {"present", "kind", "name", "vram_gb"})
        self.assertIsInstance(gpu["present"], bool)
        b = hardware.compute_budget_gb()
        self.assertIn(b["where"], ("gpu", "cpu"))
        self.assertGreaterEqual(b["budget_gb"], 0.0)


class TestWizardConfig(unittest.TestCase):
    def test_write_user_config_merges(self):
        from vulnscanai.config import Config
        old = os.environ.get("HOME")
        with tempfile.TemporaryDirectory() as d:
            os.environ["HOME"] = d
            try:
                c = Config()
                p = c.write_user_config({"provider": "local", "model": "m1"})
                self.assertTrue(os.path.isfile(p))
                c.write_user_config({"model": "m2"})  # merge, not replace
                data = json.load(open(p))
                self.assertEqual(data["provider"], "local")
                self.assertEqual(data["model"], "m2")
            finally:
                if old is not None:
                    os.environ["HOME"] = old

    def test_dashboard_enable_fix_persists(self):
        from vulnscanai.config import Config
        from vulnscanai.cli import build_parser, cmd_dashboard
        old = os.environ.get("HOME")
        with tempfile.TemporaryDirectory() as d:
            os.environ["HOME"] = d
            try:
                p = build_parser()
                c = Config()
                cfgpath = c.user_config_path()   # honours the swapped HOME
                self.assertFalse(c.dashboard_allow_fix)
                rc = cmd_dashboard(c, p.parse_args(["dashboard", "--enable-fix"]))
                self.assertEqual(rc, 0)
                self.assertTrue(c.dashboard_allow_fix)                     # in-memory
                self.assertTrue(Config.load(cfgpath).dashboard_allow_fix)  # persisted
                cmd_dashboard(c, p.parse_args(["dashboard", "--disable-fix"]))
                self.assertFalse(Config.load(cfgpath).dashboard_allow_fix)
            finally:
                if old is not None:
                    os.environ["HOME"] = old

    def test_should_offer_setup_guards(self):
        from vulnscanai.config import Config
        from vulnscanai.wizard import should_offer_setup
        with tempfile.TemporaryDirectory() as d:
            c = Config(state_dir=d)
            # never for the setup command itself
            self.assertFalse(should_offer_setup(c, "setup"))
            # suppressed by env
            os.environ["VULNSCANAI_NO_SETUP"] = "1"
            try:
                self.assertFalse(should_offer_setup(c, "scan"))
            finally:
                del os.environ["VULNSCANAI_NO_SETUP"]
            # not after the marker is written
            c.mark_setup_done()
            self.assertTrue(c.is_setup_done())
            self.assertFalse(should_offer_setup(c, "scan"))


class TestScanDiff(unittest.TestCase):
    def test_added_and_resolved(self):
        a = _finding(cve_ids=["CVE-2026-0001"], package="bash")
        b = _finding(cve_ids=["CVE-2026-0002"], package="openssl")
        c = _finding(cve_ids=["CVE-2026-0003"], package="curl")
        added, resolved = diff_findings([a, b], [b, c])
        self.assertEqual([f.package for f in added], ["curl"])
        self.assertEqual([f.package for f in resolved], ["bash"])

    def test_no_change(self):
        a = _finding()
        self.assertEqual(diff_findings([a], [a]), ([], []))

    def test_first_scan(self):
        a = _finding()
        added, resolved = diff_findings([], [a])
        self.assertEqual(len(added), 1)
        self.assertEqual(resolved, [])


class _TTY(io.StringIO):
    def isatty(self):
        return True


class TestBanner(unittest.TestCase):
    def setUp(self):
        os.environ.pop("VULNSCANAI_NO_BANNER", None)

    def test_banner_plain_for_non_tty(self):
        s = branding.banner("h1", stream=io.StringIO())
        self.assertIn("V U L N S C A N · A I", s)
        self.assertIn("h1", s)
        self.assertNotIn("\033", s)  # no ANSI colour on a non-tty stream

    def test_print_banner_suppressed_when_not_tty(self):
        buf = io.StringIO()
        branding.print_banner("scan", "h", stream=buf)
        self.assertEqual(buf.getvalue(), "")

    def test_print_banner_suppressed_for_scheduled(self):
        buf = _TTY()
        branding.print_banner("scheduled", "h", stream=buf)
        self.assertEqual(buf.getvalue(), "")

    def test_print_banner_suppressed_by_env(self):
        os.environ["VULNSCANAI_NO_BANNER"] = "1"
        buf = _TTY()
        branding.print_banner("scan", "h", stream=buf)
        self.assertEqual(buf.getvalue(), "")

    def test_print_banner_shows_on_tty(self):
        buf = _TTY()
        branding.print_banner("scan", "myhost", stream=buf)
        self.assertIn("V U L N S C A N · A I", buf.getvalue())


class _FakeSMTP:
    instances = []

    def __init__(self, host, port, timeout=0):
        self.host, self.port = host, port
        self.started = False
        self.creds = None
        self.messages = []
        _FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        self.started = True

    def login(self, user, password):
        self.creds = (user, password)

    def send_message(self, msg):
        self.messages.append(msg)


class TestNotify(unittest.TestCase):
    def _cfg(self, **kw):
        c = Config()
        for k, v in kw.items():
            setattr(c, k, v)
        return c

    def test_not_sent_without_recipient(self):
        sent, _info = notify.send_scan_email(
            self._cfg(), [_finding()], [], [], "h", "now")
        self.assertFalse(sent)

    def test_not_sent_when_below_threshold_and_no_new(self):
        cfg = self._cfg(notify_email="a@b.c", notify_min_severity="critical")
        sent, _info = notify.send_scan_email(
            cfg, [_finding(severity="low")], [], [], "h", "now")
        self.assertFalse(sent)

    def test_sent_with_auth_and_starttls(self):
        cfg = self._cfg(notify_email="ops@example.com",
                        notify_min_severity="important", smtp_starttls=True,
                        smtp_user="u", smtp_password="p", smtp_host="mail.local")
        f = _finding(severity="critical", title="bad", package="openssl")
        _FakeSMTP.instances = []
        orig = notify.smtplib.SMTP
        notify.smtplib.SMTP = _FakeSMTP
        try:
            sent, info = notify.send_scan_email(cfg, [f], [f], [], "host1", "now")
        finally:
            notify.smtplib.SMTP = orig
        self.assertTrue(sent, info)
        self.assertEqual(len(_FakeSMTP.instances), 1)
        srv = _FakeSMTP.instances[0]
        self.assertTrue(srv.started)
        self.assertEqual(srv.creds, ("u", "p"))
        self.assertEqual(len(srv.messages), 1)
        msg = srv.messages[0]
        self.assertEqual(msg["To"], "ops@example.com")
        body = msg.get_content()
        self.assertIn("host1", body)
        self.assertIn("bad", body)            # finding title appears
        self.assertIn("critical: 1", body)    # severity tally appears


class TestSelectScanners(unittest.TestCase):
    def _args(self, **kw):
        import argparse
        ns = argparse.Namespace(all=False, scanner=None)
        for k, v in kw.items():
            setattr(ns, k, v)
        return ns

    def test_all_overrides_everything(self):
        from vulnscanai.cli import _select_scanners
        from vulnscanai.scanners import SCANNERS
        sel = _select_scanners(self._args(all=True, scanner=["ssh"]),
                               Config(scanners=["dnf"]))
        self.assertEqual(set(sel), set(SCANNERS))

    def test_explicit_scanner_flags(self):
        from vulnscanai.cli import _select_scanners
        sel = _select_scanners(self._args(scanner=["ssh", "ports"]),
                               Config(scanners=["dnf"]))
        self.assertEqual(sel, ["ssh", "ports"])

    def test_default_from_config(self):
        from vulnscanai.cli import _select_scanners
        self.assertEqual(_select_scanners(self._args(), Config(scanners=["dnf"])),
                         ["dnf"])


class TestDashboard(unittest.TestCase):
    def test_password_hash_roundtrip(self):
        h = dashboard.hash_password("s3cret!")
        self.assertTrue(h.startswith("pbkdf2_sha256$"))
        self.assertTrue(dashboard.verify_password("s3cret!", h))
        self.assertFalse(dashboard.verify_password("nope", h))
        self.assertFalse(dashboard.verify_password("x", "garbage"))

    def test_client_allowlist(self):
        self.assertTrue(dashboard.client_allowed("127.0.0.1", []))   # loopback always
        self.assertTrue(dashboard.client_allowed("::1", []))
        self.assertTrue(dashboard.client_allowed("10.0.0.5", ["10.0.0.0/24"]))
        self.assertFalse(dashboard.client_allowed("8.8.8.8", ["10.0.0.0/24"]))
        self.assertFalse(dashboard.client_allowed("10.0.0.5", []))   # not loopback
        self.assertFalse(dashboard.client_allowed("not-an-ip", ["10.0.0.0/24"]))

    def test_valid_allow_entry(self):
        self.assertTrue(dashboard.valid_allow_entry("192.168.1.10"))
        self.assertTrue(dashboard.valid_allow_entry("10.0.0.0/8"))
        self.assertFalse(dashboard.valid_allow_entry("banana"))

    def test_sessions(self):
        s = dashboard._Sessions()
        tok = s.create()
        self.assertTrue(s.valid(tok))
        self.assertFalse(s.valid("bogus"))
        self.assertFalse(s.valid(None))
        s.drop(tok)
        self.assertFalse(s.valid(tok))

    def test_render(self):
        self.assertIn("Sign in", dashboard.render_login())
        self.assertIn("Invalid", dashboard.render_login("Invalid creds"))
        self.assertIn("<svg", dashboard.render_login())          # brand logo present
        self.assertIn("vulnscan", dashboard.render_login())
        f = _finding(severity="important", title="openssl update",
                     package="openssl", cve_ids=["CVE-2026-9"])
        page = dashboard.render_dashboard([f], "host1", "2026-06-23 10:00", ["10.0.0.0/24"])
        self.assertIn("openssl update", page)
        self.assertIn("important", page)
        self.assertIn("CVE-2026-9", page)
        self.assertIn("10.0.0.0/24", page)

    def test_exploited_kev_and_epss_tiles(self):
        kev = _finding(severity="important", title="a", exploited=True, epss=0.9)
        plain = _finding(severity="low", title="b")
        page = dashboard.render_dashboard([kev, plain], "h", "now", [])
        self.assertIn("exploited (KEV)", page)
        self.assertIn("EPSS &ge;50%", page)
        self.assertIn("#b3001b", page)                 # red KEV tile colour

    def test_no_exploit_tiles_when_none(self):
        # No KEV / high-EPSS findings -> the extra tiles are omitted entirely.
        page = dashboard.render_dashboard([_finding(severity="low")], "h", "now", [])
        self.assertNotIn("exploited (KEV)", page)
        self.assertNotIn("EPSS &ge;50%", page)

    def test_render_escapes_html(self):
        f = _finding(title="<script>alert(1)</script>", package=None, cve_ids=[])
        page = dashboard.render_dashboard([f], "h", "now", [])
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_firewall_hint(self):
        # Localhost-only never hints (not reachable from the network anyway).
        self.assertIsNone(dashboard.firewall_hint(65101, "127.0.0.1", []))
        # No firewall-cmd on the host -> no hint.
        orig = dashboard.shutil.which
        dashboard.shutil.which = lambda name: None
        try:
            self.assertIsNone(
                dashboard.firewall_hint(65101, "0.0.0.0", ["10.0.0.0/24"]))
        finally:
            dashboard.shutil.which = orig

    def test_browser_blocked_ports(self):
        # The default port must be one browsers actually allow.
        self.assertEqual(Config().dashboard_port, 65101)
        self.assertNotIn(65101, dashboard.BROWSER_BLOCKED_PORTS)
        self.assertIn(6666, dashboard.BROWSER_BLOCKED_PORTS)   # IRC, ERR_UNSAFE_PORT

    def test_scan_and_fix_buttons(self):
        f = _finding(severity="important", title="openssl", package="openssl")
        off = dashboard.render_dashboard([f], "h", "now", [], allow_fix=False)
        self.assertIn("Scan now", off)
        self.assertIn("Preview fix", off)
        self.assertNotIn("Apply fix", off)          # apply hidden by default
        on = dashboard.render_dashboard([f], "h", "now", [], allow_fix=True)
        self.assertIn("Apply fix", on)              # shown only with opt-in

    def test_scanning_state_autorefreshes(self):
        page = dashboard.render_dashboard([], "h", "now", [], scan_running=True)
        self.assertIn("Scanning", page)
        self.assertIn('http-equiv="refresh"', page)

    def test_apply_fix_is_opt_in_by_default(self):
        self.assertFalse(Config().dashboard_allow_fix)

    def test_fix_result_preview_vs_apply_gate(self):
        rem = Remediation(summary="do x", risk="low", confidence=0.9,
                          commands=["dnf update -y openssl"])
        # allow_fix off -> apply is disabled, no apply form
        off = dashboard.render_fix_result("openssl", "abc", rem, False)
        self.assertIn("Applying from the dashboard is disabled", off)
        self.assertNotIn('value="apply"', off)
        # allow_fix on -> an explicit apply form is offered
        on = dashboard.render_fix_result("openssl", "abc", rem, True)
        self.assertIn('value="apply"', on)


class TestApiKeyConfig(unittest.TestCase):
    def _write(self, **data):
        d = tempfile.mkdtemp()
        data.setdefault("state_dir", d)
        p = os.path.join(d, "config.json")
        with open(p, "w") as fh:
            json.dump(data, fh)
        return p

    def test_stored_key_injected_and_provider_ready(self):
        p = self._write(api_keys={"ANTHROPIC_API_KEY": "sk-stored"})
        os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            Config.load(p)
            self.assertEqual(os.environ.get("ANTHROPIC_API_KEY"), "sk-stored")
            from vulnscanai.ai import get_provider
            self.assertTrue(get_provider("claude").available())
        finally:
            os.environ.pop("ANTHROPIC_API_KEY", None)

    def test_real_env_wins_over_stored(self):
        p = self._write(api_keys={"ANTHROPIC_API_KEY": "sk-stored"})
        os.environ["ANTHROPIC_API_KEY"] = "sk-real-env"
        try:
            Config.load(p)
            self.assertEqual(os.environ.get("ANTHROPIC_API_KEY"), "sk-real-env")
        finally:
            os.environ.pop("ANTHROPIC_API_KEY", None)

    def test_wizard_saves_provider_and_key(self):
        import getpass
        import vulnscanai.wizard as W
        home = tempfile.mkdtemp()
        answers = iter(["1", "", ""])    # provider 1 (claude), model blank, effort blank
        orig_ask, orig_gp = W._ask, getpass.getpass
        orig_home = os.environ.get("HOME")
        W._ask = lambda prompt="": next(answers, "")
        getpass.getpass = lambda prompt="": "sk-ant-test"
        os.environ["HOME"] = home
        os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            W._configure_cloud_provider(Config())
            saved = json.load(open(os.path.join(
                home, ".config", "vulnscan-ai", "config.json")))
        finally:
            W._ask, getpass.getpass = orig_ask, orig_gp
            if orig_home is not None:
                os.environ["HOME"] = orig_home
            os.environ.pop("ANTHROPIC_API_KEY", None)
        self.assertEqual(saved["provider"], "claude")
        self.assertEqual(saved["api_keys"]["ANTHROPIC_API_KEY"], "sk-ant-test")

    def test_cloud_setup_reuses_saved_key(self):
        # Changing the model on a provider that already has a stored key must NOT
        # force the operator to paste the key again.
        import getpass
        import vulnscanai.wizard as W
        home = tempfile.mkdtemp()
        cfg = Config()
        cfg.api_keys = {"ANTHROPIC_API_KEY": "sk-ant-saved"}
        answers = iter(["1", "y", "", ""])   # claude, reuse=yes, model default, effort
        called = {"getpass": False}

        def boom(prompt=""):
            called["getpass"] = True
            return "sk-should-not-be-used"

        orig_ask, orig_gp = W._ask, getpass.getpass
        orig_home = os.environ.get("HOME")
        W._ask = lambda prompt="": next(answers, "")
        getpass.getpass = boom
        os.environ["HOME"] = home
        os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            W._configure_cloud_provider(cfg)
            saved = json.load(open(os.path.join(
                home, ".config", "vulnscan-ai", "config.json")))
        finally:
            W._ask, getpass.getpass = orig_ask, orig_gp
            if orig_home is not None:
                os.environ["HOME"] = orig_home
            os.environ.pop("ANTHROPIC_API_KEY", None)
        self.assertFalse(called["getpass"])          # key reused, not re-prompted
        self.assertEqual(saved["provider"], "claude")
        self.assertEqual(saved["api_keys"]["ANTHROPIC_API_KEY"], "sk-ant-saved")

    def test_local_setup_persists_even_if_pull_fails(self):
        # Picking 'local' must switch the provider even when the download can't
        # complete (offline / already-present model), so it doesn't silently
        # keep using the previous cloud provider.
        import vulnscanai.wizard as W
        home = tempfile.mkdtemp()
        cfg = Config(state_dir=tempfile.mkdtemp())
        names = ("_have", "_ensure_server", "_pull", "_ask",
                 "compute_budget_gb", "mem_total_gb")
        orig = {n: getattr(W, n) for n in names}
        orig_home = os.environ.get("HOME")
        W._have = lambda b: True
        W._ensure_server = lambda: True
        W._pull = lambda m: False                    # simulate a failed/offline pull
        W._ask = lambda prompt="": "1"               # pick model #1
        W.compute_budget_gb = lambda: {
            "gpu": {"present": False, "vram_gb": 0, "name": "x", "kind": "cpu"},
            "where": "cpu", "budget_gb": 8.0}
        W.mem_total_gb = lambda: 16.0
        os.environ["HOME"] = home
        try:
            rc = W._setup_model(cfg)
            saved = json.load(open(os.path.join(
                home, ".config", "vulnscan-ai", "config.json")))
        finally:
            for n, f in orig.items():
                setattr(W, n, f)
            if orig_home is not None:
                os.environ["HOME"] = orig_home
        self.assertEqual(saved["provider"], "local")
        self.assertEqual(saved["model"], W.MODELS[0]["name"])
        self.assertEqual(rc, 1)                       # pull failed, selection saved


class TestHttpErrorReason(unittest.TestCase):
    """HttpError must surface the server's own error text, not just the status,
    so an API reason like 'credit balance is too low' reaches the operator."""

    def test_anthropic_openai_error_shape(self):
        from vulnscanai.http import HttpError, _error_reason
        body = ('{"type":"error","error":{"type":"invalid_request_error",'
                '"message":"Your credit balance is too low"}}')
        self.assertEqual(_error_reason(body), "Your credit balance is too low")
        self.assertIn("credit balance", str(HttpError(400, "Bad Request", body)))

    def test_error_string_and_message_shapes(self):
        from vulnscanai.http import _error_reason
        self.assertEqual(_error_reason('{"error":"nope"}'), "nope")
        self.assertEqual(_error_reason('{"message":"boom"}'), "boom")

    def test_raw_and_empty_fallback(self):
        from vulnscanai.http import HttpError, _error_reason
        self.assertEqual(_error_reason("plain error"), "plain error")
        self.assertEqual(_error_reason(""), "")
        self.assertEqual(str(HttpError(500, "Server Error")), "HTTP 500: Server Error")


class TestProposalFailure(unittest.TestCase):
    def test_propose_all_records_reason(self):
        from vulnscanai import remediation
        from vulnscanai.ai.base import AIProvider, ProviderError

        class Boom(AIProvider):
            name = "boom"
            default_model = "m"

            def complete(self, system, user):
                raise ProviderError("HTTP 400: Bad Request — credit balance is too low")

        f = _finding()
        remediation.propose_all(Boom(), [f])
        self.assertEqual(f.remediation.summary, remediation.PROPOSAL_FAILED)
        self.assertIn("credit balance", f.remediation.explanation)

    def test_fix_aborts_when_all_proposals_fail(self):
        import io, contextlib, types
        from vulnscanai import cli
        from vulnscanai.ai.base import AIProvider, ProviderError

        class Broke(AIProvider):
            name = "claude"
            default_model = "claude-sonnet-4-6"
            api_key_env = "ANTHROPIC_API_KEY"

            def available(self):
                return True

            def complete(self, system, user):
                raise ProviderError("HTTP 400: Bad Request — credit balance is too low")

        d = tempfile.mkdtemp()
        cfg = Config(state_dir=d)
        cfg.patched_filter = False           # skip the dnf-backed re-check in tests
        cli._save_findings(cfg, [_finding()])
        args = types.SimpleNamespace(
            scan=False, scanner=None, all=False, no_enrich=True, min_severity=None,
            provider=None, model=None, export_script=None, export_ansible=None,
            dry_run=True, yes=False, pdf=None, ignore=None)
        orig = cli.get_provider
        cli.get_provider = lambda *a, **k: Broke()
        buf = io.StringIO()
        try:
            with contextlib.redirect_stderr(buf), contextlib.redirect_stdout(io.StringIO()):
                rc = cli.cmd_fix(cfg, args)
        finally:
            cli.get_provider = orig
        self.assertEqual(rc, 2)                       # systemic failure -> abort
        self.assertIn("credit balance", buf.getvalue())
        self.assertIn("All proposals failed", buf.getvalue())


class TestModelPicker(unittest.TestCase):
    """The setup wizard offers a menu of known model ids so a bad free-text id
    (the 'Sonnet 5' bug) can't be saved and break every remediation."""

    def _pick(self, name, answers):
        import vulnscanai.wizard as W
        it = iter(answers)
        orig = W._ask
        W._ask = lambda prompt="": next(it, "")
        try:
            return W._pick_model(name)
        finally:
            W._ask = orig

    def test_numbered_choice_returns_known_id(self):
        # claude known_models[1] == claude-opus-4-8
        self.assertEqual(self._pick("claude", ["2"]), "claude-opus-4-8")

    def test_blank_means_provider_default(self):
        self.assertEqual(self._pick("claude", [""]), "")

    def test_custom_escape_hatch(self):
        self.assertEqual(self._pick("claude", ["c", "claude-brand-new"]),
                         "claude-brand-new")

    def test_bad_id_falls_back_to_default_not_verbatim(self):
        # The exact regression: 'Sonnet 5' must NOT be accepted as a model id.
        self.assertEqual(self._pick("claude", ["Sonnet 5"]), "")

    def test_out_of_range_falls_back(self):
        self.assertEqual(self._pick("claude", ["99"]), "")

    def test_provider_without_list_is_free_text(self):
        # 'local' has no known_models -> free-text prompt, returned verbatim.
        self.assertEqual(self._pick("local", ["llama3.2:1b"]), "llama3.2:1b")

    def test_all_cloud_defaults_are_in_their_known_list(self):
        from vulnscanai.ai import PROVIDERS
        for name in ("claude", "openai", "gemini", "kimi", "deepseek", "mistral"):
            cls = PROVIDERS[name]
            self.assertIn(cls.default_model, cls.known_models,
                          f"{name} default not in known_models")


class TestClaudeEffort(unittest.TestCase):
    def _run(self, **kw):
        import vulnscanai.ai.claude as C
        captured = {}

        def fake_post(url, payload, headers=None, timeout=None):
            captured.update(payload)
            return {"content": [{"type": "text", "text": '{"summary": "x"}'}]}

        orig = C.http.post_json
        C.http.post_json = fake_post
        try:
            p = C.ClaudeProvider(**kw)
            p.api_key = "test"          # bypass the key check
            out = p.complete("sys", "user")
        finally:
            C.http.post_json = orig
        return captured, out

    def test_effort_adds_output_config_and_thinking(self):
        cap, out = self._run(model="claude-opus-4-8", effort="max")
        self.assertEqual(cap["output_config"], {"effort": "max"})
        self.assertEqual(cap["thinking"], {"type": "adaptive"})
        self.assertEqual(cap["max_tokens"], 8000)
        self.assertIn("summary", out)

    def test_no_effort_is_plain_request(self):
        cap, _ = self._run(model="claude-sonnet-4-6")
        self.assertNotIn("output_config", cap)
        self.assertNotIn("thinking", cap)
        self.assertEqual(cap["max_tokens"], 2048)

    def test_get_provider_threads_effort(self):
        from vulnscanai.ai import get_provider
        self.assertEqual(get_provider("claude", "claude-opus-4-8",
                                      effort="high").effort, "high")
        # other providers accept the kwarg and simply ignore it
        self.assertEqual(get_provider("openai", effort="high").effort, "high")

    def test_every_provider_accepts_effort(self):
        # Regression: a provider that overrides __init__ (e.g. local) must still
        # accept the effort kwarg get_provider passes, or it 500s / crashes.
        from vulnscanai.ai import PROVIDERS, get_provider
        for name in PROVIDERS:
            self.assertEqual(get_provider(name, effort="high").effort, "high",
                             f"provider {name} dropped effort")


class TestSeveritySummary(unittest.TestCase):
    def test_summary_counts_and_order(self):
        from vulnscanai.cli import _severity_summary
        fs = [_finding(severity="critical"),
              _finding(severity="critical", cve_ids=["CVE-2026-9"]),
              _finding(severity="low", package="x")]
        s = _severity_summary(fs)
        self.assertIn("CRIT 2", s)
        self.assertIn("LOW 1", s)
        self.assertLess(s.index("CRIT"), s.index("LOW"))   # highest first
        self.assertNotIn("\033", s)                        # no colour by default

    def test_summary_colour(self):
        from vulnscanai.cli import _severity_summary
        sc = _severity_summary([_finding(severity="important")], color=True)
        self.assertIn("\033[", sc)
        self.assertTrue(sc.endswith("\033[0m"))

    def test_summary_empty(self):
        from vulnscanai.cli import _severity_summary
        self.assertEqual(_severity_summary([]), "")


class TestWebrootScanner(unittest.TestCase):
    def test_classify(self):
        from vulnscanai.scanners.webroot import classify
        self.assertEqual(classify("backup.sql")[1], "important")
        self.assertEqual(classify("data.sqlite")[0], "database dump / data")
        self.assertEqual(classify(".env")[1], "critical")
        self.assertEqual(classify(".env.production")[1], "critical")
        self.assertEqual(classify("wp-config.php")[1], "important")
        self.assertEqual(classify("id_rsa")[1], "critical")
        self.assertEqual(classify("server.key")[1], "critical")
        self.assertEqual(classify("site.bak")[1], "moderate")
        self.assertEqual(classify("dump.tar.gz")[1], "moderate")
        self.assertEqual(classify("error.log")[1], "low")
        self.assertIsNone(classify("index.php"))
        self.assertIsNone(classify("style.css"))

    def test_parsers(self):
        from vulnscanai.scanners import webroot as W
        self.assertEqual(W.parse_nginx_roots("server {\n root /var/www/html;\n}"),
                         ["/var/www/html"])
        self.assertEqual(W.parse_apache_roots('DocumentRoot "/srv/www/a"'),
                         ["/srv/www/a"])
        self.assertEqual(W.parse_lighttpd_roots('server.document-root = "/srv/h"'),
                         ["/srv/h"])
        self.assertEqual(W.parse_litespeed_roots("docRoot /var/www/ls"),
                         ["/var/www/ls"])

    def test_audit_root(self):
        from vulnscanai.scanners.webroot import audit_root
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "index.php"), "w").close()       # normal
            open(os.path.join(d, "backup.sql"), "w").close()      # db dump
            open(os.path.join(d, ".env"), "w").close()            # secrets
            os.makedirs(os.path.join(d, ".git"))
            open(os.path.join(d, ".git", "config"), "w").close()  # must NOT descend
            ww = os.path.join(d, "page.html")
            open(ww, "w").close()
            os.chmod(ww, 0o666)                                   # world-writable
            cats = {f.raw["category"] for f in audit_root(d, "nginx")}
            self.assertIn("database dump / data", cats)
            self.assertIn("environment secrets", cats)
            self.assertIn("version-control directory", cats)
            self.assertIn("world-writable file", cats)
            # The .git/config file itself is not separately reported (pruned).
            paths = [f.raw["path"] for f in audit_root(d, "nginx")]
            self.assertFalse(any(p.endswith(".git/config") for p in paths))

    def test_registered(self):
        from vulnscanai.scanners import SCANNERS
        self.assertIn("webroot", SCANNERS)


class TestRemediationSanitize(unittest.TestCase):
    """propose() must clean up weak-model output: placeholder echoes, a bogus
    restart_mode, hallucinated transactional scaffolding on package fixes, and
    invented advisory ids."""

    class _FakeProvider:
        name = "fake"
        model = "fake"

        def __init__(self, payload):
            self._payload = payload

        def complete(self, system, user):
            return self._payload

    def _propose(self, payload, **finding_kw):
        from vulnscanai.remediation import propose
        f = _finding(**finding_kw)
        return propose(self._FakeProvider(payload), f)

    def test_restart_mode_menu_echo_normalised(self):
        rem = self._propose(
            '{"summary":"x","restart_mode":"reload|restart|none",'
            '"service":"sshd","validate_cmd":"sshd -t",'
            '"backup_paths":["/etc/ssh/sshd_config"]}',
            source="ssh", title="weak sshd")
        self.assertEqual(rem.restart_mode, "none")   # junk -> none, not skipped silently

    def test_placeholder_verification_dropped(self):
        rem = self._propose(
            '{"summary":"x","verification":"command to confirm the fix"}',
            source="dnf", title="pkg")
        # "command to confirm the fix" isn't a real command -> dropped
        self.assertIsNone(rem.verification)

    def test_angle_placeholder_echo_dropped(self):
        rem = self._propose(
            '{"summary":"<one-line summary>","verification":"<command>"}',
            source="dnf", title="pkg")
        self.assertEqual(rem.summary, "")
        self.assertIsNone(rem.verification)

    def test_nonexistent_validate_cmd_dropped(self):
        rem = self._propose(
            '{"summary":"x","validate_cmd":"validate nginx version"}',
            source="ssh", title="cfg")
        self.assertIsNone(rem.validate_cmd)          # not a real executable

    def test_package_finding_strips_transactional_scaffolding(self):
        # The urllib3 case: a dnf finding must not carry sshd backups/validate.
        rem = self._propose(
            '{"summary":"update urllib3","commands":["dnf update -y python3-urllib3"],'
            '"backup_paths":["/etc/ssh/sshd_config","/etc/httpd/conf.d/httpd.conf"],'
            '"validate_cmd":"systemctl restart sshd","service":"sshd",'
            '"restart_mode":"restart"}',
            source="dnf", package="python3-urllib3", title="urllib3")
        self.assertEqual(rem.backup_paths, [])
        self.assertIsNone(rem.validate_cmd)
        self.assertIsNone(rem.service)
        self.assertEqual(rem.restart_mode, "none")
        self.assertEqual(rem.commands, ["dnf update -y python3-urllib3"])

    def test_advisory_rewritten_from_finding(self):
        rem = self._propose(
            '{"summary":"x","commands":["dnf update -y --advisory=ALSAA2026:28973"]}',
            source="dnf", title="nginx", advisory="ALSA-2026:28973")
        self.assertEqual(rem.commands,
                         ["dnf update -y --advisory=ALSA-2026:28973"])

    def test_advisory_space_separated_collapsed(self):
        # The real crash: 'No match for argument: RHSA-2026:46333' from a space.
        rem = self._propose(
            '{"summary":"x","commands":'
            '["dnf update -y --advisory=RHSA-2026:46300, RHSA-2026:46333"]}',
            source="dnf", title="kernel", advisory="ALSA-2026:A009")  # malformed
        self.assertEqual(
            rem.commands,
            ["dnf update -y --advisory=RHSA-2026:46300,RHSA-2026:46333"])

    def test_advisory_trailing_flag_preserved(self):
        rem = self._propose(
            '{"summary":"x","commands":["dnf update --advisory=ALSA-2026:5 -y"]}',
            source="dnf", title="x", advisory="ALSA-2026:5")
        self.assertEqual(rem.commands, ["dnf update --advisory=ALSA-2026:5 -y"])

    def test_null_list_fields_do_not_crash(self):
        # qwen2.5:0.5b returned "config_changes": null; dict.get(k, []) returns
        # None (not []) when the key is present-but-null, which crashed propose().
        rem = self._propose(
            '{"summary":"x","commands":null,"config_changes":null,'
            '"backup_paths":null,"rollback_commands":null,"risk":null}',
            source="dnf", title="coreutils")
        self.assertEqual(rem.commands, [])
        self.assertEqual(rem.config_changes, [])
        self.assertEqual(rem.backup_paths, [])
        self.assertEqual(rem.rollback_commands, [])
        self.assertEqual(rem.risk, "unknown")

    def test_scalar_command_tolerated(self):
        # A model that returns a single command as a string, not a list.
        rem = self._propose('{"summary":"x","commands":"dnf update -y bash"}',
                            source="dnf", title="bash")
        self.assertEqual(rem.commands, ["dnf update -y bash"])

    def test_config_finding_keeps_valid_scaffolding(self):
        # validate_cmd is "true" (a binary present everywhere, incl. the minimal
        # CI/build container) standing in for a real validator like `sshd -t`;
        # the point is that a config-source finding keeps its scaffolding.
        rem = self._propose(
            '{"summary":"harden","commands":["sed -i s/a/b/ /etc/ssh/sshd_config"],'
            '"backup_paths":["/etc/ssh/sshd_config"],"validate_cmd":"true",'
            '"service":"sshd","restart_mode":"reload"}',
            source="ssh", title="sshd")
        self.assertEqual(rem.backup_paths, ["/etc/ssh/sshd_config"])
        self.assertEqual(rem.restart_mode, "reload")
        self.assertEqual(rem.service, "sshd")
        self.assertEqual(rem.validate_cmd, "true")


class TestContainerScanner(unittest.TestCase):
    def test_classify_mount(self):
        from vulnscanai.scanners.container import classify_mount
        # runtime control socket == host takeover
        self.assertEqual(
            classify_mount("/var/run/docker.sock", True)[1], "critical")
        self.assertEqual(
            classify_mount("/run/podman/podman.sock", False)[1], "critical")
        # whole root fs
        self.assertEqual(classify_mount("/", True)[1], "critical")
        # /etc writable critical, read-only downgraded to important
        self.assertEqual(classify_mount("/etc", True)[1], "critical")
        self.assertEqual(classify_mount("/etc/pki", False)[1], "important")
        # most-specific prefix wins (/var/lib/containers over /)
        self.assertEqual(
            classify_mount("/var/lib/containers/storage", True)[1], "critical")
        # benign app data is ignored
        self.assertIsNone(classify_mount("/srv/app/data", True))
        self.assertIsNone(classify_mount("/var/lib/myapp", True))

    def test_privileged_and_socket(self):
        from vulnscanai.scanners.container import assess_container
        info = {
            "Name": "/web", "Id": "abc123def456",
            "Config": {"Image": "nginx:latest", "User": "nginx"},
            "HostConfig": {"Privileged": True},
            "Mounts": [{"Type": "bind", "Source": "/var/run/docker.sock",
                        "Destination": "/var/run/docker.sock", "RW": True}],
        }
        findings = assess_container(info, "podman")
        issues = {f.raw["issue"] for f in findings}
        self.assertIn("privileged", issues)
        self.assertIn("mount", issues)
        sevs = {f.raw["issue"]: f.severity for f in findings}
        self.assertEqual(sevs["privileged"], "critical")
        for f in findings:
            self.assertEqual(f.source, "container")
            self.assertEqual(f.raw["container"], "web")
            self.assertIn("recommended", f.raw)
        # distinct ids
        self.assertEqual(len({f.id for f in findings}), len(findings))

    def test_namespaces_caps_secopt(self):
        from vulnscanai.scanners.container import assess_container
        info = {
            "Name": "app", "Id": "f00",
            "Config": {"Image": "img", "User": ""},   # root
            "HostConfig": {
                "NetworkMode": "host", "PidMode": "host", "IpcMode": "host",
                "CapAdd": ["CAP_SYS_ADMIN", "NET_RAW"],
                "SecurityOpt": ["seccomp=unconfined", "label=disable"],
            },
        }
        issues = {f.raw["issue"] for f in assess_container(info)}
        self.assertEqual(
            {"network_host", "pid_host", "ipc_host", "capability",
             "seccomp_unconfined", "selinux_disabled", "runs_as_root"} <= issues,
            True)

    def test_cap_all_collapses(self):
        from vulnscanai.scanners.container import assess_container
        info = {"Name": "x", "Id": "1", "Config": {"User": "app"},
                "HostConfig": {"CapAdd": ["ALL", "SYS_ADMIN"]}}
        issues = [f.raw["issue"] for f in assess_container(info)]
        self.assertIn("cap_all", issues)
        self.assertNotIn("capability", issues)   # individual caps not re-listed

    def test_readonly_mount_downgraded(self):
        from vulnscanai.scanners.container import assess_container
        info = {"Name": "x", "Id": "1", "Config": {"User": "app"},
                "HostConfig": {"Binds": ["/etc:/host-etc:ro"]}}
        f = [x for x in assess_container(info) if x.raw["issue"] == "mount"][0]
        self.assertEqual(f.severity, "important")   # ro downgrade from critical
        self.assertFalse(f.raw["rw"])

    def test_clean_container_no_findings(self):
        from vulnscanai.scanners.container import assess_container
        info = {
            "Name": "safe", "Id": "1",
            "Config": {"Image": "img", "User": "1000:1000"},
            "HostConfig": {
                "Privileged": False, "NetworkMode": "bridge",
                "CapAdd": [], "SecurityOpt": [],
                "Binds": ["/srv/app/data:/data:rw"],
            },
            "Mounts": [{"Type": "bind", "Source": "/srv/app/data",
                        "Destination": "/data", "RW": True}],
        }
        self.assertEqual(assess_container(info), [])

    def test_registered(self):
        from vulnscanai.scanners import SCANNERS
        self.assertIn("container", SCANNERS)


class TestFeedsParsers(unittest.TestCase):
    def test_parse_kev(self):
        data = {"vulnerabilities": [
            {"cveID": "CVE-2026-9256", "vendorProject": "F5", "product": "nginx",
             "vulnerabilityName": "nginx RCE", "dateAdded": "2026-06-20",
             "shortDescription": "allows RCE", "knownRansomwareCampaignUse": "Known"},
            {"cveID": "CVE-2026-1", "dateAdded": "2026-06-25"}]}
        items = feeds.parse_kev(data)
        self.assertEqual(items[0].published, "2026-06-25")   # newest first
        kev = [i for i in items if i.cve_ids == ["CVE-2026-9256"]][0]
        self.assertTrue(kev.exploited)
        self.assertEqual(kev.source, "kev")
        self.assertTrue(kev.summary.startswith("[known ransomware use]"))

    def test_parse_nvd_severity(self):
        data = {"vulnerabilities": [{"cve": {
            "id": "CVE-2026-2", "published": "2026-06-29T00:00:00",
            "descriptions": [{"lang": "en", "value": "heap overflow"}],
            "metrics": {"cvssMetricV31": [{"cvssData":
                {"baseSeverity": "HIGH", "baseScore": 8.1}}]}}}]}
        it = feeds.parse_nvd(data)[0]
        self.assertEqual(it.severity, "important")     # HIGH -> important
        self.assertEqual(it.cve_ids, ["CVE-2026-2"])
        self.assertEqual(it.published, "2026-06-29")

    def test_parse_epss(self):
        scores = feeds.parse_epss({"data": [
            {"cve": "CVE-2021-44228", "epss": "0.97"},
            {"cve": "bad", "epss": "n/a"}]})
        self.assertEqual(scores, {"CVE-2021-44228": 0.97})

    def test_parse_errata_rss(self):
        rss = ('<rss><channel><item>'
               '<title>ALSA-2026:289 Important: nginx security update</title>'
               '<link>https://errata.almalinux.org/9/ALSA-2026-289.html</link>'
               '<description>Fixes CVE-2026-9256</description>'
               '<pubDate>Mon, 29 Jun 2026 12:00:00 +0000</pubDate>'
               '</item></channel></rss>')
        it = feeds.parse_errata_rss(rss, "alma")[0]
        self.assertEqual(it.severity, "important")
        self.assertEqual(it.published, "2026-06-29")
        self.assertIn("CVE-2026-9256", it.cve_ids)

    def test_parse_errata_rss_malformed(self):
        self.assertEqual(feeds.parse_errata_rss("not xml", "alma"), [])

    def test_parse_rocky_apollo(self):
        data = {"advisories": [
            {"name": "RLSA-2026:30851", "synopsis": "Important: perl update",
             "severity": "SEVERITY_IMPORTANT", "publishedAt": "2026-06-29T12:00:00Z",
             "affectedProducts": ["Rocky Linux 9"], "topic": "update perl",
             "cves": [{"name": "CVE-2026-42496"}]},
            {"name": "RLSA-2026:1", "severity": "SEVERITY_LOW",
             "publishedAt": "2026-06-01T00:00:00Z",
             "affectedProducts": ["Rocky Linux 8"], "cves": []}]}
        nine = feeds.parse_rocky_apollo(data, "9")
        self.assertEqual(len(nine), 1)               # el8 one filtered out
        it = nine[0]
        self.assertEqual(it.source, "rocky")
        self.assertEqual(it.severity, "important")   # SEVERITY_IMPORTANT mapped
        self.assertEqual(it.cve_ids, ["CVE-2026-42496"])
        self.assertTrue(it.url.endswith("RLSA-2026:30851"))
        self.assertEqual(len(feeds.parse_rocky_apollo(data, "")), 2)  # no filter

    def test_parse_oracle_oval(self):
        ov = ('<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/'
              'oval-definitions-5"><definitions>'
              '<definition class="patch"><metadata>'
              '<title>ELSA-2026-24722:  libsoup security update (MODERATE)</title>'
              '<affected family="unix"><platform>Oracle Linux 9</platform></affected>'
              '<reference source="elsa" ref_id="ELSA-2026-24722" '
              'ref_url="https://linux.oracle.com/errata/ELSA-2026-24722.html"/>'
              '<reference source="CVE" ref_id="CVE-2026-5119" ref_url="x"/>'
              '<advisory><severity>MODERATE</severity><issued date="2026-06-29"/>'
              '</advisory></metadata></definition>'
              '<definition class="patch"><metadata>'
              '<title>ELSA-2026-1: kernel (IMPORTANT)</title>'
              '<affected family="unix"><platform>Oracle Linux 7</platform></affected>'
              '<reference source="elsa" ref_id="ELSA-2026-1" ref_url="y"/>'
              '<advisory><severity>IMPORTANT</severity><issued date="2026-06-01"/>'
              '</advisory></metadata></definition>'
              '</definitions></oval_definitions>')
        nine = feeds.parse_oracle_oval(ov, "9")
        self.assertEqual(len(nine), 1)               # el7 one filtered out
        it = nine[0]
        self.assertEqual(it.source, "oracle")
        self.assertEqual(it.severity, "moderate")
        self.assertEqual(it.cve_ids, ["CVE-2026-5119"])
        self.assertTrue(it.url.endswith("ELSA-2026-24722.html"))
        self.assertEqual(len(feeds.parse_oracle_oval(ov, "")), 2)  # no filter

    def test_oracle_oval_doctype_rejected(self):
        bomb = ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]>'
                '<oval_definitions><definitions></definitions></oval_definitions>')
        self.assertEqual(feeds.parse_oracle_oval(bomb, "9"), [])

    def test_dedupe_prefers_exploited(self):
        nvd = feeds.NewsItem(id="nvd:CVE-1", source="nvd", title="x",
                             cve_ids=["CVE-1"])
        kev = feeds.NewsItem(id="kev:CVE-1", source="kev", title="x",
                             cve_ids=["CVE-1"], exploited=True)
        merged = feeds._dedupe([nvd, kev])
        self.assertEqual(len(merged), 1)
        self.assertTrue(merged[0].exploited)

    def test_cache_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Config(state_dir=tmp)
            items = [feeds.NewsItem(id="kev:CVE-1", source="kev", title="t",
                                    cve_ids=["CVE-1"], exploited=True, epss=0.9)]
            feeds.save_cache(cfg, items, "2026-06-30 10:00 UTC")
            got, when = feeds.load_cache(cfg)
            self.assertEqual(when, "2026-06-30 10:00 UTC")
            self.assertEqual(got[0].cve_ids, ["CVE-1"])
            self.assertTrue(got[0].exploited)
            self.assertEqual(got[0].epss, 0.9)
            self.assertEqual(oct(os.stat(feeds._cache_path(cfg)).st_mode & 0o777),
                             "0o600")


class TestPatchedFilter(unittest.TestCase):
    def test_parse_check_update(self):
        from vulnscanai.scanners.applicability import parse_check_update
        out = ("Last metadata expiration check: 0:07 ago.\n\n"
               "bash.x86_64        5.1.8-9.el9    baseos\n"
               "python3.11.x86_64  3.11.5-1.el9   appstream\n\n"
               "Obsoleting Packages\n"
               "oldpkg.noarch      1.0-1          repo\n")
        self.assertEqual(parse_check_update(out), {"bash", "python3.11"})

    def test_filter_drops_already_patched_only(self):
        from vulnscanai.scanners.applicability import PatchedStateEnricher
        from vulnscanai.models import apply_patched_states
        enr = PatchedStateEnricher(Config())
        enr.upgradable = lambda: {"bash"}            # only bash has an update
        enr.actionable_advisories = lambda: {"ALSA-2026:2"}   # only :2 actionable
        findings = [
            Finding(source="oscap", package="kernel", advisory="ALSA-2026:1",
                    cve_ids=["CVE-1"], severity="important"),     # patched -> drop
            Finding(source="dnf", package="bash", advisory="ALSA-2026:2",
                    fixed_version="5.1.8-9", severity="important"),  # real -> keep
            Finding(source="dnf", package="openssl", advisory="ALSA-2026:3",
                    vendor_fix_state="will not fix", severity="moderate"),  # keep
            Finding(source="ssh", package=None, title="SSH root login",
                    severity="important")]                         # not a pkg -> keep
        enr.enrich(findings)
        kept, dropped = apply_patched_states(findings)
        self.assertEqual(dropped, 1)
        self.assertEqual({f.package or f.title for f in kept},
                         {"bash", "openssl", "SSH root login"})

    def test_oscap_finding_dropped_by_advisory(self):
        # oscap findings carry an advisory but NO package — the bug fix: match on
        # the advisory against the actionable set.
        from vulnscanai.scanners.applicability import PatchedStateEnricher
        from vulnscanai.models import apply_patched_states
        enr = PatchedStateEnricher(Config())
        enr.upgradable = lambda: set()
        enr.actionable_advisories = lambda: {"ALSA-2026:9"}
        findings = [
            Finding(source="oscap", package=None, advisory="ALSA-2026:25217",
                    cve_ids=["CVE-1"], severity="important"),     # not actionable -> drop
            Finding(source="oscap", package=None, advisory="ALSA-2026:9",
                    cve_ids=["CVE-2"], severity="important")]     # actionable -> keep
        enr.enrich(findings)
        kept, dropped = apply_patched_states(findings)
        self.assertEqual(dropped, 1)
        self.assertEqual([f.advisory for f in kept], ["ALSA-2026:9"])

    def test_filter_noop_when_signals_unknown(self):
        from vulnscanai.scanners.applicability import PatchedStateEnricher
        from vulnscanai.models import apply_patched_states
        enr = PatchedStateEnricher(Config())
        enr.upgradable = lambda: None                # both signals unavailable
        enr.actionable_advisories = lambda: None     # -> drop nothing
        f = Finding(source="dnf", package="kernel", advisory="ALSA-2026:1",
                    severity="important")
        enr.enrich([f])
        self.assertFalse(f.already_patched)
        self.assertEqual(apply_patched_states([f]), ([f], 0))

    def test_parse_updateinfo_advisories(self):
        from vulnscanai.scanners.applicability import parse_updateinfo_advisories
        out = ("Last metadata expiration check: 0:01 ago.\n"
               "ALSA-2026:25217 Important/Sec. kernel-5.14.x.rpm\n"
               "RHSA-2026:9 Moderate/Sec.  bash-5.1.rpm\n")
        self.assertEqual(parse_updateinfo_advisories(out),
                         {"ALSA-2026:25217", "RHSA-2026:9"})


class TestBaselineIgnoreAction(unittest.TestCase):
    def test_ignore_persists_and_round_trips(self):
        from vulnscanai.cli import _baseline_ignore
        f = _finding(source="ssh", package=None, cve_ids=[], advisory=None,
                     title="SSH permits direct root login")
        other = _finding(source="ssh", package=None, cve_ids=[], advisory=None,
                         title="SSH X11 forwarding enabled")
        with tempfile.TemporaryDirectory() as home:
            old = os.environ.get("HOME")
            os.environ["HOME"] = home
            try:
                path = _baseline_ignore(f)
                with open(path) as fh:
                    content = fh.read()
                mode = oct(os.stat(path).st_mode & 0o777)
            finally:
                if old is not None:
                    os.environ["HOME"] = old
                else:
                    os.environ.pop("HOME", None)
        self.assertIn(f.id, content)
        self.assertIn("SSH permits direct root login", content)  # readable comment
        self.assertEqual(mode, "0o600")
        patterns = content.splitlines()
        self.assertTrue(match_ignore(f, patterns))       # the ignored one matches
        self.assertFalse(match_ignore(other, patterns))  # a different one does not


class TestOvalAutoUpdate(unittest.TestCase):
    def test_stale_when_missing_then_fresh_then_old(self):
        from vulnscanai.scanners.oval import (
            is_oval_stale, oval_age_days, staged_oval_path)
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Config(state_dir=tmp)
            # Not staged -> stale, age None.
            self.assertIsNone(oval_age_days(cfg))
            self.assertTrue(is_oval_stale(cfg, 7))
            # Stage a fresh feed.
            path = staged_oval_path(cfg)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write("<oval/>")
            self.assertFalse(is_oval_stale(cfg, 7))
            self.assertLess(oval_age_days(cfg), 1)
            # Backdate it 10 days -> stale again.
            old = time.time() - 10 * 86400
            os.utime(path, (old, old))
            self.assertTrue(is_oval_stale(cfg, 7))
            self.assertFalse(is_oval_stale(cfg, 30))   # within a 30-day window


class TestExploitEnrichment(unittest.TestCase):
    def test_exploited_raised_to_important(self):
        f = _finding(source="dnf", severity="moderate", cve_ids=["CVE-1"])
        f.exploited = True
        out, raised = apply_exploit_priority([f])
        self.assertEqual(raised, 1)
        self.assertEqual(f.severity, "important")
        self.assertEqual(f.raw["severity_before_exploit"], "moderate")
        self.assertIn("[exploited]", f.description)

    def test_exploited_high_severity_not_lowered(self):
        f = _finding(severity="critical", cve_ids=["CVE-1"])
        f.exploited = True
        apply_exploit_priority([f])
        self.assertEqual(f.severity, "critical")    # never downgraded

    def test_epss_annotated_not_raised(self):
        f = _finding(severity="low", cve_ids=["CVE-1"])
        f.epss = 0.8
        out, raised = apply_exploit_priority([f])
        self.assertEqual(raised, 0)
        self.assertEqual(f.severity, "low")         # EPSS never raises severity
        self.assertIn("[epss]", f.description)

    def test_enricher_sets_fields(self):
        # Stub the network lookups so the test stays offline.
        f = _finding(cve_ids=["CVE-2021-44228"])
        orig_kev, orig_epss = feeds.kev_cve_set, feeds.epss_scores
        feeds.kev_cve_set = lambda cfg: {"CVE-2021-44228"}
        feeds.epss_scores = lambda cves, cfg: {"CVE-2021-44228": 0.97}
        try:
            from vulnscanai.scanners.exploit import ExploitEnricher
            ExploitEnricher(Config()).enrich([f])
        finally:
            feeds.kev_cve_set, feeds.epss_scores = orig_kev, orig_epss
        self.assertTrue(f.exploited)
        self.assertEqual(f.epss, 0.97)


class TestNewsRender(unittest.TestCase):
    def _items(self):
        return [
            feeds.NewsItem(id="kev:CVE-9", source="kev", title="nginx RCE",
                           severity="important", url="https://x",
                           cve_ids=["CVE-2026-9256"], exploited=True, epss=0.97),
            feeds.NewsItem(id="nvd:CVE-1", source="nvd",
                           title="bug <script>alert(1)</script>",
                           severity="moderate", url="https://y",
                           summary="oops <img src=x>", cve_ids=["CVE-2026-1"])]

    def test_escapes_feed_content(self):
        html = dashboard.render_news(self._items(), "now", "host")
        self.assertNotIn("<script>alert", html)
        self.assertIn("&lt;script&gt;", html)

    def test_badges_and_relevance(self):
        html = dashboard.render_news(self._items(), "now", "host",
                                     relevant_cves={"CVE-2026-9256"})
        self.assertIn("EXPLOITED", html)
        self.assertIn("ON THIS HOST", html)
        self.assertIn("Relevant to this host", html)

    def test_source_filter(self):
        html = dashboard.render_news(self._items(), "now", "host",
                                     source_filter="kev")
        self.assertIn("nginx RCE", html)
        self.assertNotIn("CVE-2026-1", html)        # nvd item filtered out

    def test_disabled_state(self):
        html = dashboard.render_news(self._items(), "", "host", enabled=False)
        self.assertIn("news_enabled", html)


class TestMenu(unittest.TestCase):
    """The interactive menu turns choices into the same argv the CLI parses."""

    def setUp(self):
        from vulnscanai import menu
        self.menu = menu
        # Snapshot the interactive helpers so each test can stub them safely.
        self._orig = {n: getattr(menu, n) for n in
                      ("_choose", "_multi_choose", "_ask", "_ask_yesno")}

    def tearDown(self):
        for n, fn in self._orig.items():
            setattr(self.menu, n, fn)

    def _stub(self, *, choose=(), multi=(), ask=(), yesno=()):
        """Replace the menu's interactive helpers with scripted queues."""
        cq, mq, aq, yq = list(choose), list(multi), list(ask), list(yesno)
        self.menu._choose = lambda *a, **k: cq.pop(0)
        self.menu._multi_choose = lambda *a, **k: mq.pop(0)
        self.menu._ask = lambda *a, **k: aq.pop(0)
        self.menu._ask_yesno = lambda *a, **k: yq.pop(0)

    def _parses(self, argv):
        """Assert the built argv is accepted by the real CLI parser."""
        from vulnscanai.cli import build_parser
        args = build_parser().parse_args(argv)
        self.assertTrue(hasattr(args, "func"))
        return args

    def test_scan_all_default_enrich(self):
        self._stub(choose=["all", None], ask=[""], yesno=[True])
        argv = self.menu._b_scan(Config())
        self.assertEqual(argv, ["scan", "--all"])
        self._parses(argv)

    def test_scan_choose_scanners_and_severity_no_enrich(self):
        self._stub(choose=["choose", "important"],
                   multi=[["dnf", "ssh"]], ask=["/tmp/r.pdf"], yesno=[False])
        argv = self.menu._b_scan(Config())
        self.assertEqual(argv, ["scan", "--scanner", "dnf", "--scanner", "ssh",
                                "--min-severity", "important",
                                "--no-enrich", "--pdf", "/tmp/r.pdf"])
        self._parses(argv)

    def test_scan_cancel_at_scanners(self):
        self._stub(choose=[self.menu._CANCEL])
        self.assertIsNone(self.menu._b_scan(Config()))

    def test_fix_scan_then_export_ansible(self):
        self._stub(choose=["scan", "all", None, "ansible"],
                   ask=["play.yml"])
        argv = self.menu._b_fix(Config())
        self.assertEqual(argv, ["fix", "--scan", "--all",
                                "--export-ansible", "play.yml"])
        self._parses(argv)

    def test_fix_auto_requires_confirmation(self):
        # Decline the "really auto-apply?" guard -> the action is abandoned.
        self._stub(choose=["saved", None, "auto"], yesno=[False])
        self.assertIsNone(self.menu._b_fix(Config()))

    def test_fix_auto_confirmed(self):
        self._stub(choose=["saved", None, "auto"], yesno=[True])
        argv = self.menu._b_fix(Config())
        self.assertEqual(argv, ["fix", "--yes"])
        self._parses(argv)

    def test_rollback_list_and_id(self):
        self._stub(choose=["list"])
        self.assertEqual(self.menu._b_rollback(Config()), ["rollback", "--list"])
        self._stub(choose=["id"], ask=["dnf:CVE-1"])
        self.assertEqual(self.menu._b_rollback(Config()),
                         ["rollback", "dnf:CVE-1"])

    def test_report_argv(self):
        self._stub(choose=["critical"], ask=["out.pdf"])
        argv = self.menu._b_report(Config())
        self.assertEqual(argv, ["report", "-o", "out.pdf",
                                "--min-severity", "critical"])
        self._parses(argv)

    def test_news_argv(self):
        self._stub(choose=["distro"], ask=["10"], yesno=[True])
        argv = self.menu._b_news(Config())
        self.assertEqual(argv, ["news", "--source", "distro",
                                "--refresh", "--limit", "10"])
        self._parses(argv)

    def test_dashboard_start_argv(self):
        self._stub(choose=["start", "0.0.0.0"], ask=["8443"])
        argv = self.menu._b_dashboard(Config())
        self.assertEqual(argv, ["dashboard", "--port", "8443",
                                "--bind", "0.0.0.0"])
        self._parses(argv)

    def test_dashboard_allow_argv(self):
        self._stub(choose=["allow"], ask=["10.0.0.0/24"])
        self.assertEqual(self.menu._b_dashboard(Config()),
                         ["dashboard", "--allow", "10.0.0.0/24"])

    def test_dashboard_enable_fix_confirmed(self):
        # Currently disabled -> select the toggle -> confirm the warning.
        self._stub(choose=["fixtoggle"], yesno=[True])
        cfg = Config()
        cfg.dashboard_allow_fix = False
        argv = self.menu._b_dashboard(cfg)
        self.assertEqual(argv, ["dashboard", "--enable-fix"])
        self._parses(argv)

    def test_dashboard_enable_fix_declined(self):
        # Declining the warning abandons the action (no argv).
        self._stub(choose=["fixtoggle"], yesno=[False])
        cfg = Config()
        cfg.dashboard_allow_fix = False
        self.assertIsNone(self.menu._b_dashboard(cfg))

    def test_dashboard_disable_fix_when_enabled(self):
        # When already enabled the toggle offers to disable it.
        self._stub(choose=["fixtoggle"], yesno=[True])
        cfg = Config()
        cfg.dashboard_allow_fix = True
        self.assertEqual(self.menu._b_dashboard(cfg),
                         ["dashboard", "--disable-fix"])

    def test_scheduled_argv(self):
        self._stub(choose=["default", "important"], yesno=[True, False])
        argv = self.menu._b_scheduled(Config())
        self.assertEqual(argv, ["scheduled", "--plan",
                                "--fail-on", "important"])
        self._parses(argv)

    def test_trivial_builders(self):
        for key, expect in (("info", ["info"]), ("providers", ["providers"]),
                            ("setup", ["setup"])):
            self.assertEqual(self.menu._BUILDERS[key](Config()), expect)
            self._parses(expect)

    def test_every_top_entry_has_a_builder(self):
        for _label, key in self.menu._TOP:
            self.assertIn(key, self.menu._BUILDERS)

    def test_numbered_choose_selects(self):
        items = [("a", 1), ("b", 2), ("c", 3)]
        import builtins
        orig = builtins.input
        builtins.input = lambda *_a: "2"
        try:
            self.assertEqual(self.menu._numbered_choose("t", items, None), 2)
        finally:
            builtins.input = orig

    def test_numbered_choose_quit(self):
        import builtins
        orig = builtins.input
        builtins.input = lambda *_a: "q"
        try:
            self.assertIs(self.menu._numbered_choose("t", [("a", 1)], None),
                          self.menu._CANCEL)
        finally:
            builtins.input = orig

    def test_numbered_multi_parses_list(self):
        import builtins
        orig = builtins.input
        builtins.input = lambda *_a: "1, 3"
        try:
            self.assertEqual(
                self.menu._numbered_multi("t", ["dnf", "ssh", "ports"]),
                ["dnf", "ports"])
        finally:
            builtins.input = orig

    def test_run_command_dispatches(self):
        # A real end-to-end: build ['info'] and run it through the parser.
        from vulnscanai.cli import build_parser
        buf = io.StringIO()
        import contextlib
        with contextlib.redirect_stdout(buf):
            self.menu._run_command(Config(), build_parser(), ["info"])
        self.assertIn("vulnscan-ai", buf.getvalue())


# --------------------------------------------------------------------------- #
# compliance benchmark (XCCDF) scanner
# --------------------------------------------------------------------------- #
_XCCDF_NS = "http://checklists.nist.gov/xccdf/1.2"

_DS_RULES = f"""<?xml version="1.0"?>
<Benchmark xmlns="{_XCCDF_NS}" id="xccdf_org.ssgproject.content_benchmark_TEST">
  <Rule id="xccdf_org.ssgproject.content_rule_sshd_disable_root_login" severity="high">
    <title>Disable SSH Root Login</title>
    <ident system="https://nvd.nist.gov/cce/index.cfm">CCE-1001-1</ident>
    <fix system="urn:xccdf:fix:script:sh">sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config</fix>
  </Rule>
  <Rule id="xccdf_org.ssgproject.content_rule_no_empty_passwords" severity="medium">
    <title>Prevent Empty Passwords</title>
    <ident system="https://nvd.nist.gov/cce/index.cfm">CCE-1002-2</ident>
  </Rule>
  <Rule id="xccdf_org.ssgproject.content_rule_package_aide_installed" severity="low">
    <title>Install AIDE</title>
    <fix system="urn:xccdf:fix:script:sh">dnf install -y aide</fix>
  </Rule>
</Benchmark>
"""

_XCCDF_RESULTS = f"""<?xml version="1.0"?>
<Benchmark xmlns="{_XCCDF_NS}" id="b">
  <TestResult id="xccdf_org.open-scap_testresult_test" start-time="2026-07-04T10:00:00">
    <rule-result idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login" severity="high">
      <result>fail</result>
    </rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_no_empty_passwords" severity="medium">
      <result>pass</result>
    </rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_package_aide_installed" severity="low">
      <result>fail</result>
    </rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_orphan_no_meta" severity="low">
      <result>notapplicable</result>
    </rule-result>
    <score system="urn:xccdf:scoring:default" maximum="100.000000">33.333332</score>
  </TestResult>
</Benchmark>
"""

_OSCAP_PROFILES = (
    "xccdf_org.ssgproject.content_profile_cis:CIS AlmaLinux OS 9 Level 2 - Server\n"
    "xccdf_org.ssgproject.content_profile_cis_server_l1:CIS Level 1 - Server\n"
    "xccdf_org.ssgproject.content_profile_stig:DISA STIG for AlmaLinux OS 9\n"
    "xccdf_org.ssgproject.content_profile_pci-dss:PCI-DSS v4.0.1\n"
    "\n"                        # blank line tolerated
    "Some other oscap noise line without a colon-profile\n"
)


class TestComplianceScanner(unittest.TestCase):
    def _write(self, text, suffix=".xml"):
        fd, path = tempfile.mkstemp(suffix=suffix)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    def test_parse_profiles(self):
        from vulnscanai.scanners.compliance import parse_profiles
        got = parse_profiles(_OSCAP_PROFILES)
        ids = [pid for pid, _ in got]
        self.assertIn("xccdf_org.ssgproject.content_profile_stig", ids)
        self.assertEqual(len(got), 4)  # noise/blank lines dropped
        title = dict(got)["xccdf_org.ssgproject.content_profile_cis"]
        self.assertIn("Level 2", title)

    def test_resolve_profile_alias_suffix_and_id(self):
        from vulnscanai.scanners.compliance import parse_profiles, resolve_profile
        avail = parse_profiles(_OSCAP_PROFILES)
        # friendly alias
        self.assertEqual(resolve_profile("cis-l1", avail),
                         "xccdf_org.ssgproject.content_profile_cis_server_l1")
        self.assertEqual(resolve_profile("stig", avail),
                         "xccdf_org.ssgproject.content_profile_stig")
        self.assertEqual(resolve_profile("pci", avail),
                         "xccdf_org.ssgproject.content_profile_pci-dss")
        # bare suffix
        self.assertEqual(resolve_profile("cis_server_l1", avail),
                         "xccdf_org.ssgproject.content_profile_cis_server_l1")
        # full id passthrough
        full = "xccdf_org.ssgproject.content_profile_stig"
        self.assertEqual(resolve_profile(full, avail), full)
        # unknown
        self.assertIsNone(resolve_profile("nonsense", avail))
        self.assertIsNone(resolve_profile("", avail))

    def test_candidate_datastreams(self):
        from vulnscanai.scanners.compliance import candidate_datastreams
        alma = candidate_datastreams("almalinux", "9")
        self.assertEqual(alma[0], "ssg-almalinux9-ds.xml")
        self.assertIn("ssg-rhel9-ds.xml", alma)   # RHEL-like fallback
        rhel = candidate_datastreams("rhel", "9")
        self.assertEqual(rhel[0], "ssg-rhel9-ds.xml")

    def test_parse_xccdf_rules(self):
        from vulnscanai.scanners.compliance import parse_xccdf_rules
        path = self._write(_DS_RULES)
        rules = parse_xccdf_rules(path)
        rid = "xccdf_org.ssgproject.content_rule_sshd_disable_root_login"
        self.assertIn(rid, rules)
        self.assertEqual(rules[rid]["title"], "Disable SSH Root Login")
        self.assertEqual(rules[rid]["severity"], "important")  # high -> important
        self.assertTrue(rules[rid]["fix_available"])
        self.assertIn("CCE-1001-1", rules[rid]["references"])
        # rule without a fix
        nef = "xccdf_org.ssgproject.content_rule_no_empty_passwords"
        self.assertFalse(rules[nef]["fix_available"])
        self.assertEqual(rules[nef]["severity"], "moderate")   # medium -> moderate

    def test_parse_xccdf_results(self):
        from vulnscanai.scanners.compliance import parse_xccdf_results
        path = self._write(_XCCDF_RESULTS)
        score, results, sevs = parse_xccdf_results(path)
        self.assertAlmostEqual(score, 33.333332, places=3)
        rid = "xccdf_org.ssgproject.content_rule_sshd_disable_root_login"
        self.assertEqual(results[rid], "fail")
        self.assertEqual(sevs[rid], "high")
        self.assertEqual(len(results), 4)

    def test_build_report_counts_and_sorting(self):
        from vulnscanai.scanners.compliance import (
            build_report, parse_xccdf_results, parse_xccdf_rules,
        )
        meta = parse_xccdf_rules(self._write(_DS_RULES))
        score, results, sevs = parse_xccdf_results(self._write(_XCCDF_RESULTS))
        report_obj = build_report(
            "xccdf_org.ssgproject.content_profile_cis", "CIS L2",
            "/path/ssg-almalinux9-ds.xml", meta, score, results, sevs,
            hostname="host1", generated="2026-07-04")
        self.assertEqual(report_obj.datastream, "ssg-almalinux9-ds.xml")
        self.assertEqual(report_obj.fail_count, 2)
        self.assertEqual(report_obj.pass_count, 1)
        self.assertEqual(report_obj.na_count, 1)
        # fails sorted highest severity first (important before low)
        fails = report_obj.fails
        self.assertEqual(fails[0].severity, "important")
        self.assertEqual(fails[-1].severity, "low")
        # orphan result (no benchmark metadata) still gets a readable title
        rid = "xccdf_org.ssgproject.content_rule_orphan_no_meta"
        orphan = next(r for r in report_obj.rules if r.rule_id == rid)
        self.assertEqual(orphan.title, "orphan no meta")

    def test_build_report_excludes_notselected(self):
        from vulnscanai.scanners.compliance import build_report
        # notselected rules are not part of the profile and must not be stored.
        results = {"r_fail": "fail", "r_pass": "pass", "r_off": "notselected"}
        rep = build_report("p", "P", "ds.xml", {}, 50.0, results, {})
        ids = {r.rule_id for r in rep.rules}
        self.assertEqual(ids, {"r_fail", "r_pass"})
        self.assertEqual(rep.fail_count, 1)

    def test_report_roundtrip(self):
        from vulnscanai.models import (
            ComplianceReport, ComplianceRule, compliance_from_json,
            compliance_to_json,
        )
        rep = ComplianceReport(
            profile="p", profile_title="P", datastream="ds.xml", score=87.5,
            rules=[ComplianceRule(rule_id="r1", title="R1", result="fail",
                                  severity="important", fix_available=True,
                                  references=["CCE-1"])],
            hostname="h", generated="g")
        back = compliance_from_json(compliance_to_json(rep))
        self.assertEqual(back.profile, "p")
        self.assertEqual(back.score, 87.5)
        self.assertEqual(len(back.rules), 1)
        self.assertTrue(back.rules[0].fix_available)
        self.assertEqual(back.fail_count, 1)

    def test_write_compliance_report_formats(self):
        from vulnscanai.models import ComplianceReport, ComplianceRule
        from vulnscanai.report import write_compliance_report
        rep = ComplianceReport(
            profile="xccdf_org.ssgproject.content_profile_cis",
            profile_title="CIS L2", datastream="ssg-almalinux9-ds.xml",
            score=42.0, hostname="host1", generated="2026-07-04",
            rules=[ComplianceRule(
                rule_id="xccdf_org.ssgproject.content_rule_sshd_disable_root_login",
                title="Disable SSH Root Login", result="fail",
                severity="important", fix_available=True,
                references=["CCE-1001-1"])])
        tmp = tempfile.mkdtemp()
        # JSON
        jp = os.path.join(tmp, "c.json")
        write_compliance_report(rep, jp)
        with open(jp) as fh:
            doc = json.load(fh)
        self.assertEqual(doc["fail_count"], 1)
        self.assertEqual(doc["score"], 42.0)
        # SARIF
        sp = os.path.join(tmp, "c.sarif")
        write_compliance_report(rep, sp)
        with open(sp) as fh:
            sarif = json.load(fh)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)
        self.assertEqual(sarif["runs"][0]["results"][0]["level"], "error")
        # HTML
        hp = os.path.join(tmp, "c.html")
        write_compliance_report(rep, hp)
        with open(hp) as fh:
            htext = fh.read()
        self.assertIn("Compliance Benchmark Report", htext)
        self.assertIn("Disable SSH Root Login", htext)
        for p in (jp, sp, hp):
            os.remove(p)
        os.rmdir(tmp)

    def test_severity_alias_normalisation(self):
        from vulnscanai.models import XCCDF_SEVERITY_ALIAS
        self.assertEqual(XCCDF_SEVERITY_ALIAS["high"], "important")
        self.assertEqual(XCCDF_SEVERITY_ALIAS["medium"], "moderate")
        self.assertEqual(XCCDF_SEVERITY_ALIAS.get("", "unknown"), "unknown")

    def test_dashboard_compliance_render(self):
        from vulnscanai.models import ComplianceReport, ComplianceRule
        rep = ComplianceReport(
            profile="p", profile_title="CIS L1", datastream="ssg-almalinux9-ds.xml",
            score=63.0, hostname="h", generated="g",
            rules=[
                ComplianceRule(rule_id="r_fail", title="Disable Root SSH",
                               result="fail", severity="important",
                               fix_available=True, references=["CCE-9"]),
                ComplianceRule(rule_id="r_pass", title="ok", result="pass",
                               severity="low"),
            ])
        html_out = dashboard.render_compliance(rep, "h", "2026-07-04 12:00")
        self.assertIn("63%", html_out)
        self.assertIn("CIS L1", html_out)
        self.assertIn("Disable Root SSH", html_out)
        self.assertIn("auto-fix", html_out)
        # empty state
        empty = dashboard.render_compliance(None, "h", "no scan")
        self.assertIn("No compliance scan saved yet", empty)


class TestAudit(unittest.TestCase):
    def _finding(self, applied=True, provider="claude", model="m1"):
        f = Finding(source="dnf", title="openssl flaw", severity="important")
        rem = Remediation(provider=provider, model=model)
        rem.apply_results = [{"command": "dnf -y update openssl", "status": "ok"}]
        rem.applied = applied
        f.remediation = rem
        return f

    def test_record_and_read(self):
        from vulnscanai import audit
        with tempfile.TemporaryDirectory() as d:
            cfg = Config(state_dir=d)
            path = audit.record(cfg, self._finding(), event="apply", source="cli")
            self.assertTrue(os.path.isfile(path))
            self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")
            evs = audit.read(cfg)
            self.assertEqual(len(evs), 1)
            e = evs[0]
            self.assertEqual(e["event"], "apply")
            self.assertEqual(e["source"], "cli")
            self.assertEqual(e["result"], "applied")
            self.assertEqual(e["provider"], "claude")
            self.assertEqual(e["model"], "m1")
            self.assertTrue(e["ts"].endswith("Z"))

    def test_dry_run_not_logged(self):
        from vulnscanai import audit
        with tempfile.TemporaryDirectory() as d:
            cfg = Config(state_dir=d)
            self.assertIsNone(audit.record(cfg, self._finding(),
                                           event="apply", source="cli", dry_run=True))
            self.assertEqual(audit.read(cfg), [])

    def test_failed_and_rollback_results(self):
        from vulnscanai import audit
        with tempfile.TemporaryDirectory() as d:
            cfg = Config(state_dir=d)
            audit.record(cfg, self._finding(applied=False), event="apply", source="cli")
            # restore_backup clears rem.applied -> a rollback reads as rolled-back
            audit.record(cfg, self._finding(applied=False), event="rollback",
                         source="cli", actor="root")
            results = [e["result"] for e in audit.read(cfg)]
            self.assertEqual(results, ["failed", "rolled-back"])
            self.assertEqual(audit.read(cfg)[1]["actor"], "root")

    def test_read_limit_and_corrupt_lines(self):
        from vulnscanai import audit
        with tempfile.TemporaryDirectory() as d:
            cfg = Config(state_dir=d)
            for _ in range(5):
                audit.record(cfg, self._finding(), event="apply", source="cli")
            with open(audit.audit_log_path(cfg), "a", encoding="utf-8") as fh:
                fh.write("this is not json\n")      # must be skipped, not crash
            self.assertEqual(len(audit.read(cfg, limit=2)), 2)
            self.assertEqual(len(audit.read(cfg, limit=0)), 5)  # 0 = all, corrupt dropped

    def test_read_missing_file(self):
        from vulnscanai import audit
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(audit.read(Config(state_dir=d)), [])

    def test_menu_audit_builder(self):
        from vulnscanai import menu
        orig = menu._ask
        menu._ask = lambda *a, **k: "20"
        try:
            self.assertEqual(menu._b_audit(Config()), ["audit", "--limit", "20"])
        finally:
            menu._ask = orig
        from vulnscanai.cli import build_parser
        self.assertTrue(hasattr(build_parser().parse_args(["audit", "--limit", "20"]), "func"))


class TestParserRobustness(unittest.TestCase):
    """Parsers consume external tool/API output, so malformed input must degrade
    (return empty / skip the bad item), never raise. Fuzz the whole battery."""

    BAD_STR = [
        "", "   ", "\n\n\n", chr(0) + chr(1) + chr(2), "no structure here",
        "x" * 50000, "a\tb", "col only", "1 2 3 4 5 6 7 8 9", "None",
        "]]}}{{[[", chr(0x7f) + chr(0x80), "=====", "line\n" + chr(0) + "\n",
    ]
    BAD_DICT = [
        {}, {"x": 1}, {"vulnerabilities": None}, {"vulnerabilities": [None]},
        {"vulnerabilities": [{}]}, {"advisories": [None]}, {"advisories": [{}]},
        {"data": None}, {"epss": None}, [], "notadict", None, 0,
        {"advisories": [{"cves": [None], "name": "X"}]},
    ]

    def test_text_parsers_never_raise(self):
        from vulnscanai.scanners import (ssh_config, applicability, dnf_rhsa,
                                         ports, systemd_security, webroot,
                                         compliance)
        from vulnscanai import feeds
        parsers = [
            ssh_config.parse_sshd_config, applicability.parse_check_update,
            applicability.parse_updateinfo_advisories, dnf_rhsa.parse_nevra,
            ports.parse_ss, systemd_security.parse_security_overview,
            systemd_security.parse_unit_detail, webroot.parse_nginx_roots,
            webroot.parse_apache_roots, webroot.parse_lighttpd_roots,
            webroot.parse_litespeed_roots, compliance.parse_profiles,
        ]
        for fn in parsers:
            for bad in self.BAD_STR:
                try:
                    fn(bad)
                except Exception as e:  # noqa: BLE001
                    self.fail(f"{fn.__module__}.{fn.__name__} raised "
                              f"{type(e).__name__} on {bad!r}: {e}")
        for bad in self.BAD_STR:
            for src in ("alma", "rocky"):
                feeds.parse_errata_rss(bad, src)
            feeds.parse_oracle_oval(bad, "9")

    def test_json_feed_and_container_parsers_never_raise(self):
        from vulnscanai import feeds
        from vulnscanai.scanners import container, ports, nvd
        for bad in self.BAD_DICT:
            feeds.parse_kev(bad)
            feeds.parse_nvd(bad)
            feeds.parse_epss(bad)
            feeds.parse_rocky_apollo(bad, "9")
            ports.parse_nft_ruleset(bad if isinstance(bad, dict) else {})
            container.assess_container(bad, "podman")
            nvd.select_package_state(bad, "9", None)
        # nested-malformed container inspect objects + junk mount sources
        for info in [{"HostConfig": {"Binds": None, "CapAdd": None}},
                     {"HostConfig": {"Binds": "notalist", "Mounts": [None]}},
                     {"HostConfig": {"Mounts": [{"Source": 5, "RW": "x"}]}},
                     {"Id": None, "Config": None, "HostConfig": None}]:
            container.assess_container(info, "podman")
        for src in (None, 123, "", "/var/run/docker.sock"):
            container.classify_mount(src, True)


class TestNeverCrash(unittest.TestCase):
    """The CLI must degrade with a readable message, never a raw traceback, on
    corrupt state/config or an unexpected error deep in a command."""

    def test_config_load_ignores_corrupt_file(self):
        import contextlib
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "config.json")
            open(bad, "w").write("{ this is not json")
            with contextlib.redirect_stderr(io.StringIO()) as err:
                cfg = Config.load(bad)            # must not raise
            self.assertEqual(cfg.provider, "claude")   # fell back to defaults
            self.assertIn("ignoring unreadable config", err.getvalue())

    def test_config_load_ignores_non_object_json(self):
        import contextlib
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "config.json")
            open(bad, "w").write('["a", "list", "not an object"]')
            with contextlib.redirect_stderr(io.StringIO()):
                cfg = Config.load(bad)
            self.assertEqual(cfg.provider, "claude")

    def test_findings_from_json_shape_guard(self):
        self.assertEqual(findings_from_json('{"not": "a list"}'), [])
        # a list with stray non-object entries keeps the good ones
        good = findings_from_json('[{"source": "dnf", "title": "x"}, 5, null, "s"]')
        self.assertEqual(len(good), 1)
        self.assertEqual(good[0].source, "dnf")

    def test_load_findings_on_corrupt_file_degrades(self):
        from vulnscanai.cli import _load_findings
        import contextlib
        with tempfile.TemporaryDirectory() as d:
            cfg = Config(state_dir=d)
            open(cfg.findings_path, "w").write("garbage{not json")
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(_load_findings(cfg), [])   # no raise
            self.assertIn("Could not read findings", err.getvalue())

    def test_load_cache_non_dict_degrades(self):
        from vulnscanai import feeds
        with tempfile.TemporaryDirectory() as d:
            cfg = Config(state_dir=d)
            open(feeds._cache_path(cfg), "w").write('["not", "a", "dict"]')
            self.assertEqual(feeds.load_cache(cfg), ([], ""))

    def test_main_catch_all_no_traceback(self):
        import contextlib
        import vulnscanai.cli as C
        orig = C.cmd_providers
        C.cmd_providers = lambda cfg, args: (_ for _ in ()).throw(
            RuntimeError("boom"))
        os.environ.pop("VULNSCANAI_DEBUG", None)
        try:
            with contextlib.redirect_stderr(io.StringIO()) as err:
                rc = C.main(["--no-banner", "providers"])
            self.assertEqual(rc, 1)
            self.assertIn("unexpected error", err.getvalue())
            # with the debug switch it re-raises for development
            os.environ["VULNSCANAI_DEBUG"] = "1"
            with self.assertRaises(RuntimeError):
                C.main(["--no-banner", "providers"])
        finally:
            C.cmd_providers = orig
            os.environ.pop("VULNSCANAI_DEBUG", None)


if __name__ == "__main__":
    unittest.main()
