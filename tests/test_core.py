"""Dependency-free unit tests (stdlib unittest). Run:  python3 -m unittest -v"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from vulnscanai import export, export_fix, report
from vulnscanai.ai.base import extract_json
from vulnscanai.models import (
    Finding, Remediation, apply_ignores, apply_vendor_states,
    dedup_cross_scanner, findings_from_json, findings_to_json, match_ignore,
    merge_findings, severity_rank,
)
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
from vulnscanai.scanners.ports import audit_ports, classify, parse_ss


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


if __name__ == "__main__":
    unittest.main()
