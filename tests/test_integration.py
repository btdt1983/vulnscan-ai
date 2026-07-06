# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Integration tests: run the REAL external tools on the host and feed their
actual output through the parsers / scanners.

The unit suite is fully mocked, so it cannot catch *parse drift* — a new
`ss`/`systemd-analyze`/`oscap` release changing its output format. These tests
close that gap by exercising the real thing.

They are OPT-IN so the hermetic rpmbuild %check and the CI container stay
deterministic: they only run when ``VULNSCANAI_INTEGRATION=1`` is set, and each
skips individually when its tool (or the relevant host state) is absent. Run on
a real RHEL-family host with:

    VULNSCANAI_INTEGRATION=1 python3 -m unittest tests.test_integration -v

They assert only shape/type and "does not crash" — never host-specific content,
so they are stable across hosts.
"""

import glob
import os
import shutil
import subprocess  # nosec B404 -- this is an integration test that runs tools
import unittest

from vulnscanai.config import Config
from vulnscanai.models import Finding
from vulnscanai.scanners import (SCANNERS, ports, systemd_security, ssh_config,
                                 compliance)

_INTEGRATION = bool(os.environ.get("VULNSCANAI_INTEGRATION"))
_reason = "set VULNSCANAI_INTEGRATION=1 to run integration tests"


def _run(cmd, timeout=60):
    return subprocess.run(cmd, capture_output=True, text=True,  # nosec B603
                          timeout=timeout, check=False)


@unittest.skipUnless(_INTEGRATION, _reason)
class TestRealToolParsing(unittest.TestCase):
    @unittest.skipUnless(shutil.which("ss"), "ss not installed")
    def test_parse_ss_real_output(self):
        out = _run(["ss", "-H", "-tuln"]).stdout
        socks = ports.parse_ss(out)
        self.assertIsInstance(socks, list)
        for s in socks:                       # every parsed socket is well-formed
            self.assertIsInstance(s.get("port"), int)

    @unittest.skipUnless(shutil.which("systemd-analyze"), "no systemd-analyze")
    def test_parse_security_overview_real(self):
        r = _run(["systemd-analyze", "security", "--no-pager"])
        if r.returncode != 0 or not r.stdout.strip():
            self.skipTest("systemd-analyze security unavailable (no running systemd?)")
        rows = systemd_security.parse_security_overview(r.stdout)
        self.assertIsInstance(rows, list)
        for unit, exposure, pred in rows:
            self.assertTrue(unit)
            self.assertIsInstance(exposure, float)
            self.assertNotEqual(unit, "UNIT")   # header row was skipped

    def test_parse_sshd_config_real_file(self):
        path = "/etc/ssh/sshd_config"
        if not os.path.isfile(path):
            self.skipTest("no sshd_config on this host")
        with open(path, encoding="utf-8", errors="replace") as fh:
            cfg = ssh_config.parse_sshd_config(fh.read())
        self.assertIsInstance(cfg, dict)
        # audit must produce well-formed findings from real config
        for f in ssh_config.audit_sshd_config(cfg):
            self.assertEqual(f.source, "ssh")
            self.assertTrue(f.id)

    @unittest.skipUnless(shutil.which("oscap"), "oscap not installed")
    def test_parse_profiles_real_ssg(self):
        ds = glob.glob("/usr/share/xml/scap/ssg/content/ssg-*-ds.xml")
        if not ds:
            self.skipTest("no SCAP Security Guide datastream")
        r = _run(["oscap", "info", "--profiles", ds[0]])
        if r.returncode != 0 or not r.stdout.strip():
            self.skipTest("oscap info --profiles failed")
        profs = compliance.parse_profiles(r.stdout)
        self.assertTrue(profs)                       # a real DS has profiles
        for pid, title in profs:
            self.assertIn("_profile_", pid)
            self.assertTrue(title)

    def test_parse_xccdf_rules_real_ssg(self):
        ds = glob.glob("/usr/share/xml/scap/ssg/content/ssg-*-ds.xml")
        if not ds:
            self.skipTest("no SCAP Security Guide datastream")
        rules = compliance.parse_xccdf_rules(ds[0])
        self.assertIsInstance(rules, dict)
        self.assertTrue(rules)                        # a real DS has rules
        sample = next(iter(rules.values()))
        self.assertIn("title", sample)


@unittest.skipUnless(_INTEGRATION, _reason)
class TestScannersEndToEnd(unittest.TestCase):
    """Run each local (no-network) scanner against the real host end-to-end:
    tool -> parse -> audit -> Findings, asserting it never crashes and yields
    well-formed Findings."""

    def _run_scanner(self, name):
        scanner = SCANNERS[name](Config())
        if not scanner.available():
            self.skipTest(f"{name} scanner not available on this host")
        findings = scanner.scan()
        self.assertIsInstance(findings, list)
        for f in findings:
            self.assertIsInstance(f, Finding)
            self.assertEqual(f.source, name)
            self.assertTrue(f.id)
            self.assertTrue(f.title)
        return findings

    def test_ports_scanner(self):
        self._run_scanner("ports")

    def test_ssh_scanner(self):
        self._run_scanner("ssh")

    def test_systemd_scanner(self):
        self._run_scanner("systemd")


if __name__ == "__main__":
    unittest.main()
