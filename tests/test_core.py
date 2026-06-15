"""Dependency-free unit tests (stdlib unittest). Run:  python3 -m unittest -v"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from vulnscanai import export, report
from vulnscanai.ai.base import extract_json
from vulnscanai.models import (
    Finding, Remediation, findings_from_json, findings_to_json, merge_findings,
    severity_rank,
)
from vulnscanai.pdfwriter import PdfBuilder
from vulnscanai.remediation import apply, screen_command
from vulnscanai.scanners.dnf_rhsa import parse_nevra, _CVE_LINE, _ADV_LINE


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
