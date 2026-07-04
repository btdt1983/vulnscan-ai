# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Report generation.

A single `build_blocks()` pass turns findings into a renderer-agnostic list of
content blocks. Three renderers consume it, in order of preference for a
`.pdf` target:

  1. reportlab  - richest output, if the optional dependency is installed
  2. native     - dependency-free PDF writer (always available)
  3. html       - used when the target path ends in .html

So `--pdf` always yields a real PDF, even on a host without reportlab.
"""

from __future__ import annotations

import html
import json
import os
from typing import Dict, List, Tuple

from . import export
from .fips import status_line
from .models import ComplianceReport, Finding, severity_rank
from .pdfwriter import PdfBuilder

try:  # reportlab is optional
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle, PageBreak,
    )
    _HAVE_REPORTLAB = True
except Exception:  # noqa: BLE001
    _HAVE_REPORTLAB = False


_SEV_COLOR = {
    "critical": "#b30000",
    "important": "#d4690b",
    "high": "#d4690b",
    "moderate": "#b59f00",
    "medium": "#b59f00",
    "low": "#2a7a2a",
    "unknown": "#666666",
}


def _hex_to_rgb(hexstr: str) -> Tuple[float, float, float]:
    hexstr = hexstr.lstrip("#")
    return tuple(int(hexstr[i:i + 2], 16) / 255.0 for i in (0, 2, 4))  # type: ignore[return-value]


def _summary_counts(findings: List[Finding]) -> List[Tuple[str, int]]:
    order = ["critical", "important", "moderate", "low", "unknown"]
    counts = {k: 0 for k in order}
    for f in findings:
        key = f.severity.lower()
        key = {"high": "important", "medium": "moderate"}.get(key, key)
        counts[key] = counts.get(key, 0) + 1
    return [(k, counts[k]) for k in order]


def _sorted(findings: List[Finding]) -> List[Finding]:
    return sorted(
        findings,
        key=lambda f: (-severity_rank(f.severity),
                       -(f.cvss_score or 0.0),
                       f.package or ""),
    )


# --------------------------------------------------------------------------- #
# renderer-agnostic block model
# --------------------------------------------------------------------------- #
def build_blocks(findings: List[Finding], hostname: str, generated: str) -> List[Dict]:
    findings = _sorted(findings)
    blocks: List[Dict] = []
    blocks.append({"t": "h1", "text": "Vulnerability Scan & Remediation Report"})
    blocks.append({"t": "meta", "text": f"Host: {hostname}"})
    blocks.append({"t": "meta", "text": f"Generated: {generated}"})
    blocks.append({"t": "meta", "text": status_line()})
    rows = [(sev, count, _SEV_COLOR.get(sev, "#000000"))
            for sev, count in _summary_counts(findings)]
    blocks.append({"t": "summary", "rows": rows, "total": len(findings)})
    blocks.append({"t": "note", "text": (
        "Remediation steps below are AI-generated proposals. Review before "
        "applying. Commands are screened against a safety deny-list at apply "
        "time.")})
    blocks.append({"t": "pagebreak"})

    for f in findings:
        hexc = _SEV_COLOR.get(f.severity.lower(), "#000000")
        blocks.append({"t": "h2", "text": f"[{f.severity.upper()}] {f.title}",
                       "hex": hexc})
        meta = (
            f"CVEs: {', '.join(f.cve_ids) or 'n/a'}  |  "
            f"Advisory: {f.advisory or 'n/a'}  |  "
            f"Package: {f.package or 'n/a'} "
            f"({f.installed_version or '?'} -> {f.fixed_version or '?'})  |  "
            f"CVSS: {f.cvss_score if f.cvss_score is not None else 'n/a'}"
        )
        if f.vendor_fix_state and f.vendor_fix_state.lower() != "affected":
            meta += f"  |  Vendor: {f.vendor_fix_state}"
        blocks.append({"t": "meta", "text": meta})
        if f.description:
            blocks.append({"t": "para", "text": f.description[:1200]})

        rem = f.remediation
        if rem:
            blocks.append({"t": "remhdr", "text": (
                f"Proposed remediation (risk: {rem.risk}, "
                f"confidence: {rem.confidence:.0%}, "
                f"reboot: {'yes' if rem.requires_reboot else 'no'}, "
                f"via {rem.provider}/{rem.model})")})
            if rem.summary:
                blocks.append({"t": "para", "text": rem.summary})
            if rem.backup_paths or rem.service or rem.validate_cmd:
                tx = "Transactional fix: backup -> apply -> validate -> "
                tx += f"{rem.restart_mode or 'none'} -> rollback on failure"
                blocks.append({"t": "small", "text": tx})
                if rem.backup_paths:
                    blocks.append({"t": "small",
                                   "text": f"Backup: {', '.join(rem.backup_paths)}"})
                if rem.validate_cmd:
                    blocks.append({"t": "small",
                                   "text": f"Validate: {rem.validate_cmd}"})
                if rem.service:
                    blocks.append({"t": "small", "text": (
                        f"Service: systemctl {rem.restart_mode} {rem.service}")})
            for cmd in rem.commands:
                blocks.append({"t": "cmd", "text": cmd})
            for step in rem.config_changes:
                blocks.append({"t": "bullet", "text": step})
            if rem.verification:
                blocks.append({"t": "small", "text": f"Verify: {rem.verification}"})
            if rem.apply_results:
                statuses = ", ".join(str(r.get("status")) for r in rem.apply_results)
                blocks.append({"t": "small", "text": f"Apply result: {statuses}"})
            if rem.rolled_back:
                blocks.append({"t": "small",
                               "text": "Status: ROLLED BACK (change reverted)"})
            elif rem.backup_dir:
                blocks.append({"t": "small",
                               "text": f"Backup stored at: {rem.backup_dir}"})
        blocks.append({"t": "spacer", "h": 8})
    return blocks


def write_report(findings: List[Finding], path: str, hostname: str,
                 generated: str) -> str:
    """Render to `path`; format is chosen from the file extension.

    Supported: .sarif / .sarif.json (SARIF 2.1.0), .json (export document),
    .html (HTML), anything else -> PDF.
    """
    low = path.lower()
    if low.endswith(".sarif") or low.endswith(".sarif.json"):
        _write_data(export.build_sarif(findings), path)
        return path
    if low.endswith(".json"):
        _write_data(export.build_json(findings, hostname, generated), path)
        return path

    blocks = build_blocks(findings, hostname, generated)
    if low.endswith(".html"):
        _render_html(blocks, path)
        return path
    # .pdf (or anything else) -> a PDF
    if not low.endswith(".pdf"):
        path = path + ".pdf"
    if _HAVE_REPORTLAB:
        _render_reportlab(blocks, path)
    else:
        _render_native_pdf(blocks, path)
    return path


# --------------------------------------------------------------------------- #
# compliance benchmark report (reuses the block renderers above)
# --------------------------------------------------------------------------- #
def build_compliance_blocks(report: ComplianceReport) -> List[Dict]:
    """Turn a ComplianceReport into renderer-agnostic blocks (same block types
    the vulnerability report uses, so all three renderers handle it as-is)."""
    blocks: List[Dict] = []
    blocks.append({"t": "h1", "text": "Compliance Benchmark Report"})
    if report.hostname:
        blocks.append({"t": "meta", "text": f"Host: {report.hostname}"})
    if report.generated:
        blocks.append({"t": "meta", "text": f"Generated: {report.generated}"})
    blocks.append({"t": "meta", "text": status_line()})
    blocks.append({"t": "meta",
                   "text": f"Profile: {report.profile_title or report.profile} "
                           f"({report.profile})"})
    blocks.append({"t": "meta", "text": f"Datastream: {report.datastream}"})
    blocks.append({"t": "note", "text": (
        f"Score: {report.score:.1f}%   —   pass {report.pass_count}   "
        f"fail {report.fail_count}   error {report.error_count}   "
        f"n/a {report.na_count}")})
    blocks.append({"t": "note", "text": (
        "Failing rules below come from the SCAP Security Guide benchmark. "
        "Rules marked 'remediation available' ship an automated fix.")})
    blocks.append({"t": "spacer", "h": 6})

    fails = report.fails
    if not fails:
        blocks.append({"t": "para", "text": "No failing rules. The host meets "
                                            "every selected rule in this profile."})
        return blocks
    for r in fails:
        hexc = _SEV_COLOR.get((r.severity or "unknown").lower(), "#000000")
        blocks.append({"t": "h2", "text": f"[{r.severity.upper()}] {r.title}",
                       "hex": hexc})
        blocks.append({"t": "small", "text": f"Rule: {r.rule_id}"})
        if r.references:
            blocks.append({"t": "small",
                           "text": "Identifiers: " + ", ".join(r.references[:12])})
        blocks.append({"t": "small", "text": (
            "Remediation available (ships with the benchmark)"
            if r.fix_available else "No automated remediation; fix manually")})
        blocks.append({"t": "spacer", "h": 6})
    return blocks


def write_compliance_report(report: ComplianceReport, path: str) -> str:
    """Render a ComplianceReport to `path`; format chosen by file extension.

    Supported: .sarif / .sarif.json (SARIF 2.1.0), .json (report document),
    .html (HTML), anything else -> PDF.
    """
    low = path.lower()
    if low.endswith(".sarif") or low.endswith(".sarif.json"):
        _write_data(export.build_compliance_sarif(report), path)
        return path
    if low.endswith(".json"):
        _write_data(report.to_dict(), path)
        return path
    blocks = build_compliance_blocks(report)
    if low.endswith(".html"):
        _render_html(blocks, path)
        return path
    if not low.endswith(".pdf"):
        path = path + ".pdf"
    if _HAVE_REPORTLAB:
        _render_reportlab(blocks, path)
    else:
        _render_native_pdf(blocks, path)
    return path


def _write_data(obj: Dict, path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=False)
    os.chmod(path, 0o600)


# --------------------------------------------------------------------------- #
# native PDF renderer (no dependencies)
# --------------------------------------------------------------------------- #
def _render_native_pdf(blocks: List[Dict], path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    pdf = PdfBuilder()
    for b in blocks:
        t = b["t"]
        if t == "h1":
            pdf.text(b["text"], size=18, style="bold", space_after=4)
            pdf.rule()
        elif t == "meta":
            pdf.text(b["text"], size=8, color=(0.33, 0.33, 0.33))
        elif t == "note":
            pdf.spacer(4)
            pdf.text(b["text"], size=8, color=(0.33, 0.33, 0.33))
        elif t == "summary":
            pdf.spacer(6)
            for sev, count, hexc in b["rows"]:
                pdf.text(f"{sev.capitalize():<12} {count}", size=10,
                         color=_hex_to_rgb(hexc))
            pdf.text(f"{'TOTAL':<12} {b['total']}", size=10, style="bold")
        elif t == "pagebreak":
            pdf._new_page()
        elif t == "h2":
            pdf.spacer(6)
            pdf.text(b["text"], size=12, style="bold", color=_hex_to_rgb(b["hex"]))
        elif t == "para":
            pdf.text(b["text"], size=9)
        elif t == "remhdr":
            pdf.spacer(3)
            pdf.text(b["text"], size=9, style="bold")
        elif t == "cmd":
            pdf.text("$ " + b["text"], size=8, style="mono",
                     color=(0.1, 0.1, 0.1), indent=8)
        elif t == "bullet":
            pdf.text("- " + b["text"], size=9, indent=8)
        elif t == "small":
            pdf.text(b["text"], size=8, color=(0.33, 0.33, 0.33))
        elif t == "spacer":
            pdf.spacer(b["h"])
    with open(path, "wb") as fh:
        fh.write(pdf.build())
    os.chmod(path, 0o600)


# --------------------------------------------------------------------------- #
# reportlab renderer
# --------------------------------------------------------------------------- #
def _render_reportlab(blocks: List[Dict], path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    doc = SimpleDocTemplate(path, pagesize=A4,
                            topMargin=18 * mm, bottomMargin=18 * mm,
                            leftMargin=16 * mm, rightMargin=16 * mm,
                            title="vulnscan-ai report")
    styles = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=9, leading=12)
    small = ParagraphStyle("small", parent=body, textColor=colors.HexColor("#555555"))
    mono = ParagraphStyle("mono", parent=body, fontName="Courier", fontSize=8,
                          leading=10, backColor=colors.HexColor("#f2f2f2"),
                          leftIndent=6)
    story = []
    for b in blocks:
        t = b["t"]
        esc = lambda s: html.escape(str(s))  # noqa: E731
        if t == "h1":
            story.append(Paragraph(esc(b["text"]), styles["Title"]))
        elif t in ("meta", "small", "note"):
            story.append(Paragraph(esc(b["text"]), small))
        elif t == "summary":
            rows = [["Severity", "Count"]]
            for sev, count, _hexc in b["rows"]:
                rows.append([sev.capitalize(), str(count)])
            rows.append(["TOTAL", str(b["total"])])
            tbl = Table(rows, colWidths=[80 * mm, 40 * mm])
            style = [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#222222")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#eeeeee")),
            ]
            for i, (_sev, _c, hexc) in enumerate(b["rows"], start=1):
                style.append(("TEXTCOLOR", (0, i), (0, i), colors.HexColor(hexc)))
            tbl.setStyle(TableStyle(style))
            story.append(Spacer(1, 6))
            story.append(tbl)
        elif t == "pagebreak":
            story.append(PageBreak())
        elif t == "h2":
            story.append(Spacer(1, 6))
            story.append(Paragraph(
                f'<font color="{b["hex"]}">{esc(b["text"])}</font>',
                ParagraphStyle("h2", parent=styles["Heading2"])))
        elif t == "para":
            story.append(Paragraph(esc(b["text"]), body))
        elif t == "remhdr":
            story.append(Paragraph("<b>" + esc(b["text"]) + "</b>", body))
        elif t == "cmd":
            story.append(Paragraph("$ " + esc(b["text"]), mono))
        elif t == "bullet":
            story.append(Paragraph("• " + esc(b["text"]), body))
        elif t == "spacer":
            story.append(Spacer(1, b["h"]))
    doc.build(story)


# --------------------------------------------------------------------------- #
# HTML renderer
# --------------------------------------------------------------------------- #
def _render_html(blocks: List[Dict], path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    esc = html.escape
    parts = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        "<title>vulnscan-ai report</title>",
        "<style>body{font-family:sans-serif;margin:2rem;max-width:60rem}"
        "code,pre{background:#f2f2f2;padding:2px 4px;border-radius:3px}"
        "pre{padding:8px;overflow:auto}.meta{color:#555;font-size:.9em}"
        "table{border-collapse:collapse}td,th{border:1px solid #999;padding:4px 8px}"
        "</style></head><body>",
    ]
    for b in blocks:
        t = b["t"]
        if t == "h1":
            parts.append(f"<h1>{esc(b['text'])}</h1>")
        elif t in ("meta", "small"):
            parts.append(f"<p class='meta'>{esc(b['text'])}</p>")
        elif t == "note":
            parts.append(f"<p><em>{esc(b['text'])}</em></p>")
        elif t == "summary":
            parts.append("<table><tr><th>Severity</th><th>Count</th></tr>")
            for sev, count, hexc in b["rows"]:
                parts.append(f"<tr><td style='color:{hexc}'>{sev.capitalize()}"
                             f"</td><td>{count}</td></tr>")
            parts.append(f"<tr><td><b>TOTAL</b></td><td>{b['total']}</td></tr></table>")
        elif t == "pagebreak":
            parts.append("<hr>")
        elif t == "h2":
            parts.append(f"<h2 style='color:{b['hex']}'>{esc(b['text'])}</h2>")
        elif t == "para":
            parts.append(f"<p>{esc(b['text'])}</p>")
        elif t == "remhdr":
            parts.append(f"<p><b>{esc(b['text'])}</b></p>")
        elif t == "cmd":
            parts.append(f"<pre>$ {esc(b['text'])}</pre>")
        elif t == "bullet":
            parts.append(f"<ul><li>{esc(b['text'])}</li></ul>")
        # spacer: ignored in HTML
    parts.append("</body></html>")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(parts))
