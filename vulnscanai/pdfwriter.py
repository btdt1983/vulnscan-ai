# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""A tiny, dependency-free PDF writer.

Enough to lay out a multi-page text report using the PDF built-in fonts
(Helvetica / Helvetica-Bold / Courier), with word wrapping, colours and
automatic pagination. No fonts are embedded, so output is small and there are
zero third-party dependencies — important for a minimal / FIPS-locked host
where pip-installing reportlab may not be possible.

Only the subset of PDF needed for this tool's reports is implemented.
"""

from __future__ import annotations

from typing import List, Tuple

A4 = (595.28, 841.89)

_FONT_KEY = {"regular": "F1", "bold": "F2", "mono": "F3"}
# Rough average glyph width as a fraction of font size. Courier is truly
# monospaced (0.6 em); Helvetica is proportional, 0.5 is a safe wrap estimate.
_CHAR_FACTOR = {"regular": 0.5, "bold": 0.52, "mono": 0.6}


def _escape(text: str) -> str:
    out = []
    for ch in text:
        if ord(ch) > 255:
            ch = "?"           # built-in encodings are 8-bit
        if ch in "()\\":
            out.append("\\" + ch)
        elif ch == "\t":
            out.append("    ")
        else:
            out.append(ch)
    return "".join(out)


class PdfBuilder:
    def __init__(self, page_size: Tuple[float, float] = A4, margin: float = 50.0):
        self.pw, self.ph = page_size
        self.margin = margin
        self.y = self.ph - margin
        self.pages: List[List[str]] = [[]]

    # -- layout helpers ---------------------------------------------------- #
    @property
    def _ops(self) -> List[str]:
        return self.pages[-1]

    def _new_page(self) -> None:
        self.pages.append([])
        self.y = self.ph - self.margin

    def _ensure(self, needed: float) -> None:
        if self.y - needed < self.margin:
            self._new_page()

    def spacer(self, height: float) -> None:
        self._ensure(height)
        self.y -= height

    def _wrap(self, text: str, size: float, style: str, indent: float) -> List[str]:
        usable = self.pw - 2 * self.margin - indent
        max_chars = max(8, int(usable / (size * _CHAR_FACTOR[style])))
        lines: List[str] = []
        for raw in text.split("\n"):
            cur = ""
            for word in raw.split(" "):
                # Hard-break tokens longer than a line (URLs, long commands).
                while len(word) > max_chars:
                    if cur:
                        lines.append(cur)
                        cur = ""
                    lines.append(word[:max_chars])
                    word = word[max_chars:]
                candidate = word if not cur else cur + " " + word
                if len(candidate) <= max_chars:
                    cur = candidate
                else:
                    lines.append(cur)
                    cur = word
            lines.append(cur)
        return lines

    # -- public drawing ---------------------------------------------------- #
    def text(self, text: str, size: float = 9, style: str = "regular",
             color: Tuple[float, float, float] = (0, 0, 0), indent: float = 0,
             leading: float = None, space_after: float = 0) -> None:
        if style not in _FONT_KEY:
            style = "regular"
        leading = leading or size * 1.32
        font = _FONT_KEY[style]
        r, g, b = color
        for line in self._wrap(text, size, style, indent):
            self._ensure(leading)
            self.y -= leading
            x = self.margin + indent
            self._ops.append(
                f"BT /{font} {size:g} Tf {r:.3f} {g:.3f} {b:.3f} rg "
                f"{x:.2f} {self.y:.2f} Td ({_escape(line)}) Tj ET"
            )
        if space_after:
            self.spacer(space_after)

    def rule(self, color: Tuple[float, float, float] = (0.6, 0.6, 0.6),
             width: float = 0.5) -> None:
        self._ensure(4)
        self.y -= 4
        r, g, b = color
        x1, x2 = self.margin, self.pw - self.margin
        self._ops.append(
            f"{r:.3f} {g:.3f} {b:.3f} RG {width:g} w "
            f"{x1:.2f} {self.y:.2f} m {x2:.2f} {self.y:.2f} l S"
        )

    # -- serialisation ----------------------------------------------------- #
    def build(self) -> bytes:
        fonts = [
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>",
        ]
        n_pages = len(self.pages)
        content_nums, page_nums = [], []
        nxt = 6
        for _ in range(n_pages):
            content_nums.append(nxt); nxt += 1
            page_nums.append(nxt); nxt += 1
        last = nxt - 1

        objs = {}
        objs[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
        kids = " ".join(f"{pn} 0 R" for pn in page_nums)
        objs[2] = f"<< /Type /Pages /Kids [{kids}] /Count {n_pages} >>".encode("latin-1")
        objs[3], objs[4], objs[5] = fonts
        resources = "<< /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >>"
        for i in range(n_pages):
            stream = ("\n".join(self.pages[i])).encode("latin-1", "replace")
            objs[content_nums[i]] = (
                b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream"
            )
            page = (
                f"<< /Type /Page /Parent 2 0 R "
                f"/MediaBox [0 0 {self.pw:.2f} {self.ph:.2f}] "
                f"/Resources {resources} /Contents {content_nums[i]} 0 R >>"
            )
            objs[page_nums[i]] = page.encode("latin-1")

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = {}
        for num in range(1, last + 1):
            offsets[num] = len(out)
            out += f"{num} 0 obj\n".encode("latin-1") + objs[num] + b"\nendobj\n"
        xref_pos = len(out)
        out += f"xref\n0 {last + 1}\n".encode("latin-1")
        out += b"0000000000 65535 f \n"
        for num in range(1, last + 1):
            out += f"{offsets[num]:010d} 00000 n \n".encode("latin-1")
        out += (
            f"trailer\n<< /Size {last + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF\n"
        ).encode("latin-1")
        return bytes(out)
