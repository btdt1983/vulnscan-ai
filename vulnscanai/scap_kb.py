# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Ground AI remediation prompts with vetted SCAP Security Guide fix snippets.

The compliance scanner (``scanners/compliance.py``) already parses the host's
SCAP Security Guide (SSG) XCCDF datastream for CIS/STIG/... benchmark auditing.
That same datastream's ``<Rule>`` elements carry peer-reviewed, ready-to-run bash
remediation scripts (``<fix system="urn:xccdf:fix:script:sh">``) for hundreds of
hardening checks — real "how to fix this" knowledge that the ``fix`` command's AI
step does not use at all today.

This module is a small, self-contained retrieval layer: given a vulnscan-ai
``Finding``'s text, find the most lexically-similar SSG rule (if any) and hand
its vetted fix script to the model as an optional reference, cutting down on
plain hallucination for config/service findings. There is no ID linkage between
a Finding and an XCCDF rule id — the only connection is text similarity, so
matching is deliberately conservative (a wrong "vetted" reference would be worse
than none): a candidate must clear both a cosine-similarity floor AND a minimum
number of distinct overlapping tokens, since a short rule title sharing a single
proper-noun token with the query (e.g. a finding about an exposed nginx port vs.
the unrelated rule "Uninstall nginx Package") can otherwise out-score a
genuinely relevant match on raw cosine alone.

Deliberately stdlib-only (``collections.Counter``, no embeddings/vector DB/ML
dependency, matching the rest of this project) — the corpus is ~1500 rules, so a
per-call linear scan is fast enough without an index.
"""

from __future__ import annotations

import os
import re
from collections import Counter
from math import sqrt
from typing import Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

from .scanners.compliance import find_datastream

# The only fix system whose content is plain shell a model can meaningfully
# translate into vulnscan-ai's command/write_files schema. Ansible/kickstart/
# anaconda/osbuild fixes in the same datastream are skipped — no shell content
# to ground on, and dragging YAML into the prompt would just spend budget.
_FIX_SYSTEM = "urn:xccdf:fix:script:sh"

_TOKEN_RE = re.compile(r"[a-z0-9]+")

# Generic English function words: dropped so they can't drive a cosine match
# on their own. Domain terms (ssh, root, login, package, ...) are kept.
_STOPWORDS = frozenset("""
a an the this that these those is are was were be been being
and or but if then else when while for to of in on at by with from as
it its it's they them their he she his her you your we our i
not no nor so than too very can may must should shall will would could
do does did done have has had having
also which who whom what where how any all each such
system systems host hosts file files
""".split())

# Corpus-side title tokens outweigh description tokens: a rule's title is a
# terse, high-signal summary ("Disable SSH Root Login"); its description is
# long prose that mostly restates generic hardening rationale.
_TITLE_WEIGHT = 3

# Per-reference and whole-block prompt-budget caps. This is advisory text a
# model is told to adapt, not code that runs, so a mid-script truncation is
# harmless — do not "fix" it into something that stays syntactically valid.
_MAX_FIX_CHARS = 1200
_MAX_BLOCK_CHARS = 2000

_REFERENCE_HEADER = (
    "Reference (optional, from the host's SCAP Security Guide hardening "
    "benchmark — lexically similar, NOT necessarily an exact match for this "
    "finding; adapt it, do not copy verbatim):"
)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def tokenize(text: str) -> List[str]:
    """Lowercase alphanumeric tokens with stopwords and 1-char tokens dropped."""
    return [t for t in _TOKEN_RE.findall((text or "").lower())
            if len(t) > 1 and t not in _STOPWORDS]


def _bag(title: str, description: str) -> Counter:
    return Counter(tokenize(title) * _TITLE_WEIGHT + tokenize(description))


def cosine(a: Counter, b: Counter) -> float:
    """Term-frequency cosine similarity in [0, 1]; 0.0 if either bag is empty."""
    if not a or not b:
        return 0.0
    common = set(a) & set(b)
    dot = sum(a[t] * b[t] for t in common)
    if dot == 0:
        return 0.0
    norm_a = sqrt(sum(v * v for v in a.values()))
    norm_b = sqrt(sum(v * v for v in b.values()))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def best_matches(query_bag: Counter, corpus: Dict[str, Counter], *,
                 top_k: int = 1, min_score: float = 0.40,
                 min_overlap: int = 3) -> List[Tuple[str, float]]:
    """Pure top-k lexical search. A candidate is kept only if it clears BOTH
    ``min_score`` (cosine) AND ``min_overlap`` (distinct shared tokens) — the
    overlap floor is what actually rejects a short title that shares one rare
    token with the query but is otherwise unrelated (cosine alone can't tell
    that apart from a real match on a small bag).
    """
    scored: List[Tuple[str, float]] = []
    for rid, bag in corpus.items():
        if len(set(query_bag) & set(bag)) < min_overlap:
            continue
        score = cosine(query_bag, bag)
        if score < min_score:
            continue
        scored.append((rid, score))
    scored.sort(key=lambda t: t[1], reverse=True)
    return scored[:top_k]


def parse_fix_rules(datastream_path: str) -> Dict[str, Dict[str, str]]:
    """Stream Rule elements -> {id: {title, description, rationale, fix_text}}
    for rules that carry a plain-shell fix. Rules without one (ansible/
    kickstart/anaconda-only, or no fix at all) are omitted entirely — there is
    nothing useful to ground on.

    Iterates each Rule's DIRECT children (not the whole-subtree ``elem.iter()``
    used by ``compliance.parse_xccdf_rules``): description/rationale are always
    direct children here, and skipping the nested <check>/<ident> subtrees
    avoids picking up unrelated text. ``description``/``rationale`` use
    ``.itertext()`` because SSG's content is mixed HTML (nested <html:pre>/
    <html:code>) — ``elem.text`` alone would silently truncate at the first
    child.
    """
    out: Dict[str, Dict[str, str]] = {}
    try:
        # Distro-shipped datastream; ElementTree resolves no external entities.
        context = ET.iterparse(datastream_path, events=("end",))  # nosec B314
    except (OSError, ET.ParseError):
        return out
    try:
        for _event, elem in context:
            if _local(elem.tag) != "Rule":
                continue
            rid = elem.get("id", "")
            if not rid:
                elem.clear()
                continue
            title, description, rationale, fix_text = "", "", "", ""
            for child in elem:
                lname = _local(child.tag)
                if lname == "title" and child.text and not title:
                    title = child.text.strip()
                elif lname == "description" and not description:
                    description = "".join(child.itertext()).strip()
                elif lname == "rationale" and not rationale:
                    rationale = "".join(child.itertext()).strip()
                elif (lname == "fix" and not fix_text
                      and child.get("system") == _FIX_SYSTEM):
                    fix_text = (child.text or "").strip()
            if fix_text:
                out[rid] = {"title": title, "description": description,
                           "rationale": rationale, "fix_text": fix_text}
            elem.clear()
    except ET.ParseError:
        pass
    return out


def format_reference(rule: Dict[str, str], score: float) -> str:
    """One matched rule -> an advisory reference block for the prompt."""
    fix_text = rule.get("fix_text", "")
    if len(fix_text) > _MAX_FIX_CHARS:
        fix_text = fix_text[:_MAX_FIX_CHARS] + "\n... (truncated)"
    title = rule.get("title") or "(untitled rule)"
    return f"{_REFERENCE_HEADER}\n### {title}\n{fix_text}"


# In-process cache for one datastream, keyed on (path, mtime, size) so a
# `dnf update scap-security-guide` naturally invalidates it in a long-lived
# process (the dashboard). Bounds memory to what a single host ever needs; no
# lock — a non-critical, read-mostly cache, consistent with the rest of the
# codebase not locking similar in-memory caches.
_cache_key: Optional[Tuple[str, float, int]] = None
_cache_rules: Dict[str, Dict[str, str]] = {}
_cache_bags: Dict[str, Counter] = {}


def _load(datastream_path: str) -> Tuple[Dict[str, Dict[str, str]], Dict[str, Counter]]:
    global _cache_key, _cache_rules, _cache_bags
    try:
        st = os.stat(datastream_path)
    except OSError:
        return {}, {}
    key = (datastream_path, st.st_mtime, st.st_size)
    if key != _cache_key:
        rules = parse_fix_rules(datastream_path)
        bags = {rid: _bag(r["title"], r["description"]) for rid, r in rules.items()}
        _cache_key, _cache_rules, _cache_bags = key, rules, bags
    return _cache_rules, _cache_bags


def ground(query_text: str, *, top_k: int = 1, min_score: float = 0.40,
          min_overlap: int = 3, datastream: Optional[str] = None) -> Optional[str]:
    """Return a prompt-ready reference block for the finding text described by
    ``query_text``, or None when nothing qualifies (no datastream installed, no
    match clears the threshold, or anything goes wrong parsing it). Never
    raises: a host without `scap-security-guide` behaves exactly as if this
    module did not exist.
    """
    try:
        path = find_datastream(datastream)
        if not path:
            return None
        rules, bags = _load(path)
        if not bags:
            return None
        query_bag = Counter(tokenize(query_text))
        if not query_bag:
            return None
        matches = best_matches(query_bag, bags, top_k=top_k, min_score=min_score,
                               min_overlap=min_overlap)
        if not matches:
            return None
        block = "\n\n".join(format_reference(rules[rid], score)
                            for rid, score in matches)
        if len(block) > _MAX_BLOCK_CHARS:
            block = block[:_MAX_BLOCK_CHARS] + "\n... (truncated)"
        return block
    except Exception:
        return None
