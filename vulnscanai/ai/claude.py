# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Anthropic Claude provider (default).

Calls the Messages API directly over the FIPS-hardened HTTP helper, so it
needs no third-party SDK. Set ANTHROPIC_API_KEY in the environment.
"""

from __future__ import annotations

from .. import http
from .base import AIProvider, ProviderError


class ClaudeProvider(AIProvider):
    name = "claude"
    # Sonnet is the cost-effective default for iterating over many CVEs;
    # pass --model claude-opus-5 for deeper reasoning on hard fixes.
    default_model = "claude-sonnet-5"
    known_models = [
        "claude-sonnet-5",                # balanced default
        "claude-opus-5",                  # deeper reasoning / agentic
        "claude-haiku-4-5",               # fastest / cheapest
        "claude-fable-5",                 # most capable, highest cost
    ]
    api_key_env = "ANTHROPIC_API_KEY"
    endpoint = "https://api.anthropic.com/v1/messages"
    api_version = "2023-06-01"

    def complete(self, system: str, user: str) -> str:
        if not self.api_key:
            raise ProviderError("ANTHROPIC_API_KEY is not set")
        payload = {
            "model": self.model,
            # The 5-series models think by default even when no "thinking" key is
            # sent, and max_tokens caps thinking AND answer together — a tight cap
            # truncates the JSON plan mid-object. Keep the headroom generous; this
            # is a ceiling, not a spend.
            "max_tokens": 8000,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        # Reasoning effort (low|medium|high|xhigh|max) pins adaptive thinking on
        # explicitly and controls how deep it goes. output_config.effort is GA (no
        # beta header); thinking blocks are skipped below because we only read
        # type=="text" parts.
        if self.effort:
            payload["thinking"] = {"type": "adaptive"}
            payload["output_config"] = {"effort": self.effort}
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": self.api_version,
        }
        try:
            data = http.post_json(self.endpoint, payload, headers=headers,
                                  timeout=self.timeout)
        except http.HttpError as exc:
            raise ProviderError(f"Claude API error: {exc}") from exc
        parts = data.get("content", [])
        text = "".join(p.get("text", "") for p in parts if p.get("type") == "text")
        if not text:
            # The 5-series models run safety classifiers that decline a request
            # with a normal HTTP 200 and empty content. A finding's own wording
            # ("exploit", "privilege escalation") can trip the cyber category, so
            # name the reason instead of reporting a bare empty response.
            if data.get("stop_reason") == "refusal":
                cat = (data.get("stop_details") or {}).get("category") or "unspecified"
                raise ProviderError(
                    f"Claude declined this request (category: {cat}) — retry with "
                    "another model or provider for this finding")
            raise ProviderError("empty response from Claude")
        return text
