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
    # pass --model claude-opus-4-8 for the most capable model.
    default_model = "claude-sonnet-4-6"
    known_models = [
        "claude-sonnet-4-6",              # balanced default
        "claude-opus-4-8",                # most capable
        "claude-haiku-4-5-20251001",      # fastest / cheapest
        "claude-fable-5",
    ]
    api_key_env = "ANTHROPIC_API_KEY"
    endpoint = "https://api.anthropic.com/v1/messages"
    api_version = "2023-06-01"

    def complete(self, system: str, user: str) -> str:
        if not self.api_key:
            raise ProviderError("ANTHROPIC_API_KEY is not set")
        payload = {
            "model": self.model,
            "max_tokens": 2048,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        # Reasoning effort (low|medium|high|xhigh|max) turns on adaptive thinking;
        # give the answer more room so thinking tokens don't crowd out the JSON.
        # output_config.effort is GA (no beta header); thinking blocks are skipped
        # below because we only read type=="text" parts.
        if self.effort:
            payload["max_tokens"] = 8000
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
            raise ProviderError("empty response from Claude")
        return text
