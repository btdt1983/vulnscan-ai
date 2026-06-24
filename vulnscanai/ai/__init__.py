# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""AI provider registry."""

from __future__ import annotations

from typing import Dict, Optional, Type

from .base import AIProvider, ProviderError, extract_json
from .claude import ClaudeProvider
from .deepseek import DeepSeekProvider
from .gemini import GeminiProvider
from .kimi import KimiProvider
from .local import LocalProvider
from .mistral import MistralProvider
from .openai import OpenAIProvider

PROVIDERS: Dict[str, Type[AIProvider]] = {
    ClaudeProvider.name: ClaudeProvider,
    OpenAIProvider.name: OpenAIProvider,
    GeminiProvider.name: GeminiProvider,
    KimiProvider.name: KimiProvider,
    DeepSeekProvider.name: DeepSeekProvider,
    MistralProvider.name: MistralProvider,
    LocalProvider.name: LocalProvider,
}


def get_provider(name: str, model: Optional[str] = None,
                 timeout: int = 60,
                 effort: Optional[str] = None) -> AIProvider:
    key = (name or "").lower()
    if key not in PROVIDERS:
        raise ProviderError(
            f"unknown provider {name!r}; choose from {sorted(PROVIDERS)}"
        )
    return PROVIDERS[key](model=model, timeout=timeout, effort=effort)


__all__ = [
    "AIProvider", "ProviderError", "extract_json",
    "PROVIDERS", "get_provider",
]
