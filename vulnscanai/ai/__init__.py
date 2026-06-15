"""AI provider registry."""

from __future__ import annotations

from typing import Dict, Optional, Type

from .base import AIProvider, ProviderError, extract_json
from .claude import ClaudeProvider
from .gemini import GeminiProvider
from .kimi import KimiProvider
from .local import LocalProvider
from .openai import OpenAIProvider

PROVIDERS: Dict[str, Type[AIProvider]] = {
    ClaudeProvider.name: ClaudeProvider,
    OpenAIProvider.name: OpenAIProvider,
    GeminiProvider.name: GeminiProvider,
    KimiProvider.name: KimiProvider,
    LocalProvider.name: LocalProvider,
}


def get_provider(name: str, model: Optional[str] = None,
                 timeout: int = 60) -> AIProvider:
    key = (name or "").lower()
    if key not in PROVIDERS:
        raise ProviderError(
            f"unknown provider {name!r}; choose from {sorted(PROVIDERS)}"
        )
    return PROVIDERS[key](model=model, timeout=timeout)


__all__ = [
    "AIProvider", "ProviderError", "extract_json",
    "PROVIDERS", "get_provider",
]
