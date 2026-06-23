# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""First-run setup wizard: choose and download an offline AI model.

Presents a menu of curated Ollama models (sized for different hosts),
optionally installs Ollama and starts its service, pulls the chosen model,
and saves it as the default provider/model in the per-user config so every
later run uses the local, offline backend with no API key.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from typing import List, Optional

from .ai.local import LocalProvider
from .hardware import compute_budget_gb, mem_total_gb

# Curated offline models. `need` is the approximate working-set in GB — it is
# compared against VRAM on a GPU host, or available RAM on a CPU host. The same
# model runs accelerated automatically when Ollama sees a GPU.
MODELS = [
    {"name": "qwen2.5:0.5b", "size": "0.4 GB", "need": 1.0,
     "note": "tiny & fastest; basic quality"},
    {"name": "llama3.2:1b", "size": "1.3 GB", "need": 2.5,
     "note": "good balance, CPU-friendly"},
    {"name": "llama3.2:3b", "size": "2.0 GB", "need": 4.0,
     "note": "better quality"},
    {"name": "mistral:7b", "size": "4.1 GB", "need": 6.0,
     "note": "strong quality (Apache-2.0)"},
    {"name": "qwen2.5:7b", "size": "4.7 GB", "need": 6.0,
     "note": "strong quality"},
    {"name": "llama3.1:8b", "size": "4.9 GB", "need": 7.0,
     "note": "strong general model"},
    {"name": "qwen2.5:14b", "size": "9.0 GB", "need": 11.0,
     "note": "best quality; GPU recommended"},
    {"name": "qwen2.5:32b", "size": "20 GB", "need": 24.0,
     "note": "top quality; needs a big GPU"},
]

INSTALL_CMD = "curl -fsSL https://ollama.com/install.sh | sh"


def _ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def _ask_yes(prompt: str) -> bool:
    return _ask(prompt + " [y/N]: ").lower() in ("y", "yes")


def _have(binary: str) -> bool:
    return shutil.which(binary) is not None


def _ensure_server() -> bool:
    """Best-effort: start the ollama service, then check it answers."""
    if _have("systemctl"):
        subprocess.run(["systemctl", "start", "ollama"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       check=False)
    return LocalProvider().available()


def _install_ollama() -> bool:
    print(f"\nRunning the official installer:\n  {INSTALL_CMD}\n")
    rc = subprocess.run(["sh", "-c", INSTALL_CMD], check=False).returncode
    return rc == 0


def _pull(model: str) -> bool:
    print(f"\nDownloading model '{model}' (progress below)...\n")
    rc = subprocess.run(["ollama", "pull", model], check=False).returncode
    return rc == 0


def _recommended_index(budget_gb: float) -> int:
    """Largest model whose working-set fits the memory budget (VRAM or RAM)."""
    best = 0
    for i, m in enumerate(MODELS):
        if m["need"] <= max(budget_gb, 1.0):
            best = i
    return best


def run_setup(config, *, force: bool = False) -> int:
    """Interactive model picker. Returns a process exit code (0 = fine)."""
    print("=" * 64)
    print(" vulnscan-ai setup — offline AI model")
    print("=" * 64)
    print("Pick a local model for AI remediation. It runs fully offline via")
    print("Ollama: no API key, nothing leaves this host.\n")

    if not _have("ollama"):
        print("Ollama is not installed.")
        if _ask_yes("Install Ollama now? (downloads from ollama.com)"):
            if not _install_ollama() or not _have("ollama"):
                print("Install failed. Install manually, then run "
                      "'vulnscan-ai setup'.")
                config.mark_setup_done()
                return 1
        else:
            print("\nSkipped. Install later with:\n  " + INSTALL_CMD)
            print("then run: vulnscan-ai setup")
            config.mark_setup_done()
            return 0

    _ensure_server()

    budget = compute_budget_gb()
    gpu = budget["gpu"]
    on_gpu = budget["where"] == "gpu"
    cap = budget["budget_gb"]
    if gpu["present"]:
        vram = f", {gpu['vram_gb']:.0f} GB VRAM" if gpu["vram_gb"] else ""
        print(f"GPU detected: {gpu['name']}{vram} "
              f"({gpu['kind']}) — models run GPU-accelerated.")
        print(f"Sizing against {'VRAM' if gpu['vram_gb'] else 'memory'} "
              f"budget ~{cap:.0f} GB.\n")
        need_col = "needs VRAM"
    else:
        print("No GPU detected — models run on CPU (slower; small models "
              "recommended).")
        print(f"Sizing against ~{cap:.1f} GB available RAM.\n")
        need_col = "needs RAM"

    rec = _recommended_index(cap)
    print(f"  #  model            download   {need_col:<10}  notes")
    print("  -  ---------------  ---------  ----------  -------------------------")
    for i, m in enumerate(MODELS, 1):
        if m["need"] <= cap:
            fit = "fits"
        elif on_gpu:
            fit = "spills"          # exceeds VRAM -> partial CPU offload
        elif m["need"] <= mem_total_gb():
            fit = "tight/swap"
        else:
            fit = "low mem"
        star = " (recommended)" if (i - 1) == rec else ""
        print(f"  {i}  {m['name']:<15}  {m['size']:>8}  {fit:>10}  {m['note']}{star}")
    print("  0  skip for now (configure later with 'vulnscan-ai setup')")

    default = rec + 1
    choice = _ask(f"\nChoose a model [0-{len(MODELS)}] (default {default}): ")
    if choice == "":
        choice = str(default)
    if choice == "0":
        print("\nSkipped. No model downloaded.")
        config.mark_setup_done()
        return 0
    try:
        idx = int(choice) - 1
        model = MODELS[idx]["name"]
    except (ValueError, IndexError):
        print("Invalid choice; skipping.")
        config.mark_setup_done()
        return 0

    if not _ensure_server():
        print("\nWarning: the Ollama server doesn't appear to be running.")
        print("Start it with: sudo systemctl start ollama   (or: ollama serve)")

    if not _pull(model):
        print(f"\nFailed to download '{model}'. You can retry: ollama pull {model}")
        config.mark_setup_done()
        return 1

    path = config.write_user_config({"provider": "local", "model": model})
    config.mark_setup_done()
    print("\n" + "=" * 64)
    print(f"Done. Default provider set to 'local' with model '{model}'.")
    print(f"Saved to {path}")
    print("Try it:  vulnscan-ai scan  &&  vulnscan-ai fix --dry-run")
    print("=" * 64)
    return 0


def should_offer_setup(config, command: Optional[str]) -> bool:
    """First-run heuristic: only on an interactive terminal, once."""
    import os
    if command in ("setup", None):
        return False
    if os.environ.get("VULNSCANAI_NO_SETUP"):
        return False
    if config.is_setup_done():
        return False
    return sys.stdin.isatty() and sys.stdout.isatty()
