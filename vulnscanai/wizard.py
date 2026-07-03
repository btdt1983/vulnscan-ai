# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""First-run setup wizard: choose and download an offline AI model.

Presents a menu of curated Ollama models (sized for different hosts),
optionally installs Ollama and starts its service, pulls the chosen model,
and saves it as the default provider/model in the per-user config so every
later run uses the local, offline backend with no API key.
"""

from __future__ import annotations

import os
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


def _setup_model(config, *, force: bool = False) -> int:
    """Interactive model picker. Returns a process exit code (0 = fine)."""
    print("\n--- Local offline model (Ollama) ---")
    print("Pick a local model for AI remediation. It runs fully offline:")
    print("no API key, nothing leaves this host.\n")

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

    # Persist the choice UP FRONT so selecting 'local' always takes effect, even
    # if the download is interrupted — or the model is already present but
    # 'ollama pull' can't reach the registry (offline). It can be pulled later.
    path = config.write_user_config({"provider": "local", "model": model})
    config.mark_setup_done()

    if not _ensure_server():
        print("\nWarning: the Ollama server doesn't appear to be running.")
        print("Start it with: sudo systemctl start ollama   (or: ollama serve)")

    pulled = _pull(model)
    print("\n" + "=" * 64)
    print(f"Default provider set to 'local' with model '{model}'.")
    print(f"Saved to {path}")
    if not pulled:
        print(f"NOTE: could not download '{model}' now — it may already be present, "
              f"or you're offline. Retry any time: ollama pull {model}")
    print("Try it:  vulnscan-ai scan  &&  vulnscan-ai fix --dry-run")
    print("=" * 64)
    return 0 if pulled else 1


def _configure_notifications(config) -> None:
    """Optional: set up email summaries for scheduled scans."""
    print("\n" + "-" * 64)
    print(" Email notifications (optional)")
    print("-" * 64)
    print("A scheduled scan can email a summary when findings appear.")
    if not _ask_yes("Configure email notifications now?"):
        if getattr(config, "notify_email", None):
            print(f"Keeping existing recipient: {config.notify_email}")
        else:
            print("Skipped. Configure later with 'vulnscan-ai setup'.")
        return

    email = _ask("  Send reports to (recipient email): ")
    if not email:
        print("  No address entered; skipping email setup.")
        return
    smtp_host = _ask("  SMTP server host [localhost]: ") or "localhost"
    try:
        smtp_port = int(_ask("  SMTP server port [25]: ") or "25")
    except ValueError:
        smtp_port = 25
    sender = _ask(f"  From address [{email}]: ") or email
    min_sev = _ask("  Notify on severity at/above "
                   "[important]: ") or "important"
    starttls = _ask_yes("  Use STARTTLS (encrypted submission)?")
    updates = {
        "notify_email": email, "smtp_host": smtp_host, "smtp_port": smtp_port,
        "smtp_from": sender, "notify_min_severity": min_sev,
        "smtp_starttls": starttls,
    }
    user = _ask("  SMTP username (blank = no authentication): ")
    if user:
        updates["smtp_user"] = user
        import getpass
        try:
            pw = getpass.getpass("  SMTP password (stored 0600; blank to keep "
                                 "in $VULNSCANAI_SMTP_PASSWORD): ")
        except (EOFError, KeyboardInterrupt):
            pw = ""
        if pw:
            updates["smtp_password"] = pw
    path = config.write_user_config(updates)
    print(f"  Saved email settings to {path}")
    print("  Test it with:  vulnscan-ai scheduled")


# Cloud providers that authenticate with an API key, with where to get one.
_CLOUD_PROVIDERS = [
    ("claude", "ANTHROPIC_API_KEY", "console.anthropic.com"),
    ("openai", "OPENAI_API_KEY", "platform.openai.com"),
    ("gemini", "GEMINI_API_KEY", "aistudio.google.com"),
    ("kimi", "MOONSHOT_API_KEY", "platform.moonshot.cn"),
    ("deepseek", "DEEPSEEK_API_KEY", "platform.deepseek.com"),
    ("mistral", "MISTRAL_API_KEY", "console.mistral.ai"),
]


def _pick_model(name: str) -> str:
    """Let the operator pick a model id for a cloud provider from a menu of
    known ids (with a custom-id escape hatch). Returns the chosen id, or "" to
    mean "use the provider default". Prevents typo'd ids like 'Sonnet 5' that
    the API would reject, leaving every remediation as '(AI proposal failed)'.
    """
    from .ai import PROVIDERS
    cls = PROVIDERS.get(name)
    default = getattr(cls, "default_model", "") if cls else ""
    known = list(getattr(cls, "known_models", []) or [])
    if not known:
        # No curated list for this provider — keep the free-text prompt.
        return _ask("  Model id (blank = provider default): ")

    print("\n  Available models:")
    for i, m in enumerate(known, 1):
        tag = "  (default)" if m == default else ""
        print(f"    {i}  {m}{tag}")
    print("    c  custom — type a model id")
    choice = _ask(f"  Choose a model [1-{len(known)}/c] "
                  f"(blank = default {default}): ").lower()
    if not choice:
        return ""                                   # provider default
    if choice == "c":
        custom = _ask("  Custom model id: ")
        return custom                               # may be "" -> default
    try:
        idx = int(choice) - 1
    except ValueError:
        idx = -1
    if 0 <= idx < len(known):
        return known[idx]
    print(f"  Unrecognised choice; using the default ({default}).")
    return ""


def _configure_cloud_provider(config) -> int:
    """Pick a cloud AI provider and store its API key in the user config."""
    print("\n" + "-" * 64)
    print(" Cloud AI provider — API key")
    print("-" * 64)
    print("Note: an API key is NOT a Claude Pro / ChatGPT Plus subscription.")
    print("Create a developer key (with billing) at the provider's console.\n")
    for i, (name, env, url) in enumerate(_CLOUD_PROVIDERS, 1):
        print(f"  {i}  {name:9} key={env:18} {url}")
    print("  0  skip (configure later with 'vulnscan-ai setup' or env vars)")

    choice = _ask(f"\nChoose a provider [0-{len(_CLOUD_PROVIDERS)}]: ")
    try:
        idx = int(choice) - 1
    except ValueError:
        idx = -1
    if not 0 <= idx < len(_CLOUD_PROVIDERS):
        print("Skipped.")
        return 0
    name, env, url = _CLOUD_PROVIDERS[idx]

    import getpass
    # Reuse an already-saved key so switching provider or just changing the model
    # doesn't force the operator to paste the key again every time.
    existing = (getattr(config, "api_keys", {}) or {}).get(env) or os.environ.get(env)
    key = ""
    if existing:
        ans = _ask(f"  A {name} API key is already saved. Reuse it? "
                   f"[Y/n] (n = enter a new one): ").lower()
        if ans in ("", "y", "yes"):
            key = existing
            print("  Reusing the saved key.")
    if not key:
        try:
            key = getpass.getpass(f"  Paste your {name} API key (hidden): ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
    if not key:
        print("  No key entered; skipping.")
        return 0

    model = _pick_model(name)
    effort = ""
    if name == "claude":
        effort = _ask("  Reasoning effort low|medium|high|xhigh|max "
                      "(blank = default): ").strip()

    keys = dict(getattr(config, "api_keys", {}) or {})
    keys[env] = key
    updates = {"provider": name, "api_keys": keys}
    if model:
        updates["model"] = model
    if name == "claude" and effort:
        updates["claude_effort"] = effort
    path = config.write_user_config(updates)

    # Reflect into this process so a follow-up command in the same run works.
    os.environ.setdefault(env, key)
    config.provider = name
    if model:
        config.model = model
    print(f"  Saved provider '{name}' and API key to {path} (mode 0600).")
    print(f"  Test it:  vulnscan-ai providers   (should show {name} ready)")
    return 0


def run_setup(config, *, force: bool = False) -> int:
    """Pick an AI backend (local model or cloud key), then offer email setup."""
    print("=" * 64)
    print(" vulnscan-ai setup")
    print("=" * 64)
    print("How should the AI remediation step get its model?\n")
    print("  1  Local, offline model via Ollama (no API key, nothing leaves the host)")
    print("  2  Cloud provider with an API key (Claude, OpenAI, Gemini, ...)")
    print("  0  Skip for now")
    choice = _ask("\nChoose [0/1/2] (default 1): ") or "1"

    if choice == "2":
        code = _configure_cloud_provider(config)
    elif choice == "0":
        print("Skipped AI backend setup.")
        code = 0
    else:
        code = _setup_model(config, force=force)

    _configure_notifications(config)
    config.mark_setup_done()
    return code


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
