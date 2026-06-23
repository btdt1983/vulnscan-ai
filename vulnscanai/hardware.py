# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""Host capability detection (RAM and GPU) for model sizing.

Ollama runs models on the GPU automatically when NVIDIA/AMD drivers are
present — the same model just runs accelerated. So the only thing the tool
needs to do is *size* the model to the available compute: VRAM when a GPU is
present, otherwise system RAM.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Dict


def _meminfo_gb(key: str) -> float:
    try:
        with open("/proc/meminfo", "r", encoding="ascii") as fh:
            for line in fh:
                if line.startswith(key + ":"):
                    return int(line.split()[1]) / (1024.0 * 1024.0)
    except (OSError, ValueError):
        pass
    return 0.0


def mem_total_gb() -> float:
    return _meminfo_gb("MemTotal")


def mem_available_gb() -> float:
    return _meminfo_gb("MemAvailable") or mem_total_gb()


def detect_gpu() -> Dict:
    """Return {present, kind, name, vram_gb}. vram_gb is 0.0 if unknown."""
    info = {"present": False, "kind": None, "name": "", "vram_gb": 0.0}

    if shutil.which("nvidia-smi"):
        try:
            out = subprocess.run(
                ["nvidia-smi", "--query-gpu=name,memory.total",
                 "--format=csv,noheader,nounits"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=8, check=False)
            line = out.stdout.strip().splitlines()[0] if out.stdout.strip() else ""
            if out.returncode == 0 and line:
                parts = [p.strip() for p in line.split(",")]
                vram = float(parts[1]) / 1024.0 if len(parts) > 1 else 0.0
                return {"present": True, "kind": "nvidia",
                        "name": parts[0], "vram_gb": vram}
        except (OSError, ValueError, IndexError, subprocess.SubprocessError):
            pass

    if shutil.which("rocm-smi"):
        try:
            out = subprocess.run(
                ["rocm-smi", "--showproductname"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=8, check=False)
            if out.returncode == 0:
                name = ""
                for ln in out.stdout.splitlines():
                    if ":" in ln and "card" in ln.lower():
                        name = ln.split(":", 1)[1].strip()
                        break
                return {"present": True, "kind": "amd",
                        "name": name or "AMD GPU", "vram_gb": 0.0}
        except (OSError, subprocess.SubprocessError):
            pass

    return info


def compute_budget_gb() -> Dict:
    """How much memory a model may use, and where it runs.

    Prefers GPU VRAM when a GPU with known VRAM is present; otherwise falls
    back to available system RAM (CPU inference).
    """
    gpu = detect_gpu()
    if gpu["present"] and gpu["vram_gb"] > 0:
        return {"budget_gb": gpu["vram_gb"], "where": "gpu", "gpu": gpu}
    if gpu["present"]:
        # GPU present but VRAM unknown (e.g. AMD): be optimistic but cautious.
        return {"budget_gb": max(mem_available_gb(), 8.0), "where": "gpu",
                "gpu": gpu}
    return {"budget_gb": mem_available_gb(), "where": "cpu", "gpu": gpu}
