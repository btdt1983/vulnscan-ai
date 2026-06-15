"""Scanner abstraction and shared subprocess helpers."""

from __future__ import annotations

import shutil
import subprocess
from typing import List, Optional, Tuple

from ..models import Finding


class Scanner:
    """Base class for a detection backend."""

    name: str = "base"

    def __init__(self, config) -> None:  # config: vulnscanai.config.Config
        self.config = config

    def available(self) -> bool:
        """Whether this scanner can run on the current host."""
        raise NotImplementedError

    def scan(self) -> List[Finding]:
        raise NotImplementedError


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


def run(cmd: List[str], timeout: int = 300,
        check: bool = False) -> Tuple[int, str, str]:
    """Run a command, returning (returncode, stdout, stderr).

    Never raises on non-zero exit unless check=True; scanners frequently use
    non-zero exit codes to signal "updates available".
    """
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr}"
        )
    return proc.returncode, proc.stdout, proc.stderr
