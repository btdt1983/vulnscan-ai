# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
"""vulnscan-ai: RHEL vulnerability scanner with AI-assisted remediation.

A FIPS-aware command line tool that scans RHEL-based systems for known
vulnerabilities (via dnf/RHSA, OpenSCAP and public CVE feeds), uses an LLM
provider (Claude by default; OpenAI/Gemini/Kimi/DeepSeek/Mistral/local
optional) to propose
remediation, applies fixes only after explicit approval, and can export a
PDF report.
"""

__version__ = "0.1.25"
__all__ = ["__version__"]
