# Contributing to vulnscan-ai

Thanks for wanting to help. A few ground rules keep the project clean and keep
its licensing options open.

## Licensing of contributions

vulnscan-ai is licensed under **AGPL-3.0-or-later**, and the maintainer
(techhack) also offers it under separate commercial terms. To make that
possible, all contributions are accepted under the
[Contributor License Agreement](CLA.md).

By opening a pull request you agree to the CLA. Concretely:

1. Sign off every commit with the Developer Certificate of Origin:
   `git commit -s` (adds a `Signed-off-by: Your Name <you@example.com>` line).
2. State in the pull request description that you have read and agree to the CLA.

You keep the copyright to your contribution; the CLA grants the maintainer the
rights needed to ship it under both AGPL and commercial licenses.

## New source files

Start every new source file with the license header:

```python
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 techhack
```

## Development

- Tests are dependency-free stdlib `unittest`. Run them before submitting:
  `python3 -m unittest discover -s tests -q` — they must pass.
- Match the surrounding style: type hints, small focused functions, and comments
  that explain *why*, not *what*.
- Scanners must be conservative about false positives; remediation must stay
  approval-gated and transactional. Don't regress either property.

## Reporting issues

For security-sensitive reports, email btdt1983@protonmail.com rather than opening a
public issue.
