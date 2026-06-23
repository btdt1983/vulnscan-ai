# Security Policy

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue or pull
request for anything exploitable.

Email **security@techhack.nl** with:

- a description of the issue and its impact,
- steps to reproduce (or a proof of concept),
- the affected version (`vulnscan-ai --version`) and host distribution.

You can expect an acknowledgement within a few business days. We will keep you
updated on the fix and coordinate a disclosure timeline with you. Please give us
a reasonable window to ship a fix before any public disclosure.

This being a tool that can change a live system, reports about the remediation
engine (command screening, transactional apply/rollback, the deny-list) are
especially welcome.

## Supported versions

vulnscan-ai keeps a single current release in the signed repository. Security
fixes are shipped in the **latest release** only; please upgrade before
reporting (`sudo dnf upgrade vulnscan-ai`).

## Verifying downloads

Packages and repository metadata are GPG-signed by
*techhack release signing &lt;security@techhack.nl&gt;*. With the repository
configured (`gpgcheck=1`, `repo_gpgcheck=1`), `dnf` verifies signatures
automatically; you can also check a downloaded RPM with `rpm -K`.
