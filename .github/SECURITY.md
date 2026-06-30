# Security Policy

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue or pull
request for anything exploitable.

Email **btdt1983@protonmail.com** with:

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

## Security posture

vulnscan-ai is **stdlib-only** (no third-party runtime dependencies, so no
dependency-CVE surface) and ships several deliberate guardrails:

- **SAST in CI** — every push runs `bandit` and fails on any medium-or-higher
  finding; the handful of reviewed exceptions carry an inline `# nosec` with a
  justification.
- **Remediation safety** — AI-proposed fixes are screened against a command
  deny-list and applied transactionally (backup → validate → reload →
  auto-rollback). Package-CVE fixes cannot carry config/service scaffolding.
- **Network** — all HTTP goes through one helper over a FIPS-hardened, verified
  TLS context; only `http`/`https` schemes are allowed (no `file://`), feed URLs
  are fixed constants (no SSRF), and responses are size-capped.
- **Feeds/dashboard** — advisory feed content is untrusted and HTML-escaped on
  output (no XSS); remote XML is parsed with a DOCTYPE/ENTITY guard (no XXE /
  entity-expansion). The dashboard requires login, binds to localhost unless an
  allow-list is set, and uses `SameSite=Strict` session cookies.

## Verifying downloads

Packages and repository metadata are GPG-signed by
*techhack release signing &lt;security@techhack.nl&gt;*. With the repository
configured (`gpgcheck=1`, `repo_gpgcheck=1`), `dnf` verifies signatures
automatically; you can also check a downloaded RPM with `rpm -K`.
