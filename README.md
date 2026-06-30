# vulnscan-ai

[![CI](https://github.com/btdt1983/vulnscan-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/btdt1983/vulnscan-ai/actions/workflows/ci.yml)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue)](LICENSE)
[![Release](https://img.shields.io/github/v/release/btdt1983/vulnscan-ai)](https://github.com/btdt1983/vulnscan-ai/releases)

**[Website](https://vulnscan-ai.techhack.nl)** · **[Install via dnf](https://repo.techhack.nl)** · **[Command reference](COMMANDS.md)** · **[Contributing](CONTRIBUTING.md)**

A FIPS-aware command-line tool for **RHEL-based distributions** (RHEL,
AlmaLinux, Rocky, CentOS Stream, Fedora) that:

1. **Scans** the host for known vulnerabilities using native and public sources,
2. **enriches** findings from online vulnerability databases,
3. uses an **LLM** (Claude by default; OpenAI / Gemini / Kimi / DeepSeek /
   Mistral / local optional) to **propose remediation**,
4. **applies fixes only after explicit approval** (or in `--dry-run`), screening
   every command against a safety deny-list,
5. exports a **PDF report** (or HTML when `reportlab` isn't installed).

It uses CLI tools under the hood (`dnf`/`yum`, `rpm`, optionally `oscap`) and
queries vulnerability websites (Red Hat Security Data API, NIST NVD).

---

## Why these choices

| Decision | Choice |
|---|---|
| Language | Python 3 (ships on RHEL; no mandatory 3rd-party deps) |
| Scanners | CVE: `dnf`/RHSA, OpenSCAP/OVAL, NVD/Red Hat feeds. Hardening/exposure: `ssh`, `systemd`, `ports`, `webroot`, `container` |
| Fix mode | **Suggest + approve** by default (safest for prod/FIPS) |
| AI backend | **Claude** default; pluggable adapters for the rest |

## FIPS posture

- No bundled cryptography. All TLS/hashing uses the **system OpenSSL**, which
  is the FIPS 140-validated module on RHEL.
- FIPS mode is auto-detected from `/proc/sys/crypto/fips_enabled`
  (`vulnscan-ai info` shows the status).
- Outbound HTTPS pins **TLS 1.2+** and honours the system crypto policy.
- Hashing uses **SHA-256** only; legacy digests (md5) are never used, so the
  tool keeps working when the FIPS policy disables them.
- For data-sensitive / air-gapped sites, use `--provider local` so no finding
  data leaves the host.

## Install

```bash
# core tool (no third-party deps required) — PDF works out of the box
pip install .

# optional: richer PDF layout via reportlab (otherwise the built-in
# dependency-free PDF writer is used automatically)
pip install '.[pdf]'        # pulls in reportlab
# or on RHEL:  dnf install python3-reportlab
```

Runs directly from a checkout too: `python -m vulnscanai ...`

## Configure the AI provider

The AI step proposes fixes (you approve them). Claude is the default. There are
two ways to set it up.

### Easiest: the setup wizard

Run **`vulnscan-ai setup`** (it also runs on the first interactive use) and pick:

- **A cloud provider** — `claude` / `openai` / `gemini` / `kimi` / `deepseek` /
  `mistral`. Paste the API key (hidden input), optionally choose a model and, for
  Claude, the reasoning effort. The key is stored in the per-user config (mode
  0600) and used automatically — no environment variable to manage.
- **A local, offline model** — download an Ollama model sized to the host; no
  key, nothing leaves the machine.

> An API key is **not** a Claude Pro / ChatGPT Plus subscription — create a
> developer key (with billing) at the provider's console (`console.anthropic.com`,
> `platform.openai.com`, …). **Nothing to install for the cloud providers:**
> vulnscan-ai calls the plain REST API (no SDK, no "Claude Code") — you only need
> the key and network access to the provider.

### Manual: environment variables

Or set the key yourself — a real env var always wins over a wizard-stored one:

```bash
export ANTHROPIC_API_KEY=sk-ant-...      # claude (default)
export OPENAI_API_KEY=...                # openai
export GEMINI_API_KEY=...                # gemini
export MOONSHOT_API_KEY=...              # kimi
export DEEPSEEK_API_KEY=...              # deepseek (DeepSeek-Coder)
export MISTRAL_API_KEY=...               # mistral (Mixtral 8x7B)
export OLLAMA_HOST=http://127.0.0.1:11434  # local (no key)
export OLLAMA_MODEL=llama3.2:1b          # local model to use
export NVD_API_KEY=...                   # optional, higher NVD rate limit
```

DeepSeek and Mistral both speak the OpenAI Chat Completions API; override the
endpoint with `DEEPSEEK_BASE_URL` / `MISTRAL_BASE_URL` and the model with
`--model` (e.g. `deepseek-chat`, `mistral-large-latest`). **StarCoder 2** has no
hosted API — run it offline through the `local` provider:
`vulnscan-ai --provider local --model starcoder2 fix` (after `ollama pull starcoder2`).

**Model and reasoning effort.** Pick the model with `--model` (or the `model`
config), e.g. `--model claude-opus-4-8` for the most capable Claude. For Claude
you can also dial the **reasoning effort** with `--effort low|medium|high|xhigh|max`
(config `claude_effort`, env `VULNSCANAI_CLAUDE_EFFORT`) — it turns on adaptive
thinking, so the model reasons harder on tricky fixes. Use `max` when correctness
matters more than cost; other providers ignore the flag.

### Fully offline / air-gapped (Ollama)

No API key, no external calls — the AI step runs against a local model.

**Easiest: the setup wizard.** On the first interactive run the tool offers a
menu of offline models (sized to your host's RAM), can install Ollama, downloads
your pick, and saves it as the default. Run it any time with:

```bash
vulnscan-ai setup
```

```
 vulnscan-ai setup — offline AI model
 Detected RAM: 7.3 GB total, 2.0 GB available.
   #  model            download   needs RAM   notes
   1  qwen2.5:0.5b       0.4 GB        fits  tiny & fastest (recommended)
   2  llama3.2:1b        1.3 GB  tight/swap  good balance, CPU-friendly
   3  llama3.2:3b        2.0 GB  tight/swap  better quality
   ...
   0  skip for now
```

The auto-prompt only appears on an interactive terminal (never for the systemd
timer); suppress it with `VULNSCANAI_NO_SETUP=1`.

**GPU support.** Ollama runs the chosen model GPU-accelerated automatically when
an NVIDIA/AMD GPU with drivers is present — no different model or config needed.
The wizard detects the GPU, sizes the menu against **VRAM** (offering larger,
higher-quality models), and `vulnscan-ai info` reports the GPU. On a CPU-only
host it sizes against RAM and steers you to smaller models.

**Manual equivalent:**

```bash
curl -fsSL https://ollama.com/install.sh | sh
sudo systemctl enable --now ollama
ollama pull llama3.2:1b
vulnscan-ai providers            # 'local' shows 'ready' when the server answers
vulnscan-ai --provider local --model llama3.2:1b fix --min-severity important
```

The tool asks Ollama for JSON-constrained output, so even small models return
parseable remediation plans. Disabling enrichment (`--no-enrich`) makes a scan
fully offline too; the OVAL/RHSA data can be pre-staged with `update-oval` and
a mirrored repo.

## Usage

> See **[COMMANDS.md](COMMANDS.md)** for the full command reference (every
> command, all options, examples, exit codes, and config precedence).

```bash
# Show host / FIPS / scanner / provider status
vulnscan-ai info

# Scan, save findings, and write a PDF
vulnscan-ai scan --pdf report.pdf

# Only show important+ issues
vulnscan-ai scan --min-severity important

# Propose fixes with Claude and approve them interactively
vulnscan-ai fix

# Scan + fix in one go, dry-run (plan only, executes nothing), PDF out
vulnscan-ai fix --scan --dry-run --pdf plan.pdf

# Use a different provider/model
vulnscan-ai --provider openai --model gpt-4o fix
vulnscan-ai --provider claude --model claude-opus-4-8 fix

# Non-interactive (CI): auto-approve every screened fix
vulnscan-ai fix --yes

# Re-render a report from the last scan
vulnscan-ai report -o latest.pdf

# Stage the OpenSCAP OVAL feed for this distro, then scan with it
vulnscan-ai update-oval
vulnscan-ai scan --scanner dnf --scanner oscap --pdf report.pdf

# Audit sshd hardening (root login, weak ciphers/MACs/KEX, ...)
vulnscan-ai scan --scanner ssh

# Audit systemd service sandboxing (systemd-analyze security)
vulnscan-ai scan --scanner systemd

# Audit network exposure (risky listening ports via ss)
vulnscan-ai scan --scanner ports

# Audit web document roots for exposed files (.sql dumps, .env, .git/, backups)
vulnscan-ai scan --scanner webroot

# Audit running Podman/Docker containers for unsafe runtime settings
vulnscan-ai scan --scanner container

# Run every available scanner at once
vulnscan-ai scan --all
```

The `systemd` scanner is conservative by default (only `UNSAFE`, enabled
services, exposure ≥ 9.0, skipping un-hardenable units); widen or narrow it with
`VULNSCANAI_SYSTEMD_MIN_EXPOSURE`. Its fixes are systemd drop-ins applied through
the same transactional engine (`daemon-reload` → `systemd-analyze verify` →
restart → rollback).

### Keeping false positives low

The scanners are built to avoid noise:

- **OVAL (`oscap`)** reports only real *patch* advisories — `inventory`/compliance
  definitions (e.g. "the OS is installed") are dropped — with proper CVE ids and
  severities pulled from the feed metadata.
- **`ports`** suppresses ports the host firewall blocks (a socket on `0.0.0.0`
  isn't an exposure if the firewall drops it). It reads **firewalld** when
  running and falls back to raw **nftables** (`nft --json list ruleset`) on
  hosts without it — honouring a default-deny `input` policy, accept rules
  (single port, named sets, ranges) and explicit drop/reject rules. It only
  suppresses a port it can confidently prove blocked, so a parse miss never
  hides a real exposure.
- Findings that **`dnf` and `oscap` both report** (same advisory/CVE) are merged
  into one.
- **Vendor fix state** (during enrichment): Red Hat publishes, per CVE and per
  product, whether each package is actually affected. Findings Red Hat marks
  **"Not affected"** for this RHEL release are dropped as confirmed false
  positives; **"Will not fix" / "Out of support scope" / "Fix deferred"** are
  kept but annotated (a real issue with no dnf update coming — mitigate
  manually), so the AI won't propose a pointless `dnf update`. Disable with
  `"vendor_state_filter": false` in the config.
- **Runtime exposure** (local, `rpm` + `systemctl`): a vulnerable daemon package
  whose service units are **all stopped *and* disabled/masked** isn't exposed
  until someone starts it, so the finding is **downgraded to `low`** and
  annotated (it still shows in the full report, and resurfaces at full severity
  if you enable the unit). Conservative by design: packages shipping **no**
  service unit (libraries, CLI tools like `openssl`/`glibc`) are never touched,
  a unit that is enabled, `static` or has a listening socket counts as exposed,
  and an undetermined state keeps full severity. Disable with
  `"service_state_filter": false` in the config.
- **`container`** only inspects **running** containers and flags settings that are
  unambiguously dangerous (`--privileged`, the runtime control socket or sensitive
  host paths bind-mounted, host network/PID/IPC namespaces, dangerous added
  capabilities, disabled seccomp/SELinux). Benign bind mounts are ignored,
  read-only mounts are downgraded a step, and `--privileged` is reported once
  rather than as a flood of per-capability findings.
- A **baseline** silences accepted findings: `"ignore": [...]` in the config,
  one-per-line in `~/.config/vulnscan-ai/ignore`, `VULNSCANAI_IGNORE=a,b`, or
  `--ignore PATTERN`. Patterns match a finding id, CVE, advisory, package, or
  title (globs allowed); the scan reports how many it suppressed.

PDF output always produces a real PDF: it uses `reportlab` if installed,
otherwise a built-in dependency-free PDF writer. Use a `.html` extension to
get an HTML report instead.

### Safe fixes: transactional apply with auto-rollback

When a fix touches a **config file or service** (e.g. an sshd hardening finding),
`fix` applies it transactionally instead of blindly running commands:

1. **Backup** the affected file(s) under `<state-dir>/backups/<id>/`.
2. **Apply** the change.
3. **Validate before restart** — e.g. `sshd -t` — so a broken config never reaches a restart.
4. **Reload** the service (preferring `reload` over `restart`) and confirm it stays active.
5. **Auto-rollback** — if *any* step fails, the backup is restored and the service brought back, so a bad sshd edit can't lock you out.

Every step is **streamed live** as it runs — backup, each command, the validate
step, the reload/health check (and any rollback) — along with the command's own
output, so you can see exactly what the fix is doing while it does it.

```bash
# AI proposes + applies, with the safety net above
vulnscan-ai fix --scanner ssh --scan

# Undo a fix later from its stored backup
vulnscan-ai rollback --list
vulnscan-ai rollback <finding-id>
```

Don't want to apply on the spot? Generate a reviewable artifact instead — a
self-contained bash script (with the same backup/validate/rollback logic) or an
Ansible playbook:

```bash
vulnscan-ai fix --export-script fix.sh --export-ansible fix.yml
```

### Machine-readable export (ticketing / code scanning)

Output format is chosen by file extension — `.pdf`, `.html`, `.json`, or
`.sarif` (SARIF 2.1.0):

```bash
vulnscan-ai scan --sarif findings.sarif --json findings.json
vulnscan-ai report -o findings.sarif        # from the last saved scan
```

- **SARIF 2.1.0** ingests into GitHub code scanning, DefectDojo, and most
  vuln-management pipelines. Severity maps to SARIF levels
  (critical/important→`error`, moderate→`warning`, low→`note`) and each result
  carries a numeric `security-severity` (CVSS when known) plus CVE/advisory/
  package/fix metadata and a stable `partialFingerprints` id.
- **JSON** is a flat document: tool metadata, a severity summary, and the full
  findings (including any AI remediation).

Typical operator loop: `scan` → review the table → `fix` (approve per-item) →
PDF is attached to your change ticket.

## Scheduled unattended scans (systemd timer)

The `scheduled` subcommand runs non-interactively: it scans, writes a dated
report to the reports directory, rotates old ones, and **never applies fixes**.

```bash
# what the timer runs
vulnscan-ai scheduled --keep 30
# with AI remediation proposals embedded (needs a provider key; no execution)
vulnscan-ai scheduled --plan
# CI/monitoring: non-zero exit when something serious is found
vulnscan-ai scheduled --fail-on important   # exit 3 if any >= important
```

The RPM installs a `vulnscan-ai.timer` (daily, 1h jitter, catch-up). Enable it:

```bash
sudo systemctl enable --now vulnscan-ai.timer
systemctl list-timers vulnscan-ai.timer
journalctl -u vulnscan-ai.service        # last run's output
ls /var/lib/vulnscan-ai/reports/         # generated PDFs
```

Scan-only runs need no API key and send nothing off the host. To enable
`--plan`, put a key in `/etc/vulnscan-ai/vulnscan-ai.env` (mode 0640) and add
`--plan` to `ExecStart` (override with `systemctl edit vulnscan-ai.service`).

### Drift between scans

Every `scan` compares against the previously saved findings and prints what is
**new** and what is **resolved** since the last run, so you can see a host's
posture move over time. `scheduled` reports the same drift counts.

### Email notifications

A scheduled scan can email a plain-text summary when it finds anything at or
above a severity, or anything new since the last scan. Configure it in the
wizard (`vulnscan-ai setup` → *Email notifications*) or in the config:

```json
{
  "notify_email": "ops@example.com",
  "notify_min_severity": "important",
  "smtp_host": "smtp.example.com",
  "smtp_port": 587,
  "smtp_from": "vulnscan-ai@example.com",
  "smtp_user": "vulnscan-ai",
  "smtp_starttls": true
}
```

The SMTP password is read from `VULNSCANAI_SMTP_PASSWORD` (preferred) or
`smtp_password` in the config. Sending never breaks a scan — a failed mail is
logged and the run continues. With no `notify_email` set, nothing is sent.

## Dashboard (HTTPS, login)

`vulnscan-ai dashboard` serves the saved findings — with their explanations,
CVEs and any AI fix plan — over a small HTTPS web UI behind a login. It is
stdlib-only (no extra packages), uses a self-signed certificate generated on
first run, and a single admin account — username **`admin`** by default
(change with `--user`), PBKDF2-SHA256 password hash. On start it prints the
login username, and a firewall hint if the port looks closed in firewalld.

```bash
# 1. Set the admin password (stored hashed; user 'admin' unless --user given)
sudo vulnscan-ai dashboard --set-password

# 2. Run it (foreground), or enable the service
sudo vulnscan-ai dashboard                 # https://<host>:65101/
sudo systemctl enable --now vulnscan-ai-dashboard
```

By default it **binds to localhost only** — reach it with an SSH tunnel
(`ssh -L 65101:localhost:65101 host`). To let specific machines in, add them to
the allow-list (from the CLI or the dashboard itself); the server then also
listens on the network, but **only** the allow-listed clients (and localhost)
are served:

```bash
sudo vulnscan-ai dashboard --allow 10.0.0.0/24 --allow 192.168.1.5
sudo vulnscan-ai dashboard --list            # show user/port/bind/allow-list
```

It refuses to start until a password is set, so findings are never exposed
unauthenticated. Port (`--port`, default 65101) and bind address (`--bind`) are
overridable.

### Scan and fix from the dashboard

- **Scan now** (header button) runs the configured scanners in the background
  and refreshes the page when done.
- **Preview fix** (per finding) asks the AI for a remediation and shows the
  plan — a dry-run, nothing is executed. Needs an AI provider configured.
- **Apply fix** actually runs the fix on the host (transactional, with
  auto-rollback). It is **off by default** — the dashboard stays read-only
  unless you opt in with `"dashboard_allow_fix": true` in the config. Only then
  does the Apply button appear. (Login + the allow-list still gate access.)

Opening it to the network is two layers: the app allow-list **and** the host
firewall. firewalld blocks the port by default — allow it only for your clients:

```bash
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" \
  source address="192.168.0.0/24" port port="65101" protocol="tcp" accept'
sudo firewall-cmd --reload
```

## Safety model

- The model **only proposes** commands; it never executes anything itself.
- Proposed commands pass through a deny-list (`rm -rf /`, `mkfs`, `curl|sh`,
  `setenforce 0`, `--nodeps`, package removal, crypto-policy downgrade, …)
  before they can run.
- Nothing runs without per-finding approval unless you pass `--yes`.
- `--dry-run` records the full plan in the report without touching the system.
- Fixes that require a reboot are flagged in the output and report.
- Config/service fixes are **transactional**: backup → apply → validate before
  restart → reload → **auto-rollback on failure**, so a bad edit can't strand a
  service. Restore later with `rollback`.

## Layout

```
vulnscanai/
  cli.py            # argparse CLI: info/scan/fix/rollback/report/providers/...
  config.py         # config file + env + flag precedence
  fips.py           # FIPS detection, approved hashing, hardened TLS context
  http.py           # stdlib HTTP over the hardened TLS context
  models.py         # Finding / Remediation dataclasses
  remediation.py    # AI prompt, JSON parse, screening, transactional apply+rollback
  export_fix.py     # render fixes as a bash script or Ansible playbook
  report.py         # block model + reportlab / native-PDF / HTML renderers
  pdfwriter.py      # dependency-free PDF writer (built-in fonts)
  scanners/         # dnf+RHSA, OpenSCAP/OVAL, sshd/systemd/ports hardening, CVE enrich
  ai/               # claude (default), openai, gemini, kimi, deepseek, mistral, local
```

## Disclaimer

Automated remediation changes a live system. Review proposals, prefer
`--dry-run` first, and test on non-production hosts. AI suggestions can be
wrong — the approval gate exists for a reason.

## License

Copyright (C) 2026 techhack. Licensed under the **GNU Affero General Public
License v3.0 or later** ([AGPL-3.0-or-later](LICENSE)). This keeps the project
open: anyone who runs a modified version — including over a network as a service
— must make their source available under the same terms.

The copyright holder retains the right to offer the software under separate
**commercial terms**. Contributions are accepted under the
[Contributor License Agreement](CLA.md) (see [CONTRIBUTING.md](CONTRIBUTING.md)),
which preserves that option. For a commercial license, contact
btdt1983@protonmail.com.
