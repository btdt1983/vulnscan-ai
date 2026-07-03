# vulnscan-ai — Command Reference

Complete reference for every `vulnscan-ai` command and option, with examples.
All commands run on RHEL-based distros (RHEL, AlmaLinux, Rocky, CentOS Stream,
Fedora). The tool is FIPS-aware and applies fixes only after explicit approval.

```
vulnscan-ai [GLOBAL OPTIONS] <command> [COMMAND OPTIONS]
```

## Commands at a glance

| Command | Purpose |
|---|---|
| [`menu`](#menu) | Interactive menu covering every command (also the default with no command) |
| [`info`](#info) | Show host / FIPS / GPU / scanner / provider status |
| [`scan`](#scan) | Scan for vulnerabilities; save findings; optional report/export |
| [`fix`](#fix) | Propose AI remediation and (with approval) apply it — transactional, with auto-rollback |
| [`rollback`](#rollback) | Restore a previously-applied transactional fix from its backup |
| [`report`](#report) | Render a report/export from the last saved scan |
| [`providers`](#providers) | List AI providers and their readiness |
| [`setup`](#setup) | First-run wizard: choose an offline model or a cloud provider + API key |
| [`update-oval`](#update-oval) | Download the OpenSCAP OVAL feed for this distro |
| [`scheduled`](#scheduled) | Non-interactive scan + dated report (systemd timer/cron) |
| [`dashboard`](#dashboard) | Serve saved findings over an HTTPS login dashboard |
| [`news`](#news) | Show recent vulnerability advisories (CISA KEV, NVD, distro errata) |

---

## Global options

These go **before** the command.

| Option | Description |
|---|---|
| `-h`, `--help` | Show help (works after any command too) |
| `--version` | Print the version and exit |
| `--no-banner` | Suppress the startup banner (also via `VULNSCANAI_NO_BANNER`) |
| `--config CONFIG` | Path to a config JSON (overrides the default search) |
| `--state-dir STATE_DIR` | Override the state/cache directory |
| `--provider PROVIDER` | AI provider: `claude` \| `openai` \| `gemini` \| `kimi` \| `deepseek` \| `mistral` \| `local` |
| `--model MODEL` | Model id override (e.g. `claude-opus-4-8`, `llama3.2:1b`) |
| `--effort LEVEL` | Claude reasoning effort: `low` \| `medium` \| `high` \| `xhigh` \| `max`. Turns on adaptive thinking; other providers ignore it. |

```bash
vulnscan-ai --provider local --model llama3.2:1b fix
vulnscan-ai --config /etc/vulnscan-ai/config.json scan
# Claude, most capable model, maximum reasoning effort for the hardest fixes
vulnscan-ai --provider claude --model claude-opus-4-8 --effort max fix --dry-run
```

### Severity values

Wherever `--min-severity` / `--fail-on` appear, use one of:
`low` < `moderate` < `important` < `critical` (`high`≡`important`, `medium`≡`moderate`).

---

## `menu`

Launch an interactive, menu-driven front-end so you don't have to remember flags.
It covers **every** command: scan, fix, rollback, report, news, info, providers,
dashboard, scheduled, update-oval and setup.

```bash
vulnscan-ai menu     # explicit
vulnscan-ai          # same thing — with no command on a terminal, the menu opens
```

Navigate with the arrow keys and Enter (a highlighted arrow-key list); press `q`
or Esc to go back. On terminals without cursor support (dumb terminals, some SSH
sessions, `TERM=dumb`, or `VULNSCANAI_NO_CURSES=1`) it automatically falls back
to a plain numbered prompt. Each choice is turned into the ordinary command and
run, so behaviour is identical to typing it by hand. Piped/non-interactive runs
(no TTY) still print help instead of opening the menu, so scripts are unaffected.

No options.

---

## `info`

Show tool version, FIPS status, **GPU/CPU**, available scanners, and AI provider
readiness.

```bash
vulnscan-ai info
```
No options. Example output includes lines like:
`FIPS mode: disabled`, `GPU: none detected — local models run on CPU`,
`dnf available`, `oscap available`, `local ready`.

---

## `scan`

Detect vulnerabilities, de-duplicate, enrich from CVE feeds, print a table, and
save findings to `<state-dir>/findings.json`. This is the primary command.

```
vulnscan-ai scan [--scanner NAME]... [--min-severity SEV] [--no-enrich]
                 [--pdf PATH] [--json PATH] [--sarif PATH]
```

| Option | Description |
|---|---|
| `--scanner NAME` | Scanner to run; repeatable. `dnf` (RHSA/updateinfo), `oscap` (OpenSCAP/OVAL), `ssh` (sshd hardening), `systemd` (service sandboxing), `ports` (network exposure), `webroot` (exposed files in web document roots), `container` (Podman/Docker runtime hardening). Default: from config (`dnf`). |
| `--all` | Run **every** available scanner (overrides `--scanner`). Unavailable ones are skipped. |

> **`systemd` scanner.** Wraps `systemd-analyze security`. Conservative by
> default: only `UNSAFE` units at/above exposure `9.0`, excluding un-hardenable/
> internal units (getty, emergency, `systemd-*`, …) and units that aren't
> enabled/active. Tune the floor with `VULNSCANAI_SYSTEMD_MIN_EXPOSURE` (e.g.
> `9.6` for only the worst, `0` for all UNSAFE). Fixes are systemd drop-ins
> applied transactionally (backup → write → `daemon-reload` → `systemd-analyze
> verify` → restart → rollback).

> **`ports` scanner.** Wraps `ss -tulpn`. Conservative: flags only sockets on a
> non-loopback address that are a plaintext/legacy protocol (telnet, ftp, tftp,
> rsh, vnc, X11, …) or a sensitive service that should not face the network
> (mysql, postgresql, redis, mongodb, memcached, elasticsearch, …). Expected
> public services (HTTP/HTTPS/SSH) are not flagged. The AI picks the fix
> (bind-to-localhost, firewall rule, or disable), transactional when it touches a
> config/service.

> **`webroot` scanner.** Finds files inside a web document root that a visitor
> could fetch over HTTP but should never be public: database dumps (`*.sql`,
> `*.sqlite`), env/config with secrets (`.env`, `wp-config.php`), version-control
> dirs (`.git/`), editor/backup leftovers (`*.bak`, `*~`), archives, private keys
> — plus world-writable files. Document roots are read from the server config
> (nginx `root`, Apache `DocumentRoot`, lighttpd `server.document-root`, LiteSpeed
> `docRoot`) and well-known defaults. Filesystem-only and conservative (server
> config may still deny a path — noted per finding); the AI proposes moving/
> deleting the file, a deny rule, or tighter permissions.

> **`container` scanner.** Inspects **running** Podman and Docker containers
> (`<runtime> ps` + `inspect`, read-only, no images pulled) and flags unsafe
> runtime settings, CIS-Docker style: `--privileged`, the runtime control socket
> or sensitive host paths (`/`, `/etc`, `/var/lib/containers`, …) bind-mounted,
> host network/PID/IPC namespaces, dangerous added capabilities (`SYS_ADMIN`,
> `SYS_MODULE`, `--cap-add ALL`, …), disabled seccomp/AppArmor/SELinux, and root
> as the container user. Conservative: benign mounts are ignored, read-only
> mounts downgraded a step, `--privileged` reported once. These are runtime
> findings, so the AI's fix is to **recreate the container** without the flag (no
> service to reload) — review before acting.

> **Exploitation intel (CISA KEV + EPSS).** During enrichment, every finding's
> CVE is checked against the **CISA KEV** catalog (actively exploited in the
> wild) and the **EPSS** exploit-probability score. KEV findings are tagged
> `[KEV]`, sorted to the top, and raised to at least `important` so they can't
> hide below the severity floor; a high probability shows as `[EPSS xx%]`. This
> reuses the advisory feeds (see [`news`](#news)); disable with
> `"exploit_enrich": false` or `--no-enrich`.
| `--min-severity SEV` | Only keep findings at/above this severity. |
| `--no-enrich` | Skip Red Hat/NVD CVE-feed lookups (faster; fully offline). |
| `--pdf PATH` | Also write a PDF report. |
| `--json PATH` | Also write a JSON export. |
| `--sarif PATH` | Also write a SARIF 2.1.0 file (GitHub code scanning, DefectDojo). |
| `--ignore PATTERN` | Suppress findings matching id / CVE / advisory / package / title (glob, repeatable). Augments the configured baseline. |

> **Reducing false positives.** Several measures run automatically: the `oscap`
> scanner only reports real *patch* advisories (inventory/compliance definitions
> are dropped) with proper CVE ids + severity; the `ports` scanner suppresses
> ports that firewalld blocks; and findings that the `dnf` and `oscap` scanners
> both report (same advisory/CVE) are merged. **Already-patched**: a package
> finding whose fix is in the metadata but has no installable update per
> `dnf check-update` is dropped — this clears the common lingering-old-kernel
> noise where the scanners list historical kernel advisories that `dnf` reports
> as "Nothing to do" because the newest kernel is already installed (disable with
> `"patched_filter": false`). Use a **baseline** to silence
> accepted findings: set `"ignore": [...]` in the config, list patterns (one per
> line) in `~/.config/vulnscan-ai/ignore`, set `VULNSCANAI_IGNORE=a,b`, or pass
> `--ignore`. Patterns match a finding id, CVE, advisory, package, or title
> (globs allowed); the scan prints how many were suppressed.

### Scan examples

```bash
# Default scan: dnf + enrichment, prints table, saves findings
vulnscan-ai scan

# Only critical issues
vulnscan-ai scan --min-severity critical

# Use both detection backends
vulnscan-ai scan --scanner dnf --scanner oscap

# Run every available scanner at once
vulnscan-ai scan --all

# Fully offline scan (no CVE-feed calls)
vulnscan-ai scan --no-enrich

# Scan and produce all three artifacts at once
vulnscan-ai scan --pdf report.pdf --json findings.json --sarif findings.sarif

# Scan with OpenSCAP only, important+ severity, to a PDF
vulnscan-ai scan --scanner oscap --min-severity important --pdf oscap.pdf

# Point at a different state dir (keeps findings separate)
vulnscan-ai --state-dir /srv/scans/web01 scan --min-severity moderate
```

> Tip: run [`update-oval`](#update-oval) once before using `--scanner oscap`.

---

## `fix`

Ask the AI provider to propose remediation for saved (or freshly scanned)
findings, then apply with approval. Proposed commands are screened against a
safety deny-list; nothing runs without confirmation unless `--yes`.

**Transactional fixes.** When a plan touches a config file or service (it
declares `backup_paths`/`service`/`validate_cmd`), `fix` runs it transactionally:
it snapshots the file(s), applies the change, **validates the config before
restarting** (e.g. `sshd -t`), reloads the service and checks it stays active —
and **automatically restores the backup if any step fails** (e.g. an sshd edit
that would lock you out). Backups live under `<state-dir>/backups/<id>/`; undo a
successful fix later with [`rollback`](#rollback).

**Live progress.** While a fix is applied, each step is streamed as it runs —
the backup, every command, the validate step, the service reload and health
check — together with the command's own output, so you can watch exactly what it
does instead of staring at a frozen prompt. A rollback (if triggered) prints the
same way.

**Sanitised plans.** AI proposals are cleaned before they can run: an invalid
`restart_mode` is normalised, echoed schema placeholders and non-command
"verify" strings are dropped, a malformed `--advisory=` id is rewritten to the
finding's real advisory, and package-CVE fixes (`dnf`/`oscap`) cannot carry
unrelated config backups or service restarts (those belong to config scanners).
A `dnf update` that reports **"Nothing to do"** is shown as `[no-change]` (not a
false success), so you can tell when an advisory didn't actually apply.

```
vulnscan-ai fix [--scan] [--scanner NAME]... [--no-enrich]
                [--min-severity SEV] [--yes] [--dry-run] [--pdf PATH]
                [--export-script PATH] [--export-ansible PATH]
```

| Option | Description |
|---|---|
| `--scan` | Scan first instead of using the last saved findings. |
| `--scanner NAME` | Scanner(s) to use when `--scan` is given (repeatable). |
| `--all` | With `--scan`: run every available scanner. |
| `--no-enrich` | Skip CVE-feed enrichment when `--scan` is given. |
| `--min-severity SEV` | Only act on findings at/above this severity. |
| `--yes` | Auto-approve every (screened) fix — non-interactive. |
| `--dry-run` | Produce the plan but execute nothing. |
| `--pdf PATH` | Write a PDF report after fixing. |
| `--export-script PATH` | Write a ready-to-run **bash** fix script (with backup/validate/rollback) and **do not apply**. |
| `--export-ansible PATH` | Write an **Ansible playbook** of the fixes and **do not apply**. |
| `--ignore PATTERN` | With `--scan`: suppress matching findings (glob, repeatable). |

Interactive prompt per finding: `[y]es / [n]o / [i]gnore / [a]ll / [q]uit`.
**`[i]gnore`** accepts the finding as expected and writes it to the persistent
baseline (`~/.config/vulnscan-ai/ignore`), so it won't be reported again — handy
for hardening findings you've reviewed and accepted (e.g. SSH password auth on a
LAN-only host). To accept a whole class at once instead, use a glob:
`--ignore "SSH*"` or add `SSH*` to the baseline file.

### Fix examples

```bash
# Interactive: review the last scan's findings and approve fixes one by one
vulnscan-ai fix

# Scan + fix in one step, plan only (safe preview), write a PDF plan
vulnscan-ai fix --scan --dry-run --pdf plan.pdf

# Only fix critical issues, approve each
vulnscan-ai fix --min-severity critical

# Non-interactive (CI/automation): apply every screened fix
vulnscan-ai fix --yes

# Offline AI (local model), dry-run
vulnscan-ai --provider local --model llama3.2:1b fix --dry-run

# Use Claude's most capable model for higher-quality plans
vulnscan-ai --provider claude --model claude-opus-4-8 fix --min-severity important

# Don't apply — generate a bash script and an Ansible playbook to review/run later
vulnscan-ai fix --export-script fix.sh --export-ansible fix.yml
```

---

## `rollback`

Restore a previously-applied **transactional** fix from the backup `fix` stored.
Useful if a change applied cleanly but you later want to revert it.

```
vulnscan-ai rollback [--list] [ID]
```

| Option | Description |
|---|---|
| `--list` | List fixes that have a stored backup (with their finding id and state). |
| `ID` | Finding id (from `--list`) to roll back. |

```bash
vulnscan-ai rollback --list      # see what can be restored
vulnscan-ai rollback 0a43d0c46dc7
```

Restoring re-applies the service so its runtime state matches the restored config.

---

## `report`

Render a report or machine-readable export from the **last saved scan**. The
format is chosen by the output file extension.

```
vulnscan-ai report -o PATH [--min-severity SEV]
```

| Option | Description |
|---|---|
| `-o`, `--output PATH` | Output file. Extension picks the format: `.pdf`, `.html`, `.json`, `.sarif`. Default `vulnscan-ai-report.pdf`. |
| `--min-severity SEV` | Only include findings at/above this severity. |

### Report examples

```bash
vulnscan-ai report -o latest.pdf
vulnscan-ai report -o findings.sarif --min-severity important
vulnscan-ai report -o findings.json
vulnscan-ai report -o report.html        # HTML instead of PDF
```

> PDF always produces a real PDF: `reportlab` if installed, otherwise a built-in
> dependency-free writer.

---

## `providers`

List AI providers, their default model, the API-key env var, and whether each is
ready (key present, or local server reachable).

```bash
vulnscan-ai providers
```
No options. `local` shows `ready` when an Ollama server answers.

Provider keys (set in the environment):

| Provider | Env var | Notes |
|---|---|---|
| `claude` | `ANTHROPIC_API_KEY` | default |
| `openai` | `OPENAI_API_KEY` | `OPENAI_BASE_URL` optional |
| `gemini` | `GEMINI_API_KEY` | |
| `kimi` | `MOONSHOT_API_KEY` | `MOONSHOT_BASE_URL` optional |
| `deepseek` | `DEEPSEEK_API_KEY` | DeepSeek-Coder; `DEEPSEEK_BASE_URL` optional |
| `mistral` | `MISTRAL_API_KEY` | Mixtral 8x7B; `MISTRAL_BASE_URL` optional |
| `local` | (none) | `OLLAMA_HOST`, `OLLAMA_MODEL`, `OLLAMA_TIMEOUT` (e.g. StarCoder 2) |

---

## `setup`

Interactive first-run wizard. Choose how the AI remediation step gets its model:

- **Local, offline (Ollama)** — detects GPU/RAM, lists offline models sized to
  your host, can install Ollama, downloads your pick, and saves it as the
  default provider/model. No API key; nothing leaves the host.
- **Cloud provider + API key** — pick `claude` / `openai` / `gemini` / `kimi` /
  `deepseek` / `mistral`; it prompts for the key (hidden input) and stores it in
  the per-user config (mode 0600). The model is chosen from a **menu of known
  ids** for that provider (with a *custom* option and a *default* fallback), so a
  typo'd id can't slip through; for Claude it also asks for the reasoning effort.

It then offers to set up email notifications. Also runs automatically on the
first interactive use.

**Re-run `setup` any time to switch backend, provider or model.** If a key for
the chosen cloud provider is already saved, it offers to **reuse it** — so you
can change just the model without pasting the key again. Choosing the local
backend takes effect immediately (the choice is saved up front), even if the
model download is deferred or you're offline and the model is already present.

```bash
vulnscan-ai setup
```
No options. Suppress the auto-prompt with `VULNSCANAI_NO_SETUP=1`.

> An API key is **not** a Claude Pro / ChatGPT Plus subscription — create a
> developer key (with billing) at the provider's console. A real `*_API_KEY`
> env var always takes precedence over a key stored by the wizard.

---

## `update-oval`

Detect the distro and download/stage the OpenSCAP OVAL CVE feed under
`<state-dir>/oval/`, enabling the `oscap` scanner.

```bash
vulnscan-ai update-oval
vulnscan-ai scan --scanner dnf --scanner oscap   # then scan with it
```
No options.

> **Auto-refresh.** You normally don't need to run this by hand: when a scan uses
> the `oscap` scanner and the staged feed is missing or older than
> `oval_max_age_days` (default **7**), it is downloaded automatically before the
> scan. This is TTL-gated (not a per-scan download), fail-soft (a failed refresh
> falls back to the existing feed), and skipped when offline (`--no-enrich`) or
> when `oval_auto_update` is `false` — set that on air-gapped hosts and stage the
> feed manually with this command.

---

## `scheduled`

Non-interactive scan + dated report, for the systemd timer or cron. **Never
applies fixes.** Rotates old reports and can signal severity via exit code.

```
vulnscan-ai scheduled [--scanner NAME]... [--no-enrich] [--min-severity SEV]
                      [--plan] [--html] [--keep N] [--fail-on SEVERITY]
```

| Option | Description |
|---|---|
| `--scanner NAME` | Scanner(s) to run (repeatable). |
| `--all` | Run every available scanner (overrides `--scanner`). |
| `--no-enrich` | Skip CVE-feed enrichment. |
| `--min-severity SEV` | Only keep findings at/above this severity. |
| `--plan` | Embed AI remediation proposals in the report (no execution). |
| `--html` | Write an HTML report instead of PDF. |
| `--keep N` | Retain only the newest N reports (default 30). |
| `--fail-on SEVERITY` | Exit `3` if any finding is at/above this severity. |

Reports are written to `<reports-dir>` (default `<state-dir>/reports/`) as
`vulnscan-<host>-<timestamp>.<ext>`.

### Scheduled examples

```bash
# What the timer runs by default
vulnscan-ai scheduled --keep 30

# Add offline AI proposals to each report
vulnscan-ai --provider local scheduled --plan

# Alert in monitoring: non-zero exit when important+ is present
vulnscan-ai scheduled --fail-on important   # exit 3 if any >= important

# Enable the daily timer (installed by the RPM)
sudo systemctl enable --now vulnscan-ai.timer
```

---

## `dashboard`

Serve the saved findings over a small HTTPS web UI behind a login. stdlib only,
self-signed certificate on first run, a single admin account.

```
vulnscan-ai dashboard [--port N] [--bind ADDR]
vulnscan-ai dashboard --set-password [--user NAME]
vulnscan-ai dashboard --allow IP/CIDR ... | --deny IP/CIDR ... | --list
```

| Option | Description |
|---|---|
| `--set-password` | Prompt for and store the admin password (PBKDF2-SHA256), then exit. |
| `--user NAME` | Admin username (default `admin`). |
| `--allow IP/CIDR` | Permit a network client besides localhost (repeatable), then exit. |
| `--deny IP/CIDR` | Remove a permitted client (repeatable), then exit. |
| `--list` | Show user / port / bind / allow-list, then exit. |
| `--port N` | Listen port (default `65101`). |
| `--bind ADDR` | Bind address (default `127.0.0.1`; auto `0.0.0.0` when an allow-list is set). |

Refuses to start until a password is set. Binds to localhost only unless an
allow-list opens it to specific network clients; loopback is always allowed.
Also serves `GET /api/findings.json` (authenticated). Run it as a service with
`systemctl enable --now vulnscan-ai-dashboard`.

**Summary tiles.** The overview shows total and per-severity counts, plus an
**actively-exploited (CISA KEV)** tile and an **EPSS ≥50%** tile whenever a
finding matches — the highest-priority signals up front.

**Actions in the UI.** A **Scan now** button runs the configured scanners in the
background; per-finding **Preview fix** shows the AI's proposed plan (dry-run, no
execution). **Apply fix** runs the fix transactionally on the host and is **off
by default** — set `"dashboard_allow_fix": true` in the config to make the Apply
button appear (login + allow-list still apply). `--list` shows this state.

**Advisories tab.** A second tab shows recent vulnerability [news](#news) (CISA
KEV, NVD, distro errata), refreshed in the background and cached so it works
offline. Advisories whose CVE matches your last scan are flagged **on this host**.

```bash
sudo vulnscan-ai dashboard --set-password
ssh -L 65101:localhost:65101 host    # then browse https://localhost:65101/
```

---

## `news`

Show recent vulnerability advisories aggregated from public feeds. The same
feeds also enrich `scan` findings (see the exploitation-intel note under
[`scan`](#scan)).

```
vulnscan-ai news [--source kev|nvd|distro] [--refresh] [--limit N]
```

| Option | Description |
|---|---|
| `--source NAME` | Show only one feed: `kev` (CISA Known Exploited), `nvd` (recent NVD CVEs), or `distro` (the host distribution's errata). |
| `--refresh` | Fetch fresh data instead of the on-disk cache. |
| `--limit N` | Maximum advisories to show (default 30). |

Sources (all stdlib HTTP over FIPS-hardened TLS; URLs are fixed, never
user-supplied):

- **CISA KEV** — Known Exploited Vulnerabilities (actively exploited in the wild).
- **NVD** — recently published CVEs (NIST NVD API 2.0).
- **distro errata** — the host distribution's own advisories: AlmaLinux, Rocky
  Linux (RESF/Apollo) and Oracle Linux (ELSA), selected automatically.

Advisories are cached under `<state-dir>/news-cache.json` so the command (and the
dashboard tab) work offline. Items whose CVE matches the last scan are tagged
`[on-host]`; actively-exploited ones carry `[KEV]` and a high `[EPSS xx%]` score.
Configure with `news_enabled`, `news_sources`, `news_refresh_hours`.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | No findings to act on / a step failed (e.g. OVAL download) |
| `2` | AI provider error (e.g. key missing / model unreachable) |
| `3` | `scheduled --fail-on` threshold met (findings at/above severity) |
| `130` | Interrupted (Ctrl-C) |

## Configuration precedence

Highest wins: **command-line flags** → **environment** (`VULNSCANAI_*`,
provider keys) → **user config** (`~/.config/vulnscan-ai/config.json`) →
**system config** (`/etc/vulnscan-ai/config.json`) → built-in defaults.
