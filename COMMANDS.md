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
| [`info`](#info) | Show host / FIPS / GPU / scanner / provider status |
| [`scan`](#scan) | Scan for vulnerabilities; save findings; optional report/export |
| [`fix`](#fix) | Propose AI remediation and (with approval) apply it |
| [`report`](#report) | Render a report/export from the last saved scan |
| [`providers`](#providers) | List AI providers and their readiness |
| [`setup`](#setup) | First-run wizard: pick & download an offline AI model |
| [`update-oval`](#update-oval) | Download the OpenSCAP OVAL feed for this distro |
| [`scheduled`](#scheduled) | Non-interactive scan + dated report (systemd timer/cron) |

---

## Global options

These go **before** the command.

| Option | Description |
|---|---|
| `-h`, `--help` | Show help (works after any command too) |
| `--version` | Print the version and exit |
| `--config CONFIG` | Path to a config JSON (overrides the default search) |
| `--state-dir STATE_DIR` | Override the state/cache directory |
| `--provider PROVIDER` | AI provider: `claude` \| `openai` \| `gemini` \| `kimi` \| `local` |
| `--model MODEL` | Model id override (e.g. `claude-opus-4-8`, `llama3.2:1b`) |

```bash
vulnscan-ai --provider local --model llama3.2:1b fix
vulnscan-ai --config /etc/vulnscan-ai/config.json scan
```

### Severity values

Wherever `--min-severity` / `--fail-on` appear, use one of:
`low` < `moderate` < `important` < `critical` (`high`≡`important`, `medium`≡`moderate`).

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
| `--scanner NAME` | Scanner to run; repeatable. `dnf` (RHSA/updateinfo) and `oscap` (OpenSCAP/OVAL). Default: from config (`dnf`). |
| `--min-severity SEV` | Only keep findings at/above this severity. |
| `--no-enrich` | Skip Red Hat/NVD CVE-feed lookups (faster; fully offline). |
| `--pdf PATH` | Also write a PDF report. |
| `--json PATH` | Also write a JSON export. |
| `--sarif PATH` | Also write a SARIF 2.1.0 file (GitHub code scanning, DefectDojo). |

### Scan examples

```bash
# Default scan: dnf + enrichment, prints table, saves findings
vulnscan-ai scan

# Only critical issues
vulnscan-ai scan --min-severity critical

# Use both detection backends
vulnscan-ai scan --scanner dnf --scanner oscap

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

```
vulnscan-ai fix [--scan] [--scanner NAME]... [--no-enrich]
                [--min-severity SEV] [--yes] [--dry-run] [--pdf PATH]
```

| Option | Description |
|---|---|
| `--scan` | Scan first instead of using the last saved findings. |
| `--scanner NAME` | Scanner(s) to use when `--scan` is given (repeatable). |
| `--no-enrich` | Skip CVE-feed enrichment when `--scan` is given. |
| `--min-severity SEV` | Only act on findings at/above this severity. |
| `--yes` | Auto-approve every (screened) fix — non-interactive. |
| `--dry-run` | Produce the plan but execute nothing. |
| `--pdf PATH` | Write a PDF report after fixing. |

Interactive prompt per finding: `[y]es / [n]o / [a]ll / [q]uit`.

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
```

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
| `local` | (none) | `OLLAMA_HOST`, `OLLAMA_MODEL`, `OLLAMA_TIMEOUT` |

---

## `setup`

Interactive first-run wizard: detects GPU/RAM, lists offline models sized to your
host, can install Ollama, downloads your pick, and saves it as the default
provider/model. Also offered automatically on the first interactive run.

```bash
vulnscan-ai setup
```
No options. Suppress the auto-prompt with `VULNSCANAI_NO_SETUP=1`.

---

## `update-oval`

Detect the distro and download/stage the OpenSCAP OVAL CVE feed under
`<state-dir>/oval/`, enabling the `oscap` scanner.

```bash
vulnscan-ai update-oval
vulnscan-ai scan --scanner dnf --scanner oscap   # then scan with it
```
No options.

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
