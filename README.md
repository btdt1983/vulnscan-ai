# vulnscan-ai

A FIPS-aware command-line tool for **RHEL-based distributions** (RHEL,
AlmaLinux, Rocky, CentOS Stream, Fedora) that:

1. **Scans** the host for known vulnerabilities using native and public sources,
2. **enriches** findings from online vulnerability databases,
3. uses an **LLM** (Claude by default; OpenAI / Gemini / Kimi / local optional)
   to **propose remediation**,
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
| Scanners | `dnf`/`yum` + RHSA, OpenSCAP/OVAL, NVD/Red Hat CVE feeds |
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

Set the key for whichever provider you use (Claude is the default):

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
```

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

## Signed dnf repository

Publish the RPMs as a GPG-signed repo so hosts install with a plain
`dnf install vulnscan-ai` (with `gpgcheck` and `repo_gpgcheck` enforced):

```bash
sudo dnf install rpm-sign createrepo_c gnupg2
packaging/make-repo.sh                 # -> dist/repo/ (key, metadata, .repo)
# for remote hosts, serve dist/repo over HTTPS and:
REPO_BASEURL=https://repo.example.com/vulnscan-ai packaging/make-repo.sh
```

The script generates a signing key (first run), signs every package, builds and
**detached-signs the repo metadata**, exports the public key, and writes the
`.repo` file plus browsable index pages. The layout is one repo per EL version:

```
repo/
  index.html            root landing page (lists distributions)
  techhack.repo         client drop-in (covers all versions via $releasever)
  RPM-GPG-KEY-techhack  shared public signing key
  el9/  index.html + repodata/ + *.rpm    EL9 packages + per-version install
  el10/ ...                               add more dists as needed
```

Each `el<N>/index.html` carries a self-contained, copy-paste install pinned to
that EL version. On a client:

```bash
sudo rpm --import https://repo.example.com/RPM-GPG-KEY-techhack
sudo curl -o /etc/yum.repos.d/techhack.repo \
     https://repo.example.com/techhack.repo
sudo dnf install vulnscan-ai
```

The generated `techhack.repo` (one file works on el9/el10/... via `$releasever`):

```ini
[techhack]
name=techhack tools (EL$releasever)
baseurl=https://repo.example.com/el$releasever
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://repo.example.com/RPM-GPG-KEY-techhack
```

> The demo key is passphrase-less for automation. For a real release line, use a
> passphrase-protected key driven by `gpg-agent` (set `VULNSCANAI_GPG_NAME` /
> `VULNSCANAI_GPG_EMAIL`), and keep the private key off the build host.

### Releasing on a tag

`packaging/release.sh` builds, signs, publishes to the repo, and reloads nginx.
Run it on the repo host (or a self-hosted runner on it):

```bash
# publish the current version for el9
REPO_BASEURL=https://repo.techhack.nl packaging/release.sh

# multiple targets (clean-chroot via mock for non-host dists)
DISTS="el9 el10" REPO_BASEURL=https://repo.techhack.nl packaging/release.sh
```

`.github/workflows/release.yml` runs the same on a `v*` tag from a **self-hosted
runner** that holds the signing key on a **YubiKey/OpenPGP smartcard** (set the
`SIGNING_EMAIL`/`SIGNING_KEYGRIP` repo vars and `CARD_PIN` secret).

**Multi-distro notes.** The host dist (el9) builds natively with `rpmbuild`;
other targets build in a clean **mock** chroot (`alma+epel-<N>-x86_64`), so they
need `mock` installed and the matching config. Caveat: **el8** ships Python 3.6
by default while this tool requires `python3 >= 3.9` — on el8 you must build/run
against the `python39` module and adjust the `Requires`. el9/el10 are
straightforward. Pure-`noarch` Python means the package is portable, but
per-dist builds give correct `.elN` dist tags and separate repo trees.

### Adding another tool to the repo

Build its RPM, then publish alongside vulnscan-ai (the glob is explicit so it
never scoops unrelated packages):

```bash
PKG_GLOB='{vulnscan-ai,othertool}-*' REPO_BASEURL=https://repo.techhack.nl \
    packaging/make-repo.sh /srv/repo
sudo chcon -R -t httpd_sys_content_t /srv/repo
```

## Build the RPM

```bash
sudo dnf install rpm-build rpmdevtools python3-devel \
  pyproject-rpm-macros systemd-rpm-macros \
  python3-setuptools python3-wheel python3-tomli   # build backend on EL9
rpmdev-setuptree
packaging/build-rpm.sh           # runs the test suite via %check
sudo dnf install ~/rpmbuild/RPMS/noarch/vulnscan-ai-*.rpm
```

On a stock RHEL/AlmaLinux 9 the project builds with the system toolchain
(setuptools 53) because metadata lives in `setup.cfg`, not a PEP 621
`[project]` table. The `mock` build (see CI) resolves all build dependencies
automatically in a clean chroot.

### CI

`.github/workflows/ci.yml` runs three jobs on AlmaLinux 9:

- **test** — `python3 -m unittest` (stdlib-only suite) + CLI smoke test.
- **rpmbuild** — builds the RPM (its `%check` runs the tests), installs it so
  real dependency resolution is exercised (incl. `openscap-scanner`), smoke
  tests the installed CLI and units, and uploads the RPM artifact.
- **mock** — clean-chroot build from the SRPM in an `alma+epel-9` mock root,
  proving the package builds with only its declared `BuildRequires`.

Build locally with `packaging/build-rpm.sh` (or `packaging/build-rpm.sh srpm`
for just the SRPM).

The package is `noarch` and declares as hard deps `python3 >= 3.9`, `dnf`,
`rpm`, and `openscap-scanner` (so all three scanners work out of the box). It
*recommends* `python3-reportlab` (PDF has a built-in dependency-free fallback)
and `scap-security-guide` (our `update-oval` fetches the CVE OVAL feed itself);
both are auto-installed on a normal RHEL host via weak dependencies and skipped
only on minimal/`install_weak_deps=False` images, where those features degrade
gracefully. It ships the CLI, systemd timer/service, `/etc/vulnscan-ai/config.json`
(noreplace), the env file (0640), and `/var/lib/vulnscan-ai` state/reports dirs.

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
  scanners/         # dnf+RHSA, OpenSCAP/OVAL, sshd hardening, CVE enrichment
  ai/               # claude (default), openai, gemini, kimi, deepseek, mistral, local
```

## Disclaimer

Automated remediation changes a live system. Review proposals, prefer
`--dry-run` first, and test on non-production hosts. AI suggestions can be
wrong — the approval gate exists for a reason.
