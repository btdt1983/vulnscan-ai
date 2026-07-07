%global pypi_name vulnscan-ai
%global mod_name vulnscanai

# The package is stdlib-only pure Python that runs on any interpreter >= 3.9.
# Drop the exact `python(abi) = <build-python>` auto-requirement so one noarch
# build stays installable across EL releases: pinning it to the build host's
# ABI (3.9 on EL9) makes the package uninstallable on EL10 (Python 3.12). The
# explicit `Requires: python3 >= 3.9` below is the real, honest floor.
%global __requires_exclude ^python\\(abi\\)

Name:           vulnscan-ai
Epoch:          1
Version:        0.4.3
Release:        1%{?dist}
Summary:        RHEL vulnerability scanner with AI-assisted, approval-gated remediation

License:        AGPL-3.0-or-later
URL:            https://vulnscan-ai.techhack.nl
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  pyproject-rpm-macros
BuildRequires:  systemd-rpm-macros

# Runtime: the package manager and rpmdb tooling the scanner drives.
Requires:       python3 >= 3.9
Requires:       dnf
Requires:       rpm
# The oscap binary backs one of the three scanners; require it so every
# scanner works out of the box.
Requires:       openscap-scanner
# Genuinely optional: PDF has a built-in dependency-free fallback, and our
# update-oval command fetches the CVE OVAL feed itself (SSG ships compliance
# content we don't consume). Auto-installed on normal RHEL via weak deps.
Recommends:     python3-reportlab
Recommends:     scap-security-guide
# Pulls in /usr/lib/sysusers.d handling on EL9.
%{?sysusers_requires_compat}

%description
vulnscan-ai scans RHEL-based hosts for known vulnerabilities using dnf/RHSA,
OpenSCAP/OVAL and public CVE feeds (Red Hat Security Data API, NVD), then uses
an LLM (Claude by default; OpenAI/Gemini/Kimi/local optional) to propose
remediation. Fixes are applied only after explicit approval and after passing
a safety deny-list. It is FIPS-aware (relies on the system OpenSSL, pins
TLS 1.2+, uses SHA-2 only) and can export PDF reports without any third-party
dependency. A systemd timer provides daily unattended scan-and-report.

%prep
%autosetup -n %{name}-%{version}

%generate_buildrequires
%pyproject_buildrequires

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files %{mod_name}

# systemd units
install -D -m0644 packaging/systemd/%{name}.service %{buildroot}%{_unitdir}/%{name}.service
install -D -m0644 packaging/systemd/%{name}.timer   %{buildroot}%{_unitdir}/%{name}.timer
install -D -m0644 packaging/systemd/%{name}-dashboard.service %{buildroot}%{_unitdir}/%{name}-dashboard.service

# configuration
install -D -m0644 packaging/config.json       %{buildroot}%{_sysconfdir}/%{name}/config.json
install -D -m0640 packaging/vulnscan-ai.env   %{buildroot}%{_sysconfdir}/%{name}/%{name}.env

# man page (version substituted at build time) and shell completions
install -d %{buildroot}%{_mandir}/man1
sed 's/@VERSION@/%{version}/g' packaging/%{name}.1 > %{buildroot}%{_mandir}/man1/%{name}.1
install -D -m0644 packaging/completions/%{name}.bash %{buildroot}%{_datadir}/bash-completion/completions/%{name}
install -D -m0644 packaging/completions/_%{name}     %{buildroot}%{_datadir}/zsh/site-functions/_%{name}

# state / reports directory
install -d -m0750 %{buildroot}%{_sharedstatedir}/%{name}
install -d -m0750 %{buildroot}%{_sharedstatedir}/%{name}/reports

%check
# Dependency-free unit tests, run against the build tree.
%{python3} -m unittest discover -s tests -v

%files -f %{pyproject_files}
%license LICENSE
%doc README.md COMMANDS.md
%{_bindir}/vulnscan-ai
%{_mandir}/man1/%{name}.1*
%{_datadir}/bash-completion/completions/%{name}
%{_datadir}/zsh/site-functions/_%{name}
%{_unitdir}/%{name}.service
%{_unitdir}/%{name}.timer
%{_unitdir}/%{name}-dashboard.service
%dir %{_sysconfdir}/%{name}
%config(noreplace) %{_sysconfdir}/%{name}/config.json
%config(noreplace) %attr(0640,root,root) %{_sysconfdir}/%{name}/%{name}.env
%dir %attr(0750,root,root) %{_sharedstatedir}/%{name}
%dir %attr(0750,root,root) %{_sharedstatedir}/%{name}/reports

%post
%systemd_post %{name}.timer
%systemd_post %{name}-dashboard.service

%preun
%systemd_preun %{name}.timer
%systemd_preun %{name}-dashboard.service

%postun
%systemd_postun_with_restart %{name}.timer
%systemd_postun_with_restart %{name}-dashboard.service

%changelog
* Tue Jul 07 2026 vulnscan-ai <noreply@example.invalid> - 1:0.4.3-1
- Offline deterministic remediation catalog: `fix` now works fully air-gapped.
  Package/advisory findings (dnf/oscap) are planned locally as a scoped
  `dnf update -y --advisory=<id>` (or `dnf update -y <package>`) with NO AI call
  and no network, so a host with no provider configured is no longer a dead end
  and package fixes are reproducible (same finding -> same plan). The AI is
  reserved for config/service findings that need reasoning.
  * New `vulnscanai/catalog.py`; `remediation.propose_all` is catalog-first by
    default. New `fix --offline` (catalog only, never call a provider) and
    `fix --no-catalog` (AI for everything) flags, and `offline_catalog` config
    key (default true; `--offline` overrides it).
  * Command construction is injection-safe: the advisory is accepted only on a
    full-string match and the package name is allowlist-validated, so a crafted
    finding cannot inject extra dnf arguments.
  * The web dashboard's apply-fix is catalog-first too; `cmd_scheduled --plan`
    produces a deterministic plan offline. Findings with no offline plan are
    surfaced and skipped (never falsely reported as applied).

* Mon Jul 06 2026 vulnscan-ai <noreply@example.invalid> - 1:0.4.2-1
- Structured file writes: config/drop-in fixes apply in-process again. A fix that
  creates or replaces a file (e.g. a systemd hardening drop-in) now carries the
  file path + content, and the transactional engine writes it safely WITHOUT a
  shell — closing the gap the 0.4.1 no-shell hardening opened (previously such a
  fix was blocked and only worked via `--export-script`).
  * New `write_files` remediation field; the model is prompted to use it instead
    of a shell redirect. Sanitised on the way in (absolute path only; placeholder/
    relative/non-dict entries dropped) and stripped from package-CVE findings.
  * The engine screens write targets (refuses non-absolute paths, /etc/shadow,
    /etc/passwd, /dev|/proc|/sys|/boot, directories), snapshots the written files
    alongside backup_paths, writes them before the commands (so a following
    `systemctl daemon-reload` picks up a new drop-in), and on any failure rolls
    back — removing a created file or restoring an overwritten one.
  * `fix --export-script`/`--export-ansible` now render the file writes too
    (bash heredoc / Ansible copy-with-content); fixed the exported backup/restore
    helpers so a newly-created file no longer trips `set -e` and rollback removes
    it, matching the in-process engine.
- +11 tests (227), integration suite still green, bandit clean.

* Mon Jul 06 2026 vulnscan-ai <noreply@example.invalid> - 1:0.4.1-1
- Stability release — hardening of what the tool already does, no new surface.
- Remediation engine (the code that changes the system):
  * Rollback can no longer report success when it failed. `rollback` (and the
    automatic rollback) now return the true outcome; a missing/partial restore
    is surfaced as ROLLBACK INCOMPLETE instead of a false "reverted", and the
    audit log records it truthfully.
  * File-writing fixes no longer silently no-op into a false success. Commands
    that need a shell (redirect/pipe/&&/$()/backtick) — which the no-shell
    runner cannot execute as written — are now blocked with a message pointing
    at `--export-script`, instead of running e.g. `echo … > file` as a no-op and
    reporting "applied".
- Parser robustness: the scanner/feed parsers survive malformed external data
  (a null item or wrong-typed field in CISA KEV / Rocky Apollo JSON or a
  container inspect object) by skipping the bad item instead of crashing
  `news`/container scans.
- Never-crash CLI: a last-resort guard means an unexpected error prints a
  readable message and exits non-zero instead of dumping a traceback
  (VULNSCANAI_DEBUG=1 re-raises); a corrupt config or findings.json degrades
  with a warning instead of bricking the command.
- Tests: +22 (fuzz battery for every parser, engine rollback/shell cases,
  never-crash paths) plus an opt-in integration suite that runs the real
  ss/systemd-analyze/oscap and the scanners against a live host
  (VULNSCANAI_INTEGRATION=1).

* Mon Jul 06 2026 vulnscan-ai <noreply@example.invalid> - 1:0.4.0-1
- New `audit` command: an append-only remediation audit log. Every fix actually
  applied (and every rollback), from the CLI or the web dashboard, is recorded
  as one JSON line in <state-dir>/audit.log (0600) — timestamp, source, actor,
  finding, result, and the AI provider/model that generated the plan. Dry-run
  previews are not logged. `vulnscan-ai audit [--limit N] [--json]`; interactive
  menu gains an Audit entry. Dashboard-applied fixes record the login user.
- EL10 packages are now genuinely installable AND importable. Previously the
  el10 tree served the el9 noarch build, whose files live under the build
  interpreter's site-packages path (…/python3.9/…) and pin `python(abi) = 3.9`,
  so it failed to install (or import) on EL10's Python 3.12. Each EL is now
  built natively (release.sh builds el10 in an almalinux:10 container); the spec
  also drops the exact `python(abi)` auto-requirement, keeping `python3 >= 3.9`
  as the honest floor.
- CI/release hardening: the tag workflow no longer hangs on a missing
  self-hosted runner — it verifies build+install on el9 AND el10 on
  GitHub-hosted runners, and the sign+publish job is opt-in (manual dispatch).
  Unit tests also run on el10 (Python 3.12) on every push.
- Packaging for Fedora Copr (.copr/Makefile + packaging/COPR.md) for free
  el9/el10/fedora builds and a public repo URL.

* Mon Jul 06 2026 vulnscan-ai <noreply@example.invalid> - 1:0.3.1-1
- Dashboard apply-fix toggle is now a first-class control:
  * new `vulnscan-ai dashboard --enable-fix` / `--disable-fix` write
    `dashboard_allow_fix` (no more hand-editing the config file); `--list`
    reports the current state.
  * the interactive menu's "Web dashboard" screen gains an Enable/Disable
    applying-fixes entry that shows the current state and prints a clear
    warning (enabling grants dashboard users root-equivalent remediation
    power) before it opts you in.

* Sat Jul 04 2026 vulnscan-ai <noreply@example.invalid> - 1:0.3.0-1
- Compliance benchmark scanning (CIS / DISA STIG / PCI-DSS / HIPAA / ANSSI):
  * new `scan --compliance <profile>` mode runs `oscap xccdf eval` against the
    SCAP Security Guide and reports a compliance score plus every failing rule
    (sorted by severity, with CCE/CIS/STIG identifiers and whether an automated
    remediation ships). A distinct mode — not part of `--all` (XCCDF is a
    minutes-long full-system audit).
  * `scan --list-profiles` lists the profiles the host's datastream offers;
    friendly aliases (cis-l1, cis-l2, stig, pci-dss, hipaa, ospp, anssi-high, …)
    or a full XCCDF profile id both resolve.
  * results saved to <state-dir>/compliance.json; `--pdf`/`--json`/`--sarif`
    export them; exits 3 when any rule fails (for CI/timers).
  * dashboard gains a read-only Compliance tab (score tile + failing rules);
    interactive menu gains a Compliance entry; `info` shows availability.
  * requires oscap + the scap-security-guide package.
* Fri Jul 03 2026 vulnscan-ai <noreply@example.invalid> - 1:0.2.5-1
- AI provider/model UX + error visibility:
  * setup now picks the cloud model from a MENU of known ids per provider (with a
    custom-id escape hatch), so a typo'd id like 'Sonnet 5' can't be saved and
    silently break every remediation.
  * setup reuses an already-saved API key ("reuse it? [Y/n]"), so you can switch
    provider or just change the model without pasting the key again.
  * picking the local (Ollama) backend now takes effect immediately — the choice
    is persisted up front, so a deferred/offline download no longer leaves the
    tool silently using the previous cloud provider.
- HTTP errors now surface the server's own message (e.g. "credit balance is too
  low") instead of a bare "HTTP 400: Bad Request", for every provider.
- fix: when an AI proposal fails it prints the real reason, and if EVERY proposal
  fails (systemic — credits/key/model) it stops with that reason instead of
  walking the operator through empty approval prompts.
- The interactive menu draws the banner as its header, so it stays visible in the
  full-screen (curses) view.

* Thu Jul 02 2026 vulnscan-ai <noreply@example.invalid> - 1:0.2.4-1
- STABLE. Graduates the 0.2.4b0 interactive menu to final and adds a small
  dashboard touch: the summary row now carries an actively-exploited (CISA KEV)
  tile and an EPSS >=50% tile whenever a finding matches, surfacing the
  highest-priority exploitation signals up front instead of only in the list.
- Introduces Epoch 1 so this release cleanly supersedes the 0.2.4b0 pre-release
  (RPM ranks '0.2.4b0' above '0.2.4', so without an epoch 'dnf update' would not
  move beta hosts to the final). Epoch stays 1 for subsequent releases.

* Thu Jul 02 2026 vulnscan-ai <noreply@example.invalid> - 0.2.4b0-1
- BETA. Interactive, menu-driven front-end: run 'vulnscan-ai' with no command on
  a terminal (or 'vulnscan-ai menu') for a navigable menu that covers every
  command — scan, fix, rollback, report, news, info, providers, dashboard,
  scheduled, update-oval and setup — so flags need not be memorised. Arrow-key
  curses UI with a numbered-prompt fallback for terminals without cursor support
  (or VULNSCANAI_NO_CURSES=1); non-interactive/piped runs still print help. Each
  choice is turned into the ordinary command and run through the real parser, so
  behaviour is identical to typing it by hand.

* Tue Jun 30 2026 vulnscan-ai <noreply@example.invalid> - 0.2.3-1
- BUGFIX (0.2.2 already-patched filter): the filter matched on package name
  only, so it never caught 'oscap' findings (which carry an advisory but no
  package) — the lingering-old-kernel ALSA advisories still showed up. The
  filter now also consults 'dnf updateinfo list --updates' (the realistic
  installable-advisory set) and drops a finding when its advisory isn't actionable;
  both signals are considered and it stays fail-safe. 'fix' now applies the filter
  to the saved findings too, so already-patched advisories no longer waste an AI
  proposal or a no-op apply even without re-scanning.

* Tue Jun 30 2026 vulnscan-ai <noreply@example.invalid> - 0.2.2-1
- STABLE. Already-patched filter: a package finding whose fix is in the repo
  metadata but has no installable update per 'dnf check-update' is dropped — the
  host already has it. Clears the common lingering-old-kernel noise (old kernels
  stay installed, so the scanners keep listing historical kernel advisories that
  dnf reports as "Nothing to do"). Won't-fix advisories are never dropped this
  way; fail-safe (drops nothing if dnf can't be queried). Toggle: patched_filter.
- fix: the interactive prompt gains '[i]gnore' — accept a reviewed finding and
  add it to the persistent baseline (~/.config/vulnscan-ai/ignore) on the spot,
  so it isn't reported again (handy for accepted hardening items on a LAN host).
- fix: harden the '--advisory=' rewrite — collapse space/comma-separated id lists
  into one argument and drop garbage tokens, so a model emitting
  '--advisory=RHSA-1, RHSA-2' no longer makes dnf fail with "No match for
  argument"; the finding's own advisory is preferred when well-formed.

* Tue Jun 30 2026 vulnscan-ai <noreply@example.invalid> - 0.2.1-1
- Distro errata feed now covers all three RHEL clones, picked automatically:
  AlmaLinux (errata RSS), Rocky Linux (RESF/Apollo advisories JSON) and Oracle
  Linux (year-scoped ELSA OVAL, with bounded decompression as a bomb guard).
- OVAL auto-refresh: a scan that uses the oscap scanner now downloads the OVAL
  feed automatically when it is missing or older than oval_max_age_days (default
  7) — no manual 'update-oval' needed. TTL-gated, fail-soft (falls back to the
  existing feed), and skipped when offline (--no-enrich) or oval_auto_update is
  false. New config keys oval_auto_update, oval_max_age_days.

* Tue Jun 30 2026 vulnscan-ai <noreply@example.invalid> - 0.2.0-1
- STABLE release. Exploitation-aware prioritisation: every finding's CVE is
  checked against the CISA KEV catalog (actively exploited in the wild) and the
  FIRST.org EPSS score during enrichment. KEV findings are tagged [KEV], sorted
  to the top and raised to at least 'important'; high EPSS shows as [EPSS xx%].
  Toggle with 'exploit_enrich'.
- New 'news' command + dashboard "Advisories" tab: recent vulnerability news from
  CISA KEV, NIST NVD and the host distribution's errata (AlmaLinux today), cached
  to the state dir so it works offline. Advisories matching the last scan are
  flagged. New 'feeds' module (stdlib only, FIPS TLS); config keys news_enabled,
  news_sources, news_refresh_hours.
- Security hardening: HTTP restricted to http/https schemes (no file:// SSRF) with
  a response-size cap; untrusted feed XML rejects DOCTYPE/ENTITY (no XXE); all
  feed content HTML-escaped in the dashboard. New bandit SAST job in CI (fails on
  medium+). Man page gains the dashboard and news sections.

* Tue Jun 30 2026 vulnscan-ai <noreply@example.invalid> - 0.1.26-1
- BUGFIX (regression in 0.1.25): 'fix' crashed with "TypeError: 'NoneType'
  object is not iterable" when the AI returned a null list field (e.g.
  "config_changes": null). dict.get(k, []) returns None — not [] — when the key
  is present but null; every list field (commands/config_changes/backup_paths/
  rollback_commands) is now coerced safely, and a single scalar is tolerated.

* Tue Jun 30 2026 vulnscan-ai <noreply@example.invalid> - 0.1.25-1
- fix: stream every apply step live (backup, each command, validate, service
  reload/health check, rollback) together with the command's own output, so you
  can see what a fix does while it runs instead of waiting for a silent finish.
- fix: sanitise AI remediation plans before they can run — normalise an invalid
  restart_mode (a model echoing "reload|restart|none" no longer silently skips
  the reload), drop echoed schema placeholders and non-command "verify" strings,
  rewrite a malformed --advisory= id to the finding's real advisory, and strip
  config backups/validate/service from package-CVE (dnf/oscap) fixes where the
  model tends to hallucinate unrelated sshd/httpd scaffolding.
- fix: a 'dnf update' that reports "Nothing to do" is now shown as [no-change]
  (not a false [ok]), so an advisory that didn't actually apply is visible.

* Tue Jun 30 2026 vulnscan-ai <noreply@example.invalid> - 0.1.24-1
- New 'container' scanner (7th): inspects running Podman/Docker containers and
  flags unsafe runtime settings CIS-Docker style — --privileged, runtime control
  socket or sensitive host paths bind-mounted, host network/PID/IPC namespaces,
  dangerous added capabilities (SYS_ADMIN, SYS_MODULE, --cap-add ALL), disabled
  seccomp/AppArmor/SELinux, and root as the container user. Read-only and
  conservative (benign mounts ignored, read-only mounts downgraded, --privileged
  reported once). Selectable via --scanner container / --all.

* Fri Jun 26 2026 vulnscan-ai <noreply@example.invalid> - 0.1.23-1
- Dashboard: show a loading-spinner overlay while a Preview/Apply fix runs, so
  the page doesn't look frozen during the (synchronous) AI call on slow local
  models.

* Fri Jun 26 2026 vulnscan-ai <noreply@example.invalid> - 0.1.22-1
- Fix: the 'local' (Ollama) provider crashed with TypeError on the 'effort'
  argument introduced in 0.1.19, breaking 'fix' and the dashboard Preview/Apply
  with a local model. All providers now accept the effort kwarg.
- Dashboard: an unexpected handler error now returns a 500 page (with the
  traceback logged) instead of an empty response (ERR_EMPTY_RESPONSE).

* Fri Jun 26 2026 vulnscan-ai <noreply@example.invalid> - 0.1.21-1
- Dashboard gains interactive actions: a 'Scan now' button runs the scanners
  in the background, per-finding 'Preview fix' shows the AI plan (dry-run), and
  'Apply fix' runs the fix transactionally on the host. Apply is opt-in only
  (config dashboard_allow_fix, default false) so the dashboard stays read-only
  by default; login and the allow-list still gate access.

* Wed Jun 24 2026 vulnscan-ai <noreply@example.invalid> - 0.1.20-1
- Setup wizard can configure a cloud AI provider + API key: pick claude/
  openai/gemini/kimi/deepseek/mistral, enter the key (hidden), optional model
  and (Claude) effort. Stored in the 0600 user config (new 'api_keys') and
  injected into the environment on load; a real env var always wins.

* Wed Jun 24 2026 vulnscan-ai <noreply@example.invalid> - 0.1.19-1
- Claude reasoning-effort selection: global --effort low|medium|high|xhigh|max
  (config claude_effort, env VULNSCANAI_CLAUDE_EFFORT) turns on adaptive
  thinking for the Claude provider; other providers ignore it.

* Wed Jun 24 2026 vulnscan-ai <noreply@example.invalid> - 0.1.18-1
- scan: a per-severity tally line below the table and a colour-coded SEV
  column (TTY-aware; NO_COLOR honoured, never coloured when piped).
- Refresh bash/zsh completions for the current commands, scanners, providers
  and options (dashboard, webroot, --all, --no-banner, …).

* Tue Jun 23 2026 vulnscan-ai <noreply@example.invalid> - 0.1.17-1
- New 'webroot' scanner: finds web-exposed sensitive files in document roots
  (*.sql/*.sqlite dumps, .env/wp-config.php secrets, .git/, *.bak/*~ backups,
  archives, private keys) plus world-writable files. Roots read from nginx/
  apache/lighttpd/litespeed configs and defaults. Picked up by 'scan --all'.
- Dashboard login page and header now carry the vulnscan-ai brand logo.

* Tue Jun 23 2026 vulnscan-ai <noreply@example.invalid> - 0.1.16-1
- Dashboard prints the login username on start, and a copy-paste firewalld
  rule when the port looks closed in a running firewalld (network binds only).

* Tue Jun 23 2026 vulnscan-ai <noreply@example.invalid> - 0.1.15-1
- Dashboard default port is now 65101 (was 6666, which browsers block with
  ERR_UNSAFE_PORT). The dashboard warns when started on a browser-blocked port.

* Tue Jun 23 2026 vulnscan-ai <noreply@example.invalid> - 0.1.14-1
- New 'dashboard' command: a stdlib HTTPS web UI behind a login that shows
  saved findings with their explanations, CVEs and any AI fix plan.
  Self-signed cert on first run; PBKDF2-SHA256 admin password; localhost-only
  by default with an IP/CIDR allow-list for specific network clients. Ships a
  vulnscan-ai-dashboard.service unit.
- scan/fix/scheduled gain '--all' to run every available scanner.

* Tue Jun 23 2026 vulnscan-ai <noreply@example.invalid> - 0.1.13-1
- Branded startup banner (MOTD) on interactive runs; suppressed for pipes,
  machine output, scheduled runs and via --no-banner / VULNSCANAI_NO_BANNER.
- Scan drift: scan and scheduled report what is new vs resolved since the
  previous saved scan.
- Email notifications: a scheduled scan can email a summary when findings
  reach a severity or new ones appear (SMTP config + setup-wizard section;
  password via VULNSCANAI_SMTP_PASSWORD). A failed mail never breaks a scan.

* Tue Jun 23 2026 vulnscan-ai <noreply@example.invalid> - 0.1.12-1
- Relicensed from Apache-2.0 to AGPL-3.0-or-later. The package now ships the
  AGPL-3.0 LICENSE and all sources carry SPDX headers. Contributions are
  accepted under a CLA so the project can also be offered commercially.
- No functional change to scanning or remediation.

* Mon Jun 22 2026 vulnscan-ai <noreply@example.invalid> - 0.1.11-1
- Runtime-exposure filter: a vulnerable daemon package whose systemd
  service/socket units are all stopped AND disabled/masked is downgraded
  to "low" and annotated (not exposed until the service is started),
  cutting noise without hiding the issue. Conservative — packages with no
  service unit (libraries, CLI tools) are untouched, enabled/static/
  socket-listening units count as exposed, undetermined state keeps full
  severity. Toggle "service_state_filter" (default on).
- Released signed with the production GPG key (techhack release signing).

* Fri Jun 19 2026 vulnscan-ai <noreply@example.invalid> - 0.1.10-1
- Fewer false positives via Red Hat per-CVE package_state: findings the
  vendor marks "Not affected" for this RHEL release are dropped; the
  won't-fix family ("Will not fix"/"Out of support scope"/"Fix deferred")
  is kept but annotated so no pointless dnf update is proposed (toggle
  with config 'vendor_state_filter').
- ports scanner gains nftables firewall-awareness: when firewalld isn't
  running it parses 'nft --json list ruleset' (default-deny input policy,
  accept rules incl. named sets/ranges, explicit drop/reject) and only
  suppresses ports it can confidently prove blocked.

* Tue Jun 16 2026 vulnscan-ai <noreply@example.invalid> - 0.1.9-1
- Minimize false positives: OVAL scanner reports only patch-class
  definitions (drops inventory/compliance) with real CVE ids + severity;
  ports scanner suppresses firewalld-blocked ports; dnf+oscap findings
  sharing an advisory/CVE are merged; new baseline/allowlist (config
  'ignore', ~/.config/vulnscan-ai/ignore, VULNSCANAI_IGNORE, --ignore).

* Tue Jun 16 2026 vulnscan-ai <noreply@example.invalid> - 0.1.8-1
- Add systemd service-hardening scanner (--scanner systemd) via
  systemd-analyze security; conservative defaults, drop-in remediation.
- Add network exposure scanner (--scanner ports) via ss; flags risky
  plaintext/legacy and sensitive services listening off-host.
- Transactional rollback now runs systemctl daemon-reload before restart.
- Readable scan output for config findings (show title when no package).

* Tue Jun 16 2026 vulnscan-ai <noreply@example.invalid> - 0.1.7-1
- Transactional remediation: config/service fixes now back up the file(s),
  validate before restart (e.g. sshd -t), reload + health-check the service,
  and auto-roll back on failure. New 'rollback' command restores a fix.
- Add SSH hardening scanner (--scanner ssh): root login, weak ciphers/MACs/
  KEX, password auth, X11 forwarding, legacy protocol.
- fix --export-script / --export-ansible: emit a bash script or Ansible
  playbook instead of applying.

* Tue Jun 16 2026 vulnscan-ai <noreply@example.invalid> - 0.1.6-1
- Add DeepSeek (DeepSeek-Coder) and Mistral (Mixtral 8x7B) AI providers,
  both OpenAI-compatible. StarCoder 2 is supported via the local/Ollama
  provider (--provider local --model starcoder2).
- repo: per-version index pages (el9/el10) listing downloadable packages.

* Sun Jun 14 2026 vulnscan-ai <noreply@example.invalid> - 0.1.5-1
- Add a man page (man vulnscan-ai) and bash + zsh shell completion.
- Ship COMMANDS.md reference; point systemd Documentation= at the man page.

* Sun Jun 14 2026 vulnscan-ai <noreply@example.invalid> - 0.1.4-1
- GPU support: detect NVIDIA/AMD GPUs and size the model menu against VRAM
  (offering larger models on GPU hosts); 'info' reports GPU/CPU. Ollama runs
  the chosen model GPU-accelerated automatically when a GPU is present.

* Sun Jun 14 2026 vulnscan-ai <noreply@example.invalid> - 0.1.3-1
- Add interactive first-run setup wizard ('vulnscan-ai setup', also offered
  automatically on first interactive run) to choose and download an offline
  AI model via Ollama; saves the choice as the default provider/model.
- config: merge system + per-user config so a user choice overrides /etc.

* Sat Jun 13 2026 vulnscan-ai <noreply@example.invalid> - 0.1.2-1
- http: catch read timeouts / socket errors and surface them cleanly instead
  of crashing (slow local CPU inference no longer aborts a run).
- local: patient default timeout (300s, OLLAMA_TIMEOUT to override) for local
  model load + CPU inference.

* Sat Jun 13 2026 vulnscan-ai <noreply@example.invalid> - 0.1.1-1
- local (Ollama) provider: JSON-constrained output for reliable structured
  remediation from small models; live server readiness check; OLLAMA_MODEL
  support and clearer "server down" / "model not pulled" errors.

* Sat Jun 13 2026 vulnscan-ai <noreply@example.invalid> - 0.1.0-1
- Initial package: scanner, AI remediation, PDF reporting, systemd timer.
