%global pypi_name vulnscan-ai
%global mod_name vulnscanai

Name:           vulnscan-ai
Version:        0.1.11
Release:        1%{?dist}
Summary:        RHEL vulnerability scanner with AI-assisted, approval-gated remediation

License:        Apache-2.0
URL:            https://example.invalid/vulnscan-ai
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
%doc README.md COMMANDS.md
%{_bindir}/vulnscan-ai
%{_mandir}/man1/%{name}.1*
%{_datadir}/bash-completion/completions/%{name}
%{_datadir}/zsh/site-functions/_%{name}
%{_unitdir}/%{name}.service
%{_unitdir}/%{name}.timer
%dir %{_sysconfdir}/%{name}
%config(noreplace) %{_sysconfdir}/%{name}/config.json
%config(noreplace) %attr(0640,root,root) %{_sysconfdir}/%{name}/%{name}.env
%dir %attr(0750,root,root) %{_sharedstatedir}/%{name}
%dir %attr(0750,root,root) %{_sharedstatedir}/%{name}/reports

%post
%systemd_post %{name}.timer

%preun
%systemd_preun %{name}.timer

%postun
%systemd_postun_with_restart %{name}.timer

%changelog
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
