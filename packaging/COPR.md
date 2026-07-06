# Publishing vulnscan-ai on Fedora Copr

[Copr](https://copr.fedorainfracloud.org/) gives us free, reproducible builds
across **EL9, EL10 and Fedora** from a single source, a public repo URL anyone
can `dnf copr enable`, and — because every target chroot is built from scratch —
real multi-distro build CI. It complements (does not replace) the signed
`repo.techhack.nl` repo: Copr is reach + coverage, techhack is the canonical
signed channel.

Builds run from [`.copr/Makefile`](../.copr/Makefile): Copr checks out the repo
at a tag, runs the `srpm` target to produce a SRPM, then rebuilds it in each
chroot. No SRPM upload, no secrets in CI.

## One-time setup (maintainer action — needs a Copr login)

Copr project creation needs your Copr API token, so these steps are run by the
maintainer, not automated here.

1. **Get an API token:** log in at <https://copr.fedorainfracloud.org/>, open
   *API* (top-right menu), and copy the config block into `~/.config/copr`.

2. **Install the client:**
   ```bash
   sudo dnf install copr-cli
   ```

3. **Create the project** with the target chroots (add/trim as you like):
   ```bash
   copr-cli create vulnscan-ai \
     --chroot epel-9-x86_64 \
     --chroot epel-10-x86_64 \
     --chroot fedora-rawhide-x86_64 \
     --description "FIPS-aware RHEL vulnerability scanner with AI-assisted, approval-gated, transactional remediation." \
     --instructions "dnf copr enable <your-copr-user>/vulnscan-ai && dnf install vulnscan-ai"
   ```

4. **Add the package as an SCM source** (auto-rebuilds from this repo):
   ```bash
   copr-cli add-package-scm vulnscan-ai \
     --name vulnscan-ai \
     --clone-url https://github.com/btdt1983/vulnscan-ai.git \
     --commit master \
     --spec packaging/vulnscan-ai.spec \
     --type git \
     --method makefile \
     --webhook-rebuild on
   ```

5. **Kick off the first build** (a specific tag is reproducible):
   ```bash
   copr-cli build-package vulnscan-ai --name vulnscan-ai --commit v0.4.0
   # or build straight from a clone URL at a tag:
   # copr-cli build vulnscan-ai https://github.com/btdt1983/vulnscan-ai.git#v0.4.0
   ```

## Per-release

With `--webhook-rebuild on` and the GitHub webhook enabled (Copr project →
*Settings → Integrations* shows the webhook URL to add to the repo), pushing a
new `v*` tag triggers a Copr rebuild automatically. Otherwise trigger it
manually after the tag is pushed:

```bash
copr-cli build-package vulnscan-ai --name vulnscan-ai --commit vX.Y.Z
```

## Notes

- **EL10 works because the package is portable noarch.** The spec drops the
  exact `python(abi)` auto-requirement (it would pin the build interpreter and
  make the noarch RPM uninstallable on EL10's Python 3.12); the honest floor is
  `Requires: python3 >= 3.9`. Copr building natively per chroot also sidesteps
  this, but the portability fix keeps a single artifact valid everywhere.
- `openscap-scanner` and `scap-security-guide` (a Recommends) must exist in the
  target chroots; they do in EPEL/AppStream for EL9/EL10 and in Fedora.
- Copr does **not** sign packages with our key — it signs with Copr's own per
  project key. Users who want the techhack-signed builds use `repo.techhack.nl`.
