#!/usr/bin/env bash
# Build/refresh a GPG-signed, multi-tool dnf repository.
#
# Layout (what real repos like EPEL use): one repo per EL version holding many
# packages, addressed with $releasever so a single .repo works everywhere:
#
#   <REPO_ROOT>/
#     RPM-GPG-KEY-techhack          one shared public signing key
#     techhack.repo                 client drop-in (.repo)
#     index.html                    root landing page (lists distributions)
#     el9/  index.html + repodata/ + *.rpm   all EL9 tools + per-version install
#     el10/ ...                      add more dists as needed
#
# Drop any tool's RPMs into rpmbuild/RPMS (or point RPMS_SRC at them) and re-run;
# every package lands in the matching el<N>/ repo and shows up for dnf.
#
# Requires: rpm-sign, createrepo_c, gnupg2
#
# Usage:   packaging/make-repo.sh [REPO_ROOT]
# Env:     VULNSCANAI_GPG_NAME, VULNSCANAI_GPG_EMAIL, RPMS_SRC,
#          REPO_BASEURL (e.g. https://repo.techhack.nl), DIST (e.g. el9)
set -euo pipefail

KEY_NAME="${VULNSCANAI_GPG_NAME:-techhack repo signing}"
KEY_EMAIL="${VULNSCANAI_GPG_EMAIL:-security@example.invalid}"
REPO_ROOT="${1:-${VULNSCANAI_REPO_DIR:-$PWD/dist/repo}}"
RPMS_SRC="${RPMS_SRC:-$(rpm --eval '%{_topdir}')/RPMS}"
REPO_BASEURL="${REPO_BASEURL:-file://$REPO_ROOT}"
KEYFILE="RPM-GPG-KEY-techhack"
# Only these packages are published. Scoped on purpose so the script never
# scoops up unrelated RPMs from the build tree. Add more tools deliberately,
# e.g. PKG_GLOB='{vulnscan-ai,othertool}-*'.
PKG_GLOB="${PKG_GLOB:-vulnscan-ai-*}"
# Extra dist trees to also receive *noarch* packages, since a noarch build runs
# unchanged on other EL versions (e.g. EXTRA_DISTS="el10" mirrors el9 noarch
# RPMs into el10/). Arch-specific packages are never fanned out this way.
EXTRA_DISTS="${EXTRA_DISTS:-}"

for t in rpm rpmsign gpg createrepo_c; do
    command -v "$t" >/dev/null || { echo "ERROR: missing '$t'"; exit 1; }
done

# 1. Signing key (passphrase-less here; use an HSM/smartcard for releases).
if ! gpg --list-secret-keys "$KEY_EMAIL" >/dev/null 2>&1; then
    echo ">> generating GPG signing key for $KEY_EMAIL"
    batch="$(mktemp)"
    cat > "$batch" <<EOF
%no-protection
Key-Type: RSA
Key-Length: 4096
Name-Real: $KEY_NAME
Name-Email: $KEY_EMAIL
Expire-Date: 0
%commit
EOF
    gpg --batch --gen-key "$batch"; rm -f "$batch"
fi
KEYID="$(gpg --list-keys --with-colons "$KEY_EMAIL" | awk -F: '/^pub:/{print $5; exit}')"
echo ">> signing key id: $KEYID"

# 2. Collect RPMs and sign them.
mapfile -t RPMS < <(find "$RPMS_SRC" -name "${PKG_GLOB}.rpm" ! -name '*.src.rpm' | sort)
[ "${#RPMS[@]}" -gt 0 ] || { echo "ERROR: no RPMs matching '${PKG_GLOB}.rpm' under $RPMS_SRC"; exit 1; }
echo ">> signing ${#RPMS[@]} package(s)"
rpmsign --define "_gpg_name $KEY_EMAIL" \
        --define "__gpg_sign_cmd %{__gpg} gpg --no-verbose --no-armor --pinentry-mode loopback --batch -u %{_gpg_name} -sbo %{__signature_filename} --digest-algo sha256 %{__plaintext_filename}" \
        --addsign "${RPMS[@]}"

# 3. Place each RPM into the el<N>/ dir implied by its dist tag.
mkdir -p "$REPO_ROOT"
gpg --armor --export "$KEYID" > "$REPO_ROOT/$KEYFILE"
declare -A DISTS=()
for rpm in "${RPMS[@]}"; do
    base="$(basename "$rpm")"
    dist="${DIST:-}"
    [ -n "$dist" ] || dist="$(printf '%s' "$base" | grep -oE 'el[0-9]+' | head -1)"
    [ -n "$dist" ] || dist="el9"
    mkdir -p "$REPO_ROOT/$dist"
    cp -f "$rpm" "$REPO_ROOT/$dist/"
    DISTS["$dist"]=1
    # A noarch package runs unchanged on other EL versions; mirror it there.
    case "$base" in
        *.noarch.rpm)
            for ed in $EXTRA_DISTS; do
                [ "$ed" = "$dist" ] && continue
                mkdir -p "$REPO_ROOT/$ed"
                cp -f "$rpm" "$REPO_ROOT/$ed/"
                DISTS["$ed"]=1
            done
            ;;
    esac
done

# 4. Build + sign metadata for each dist.
for dist in "${!DISTS[@]}"; do
    echo ">> createrepo $dist"
    createrepo_c --update "$REPO_ROOT/$dist" >/dev/null
    rm -f "$REPO_ROOT/$dist/repodata/repomd.xml.asc"
    gpg --batch --yes --pinentry-mode loopback -u "$KEYID" \
        --detach-sign --armor "$REPO_ROOT/$dist/repodata/repomd.xml"
done

# 5. Client .repo (uses $releasever so one file covers el9/el10/...).
cat > "$REPO_ROOT/techhack.repo" <<EOF
[techhack]
name=techhack tools (EL\$releasever)
baseurl=$REPO_BASEURL/el\$releasever
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=$REPO_BASEURL/$KEYFILE
EOF

# 6. Browsable landing pages.
HTML_STYLE="<style>body{font-family:system-ui,sans-serif;max-width:48rem;margin:3rem auto;padding:0 1rem;line-height:1.5}code,pre{background:#f4f4f4;padding:.1rem .3rem;border-radius:4px}pre{padding:1rem;overflow:auto}a{color:#0a58ca}</style>"

# Root: just a clean directory of distributions. The install command lives on
# each el<N>/ page so it is unambiguous about which EL version it targets.
{
    echo "<!doctype html><meta charset=utf-8><title>techhack RPM repo</title>"
    echo "$HTML_STYLE"
    echo "<h1>techhack RPM repository</h1>"
    echo "<p>Signed dnf repository for RHEL-based hosts. Pick your distribution for install instructions:</p>"
    echo "<ul>"
    for dist in $(printf '%s\n' "${!DISTS[@]}" | sort); do
        echo "<li><a href=\"$dist/\">$dist/</a></li>"
    done
    echo "</ul>"
    echo "<p><a href=\"$KEYFILE\">GPG public key</a> &middot; <a href=\"techhack.repo\">techhack.repo</a> (covers all versions via \$releasever)</p>"
    echo "<p style=color:#666>Packages are GPG-signed; metadata is signed (repo_gpgcheck).</p>"
} > "$REPO_ROOT/index.html"

# Per-version: a self-contained, copy-paste install for exactly this EL version.
for dist in "${!DISTS[@]}"; do
    {
        echo "<!doctype html><meta charset=utf-8><title>techhack RPM repo ($dist)</title>"
        echo "$HTML_STYLE"
        echo "<p><a href=\"../\">&larr; all distributions</a></p>"
        echo "<h1>techhack tools (${dist^^})</h1>"
        echo "<p>Install on ${dist^^}:</p>"
        echo "<pre>sudo rpm --import $REPO_BASEURL/$KEYFILE"
        echo "sudo tee /etc/yum.repos.d/techhack.repo &lt;&lt;'EOF'"
        echo "[techhack]"
        echo "name=techhack tools (${dist^^})"
        echo "baseurl=$REPO_BASEURL/$dist"
        echo "enabled=1"
        echo "gpgcheck=1"
        echo "repo_gpgcheck=1"
        echo "gpgkey=$REPO_BASEURL/$KEYFILE"
        echo "EOF"
        echo
        echo "sudo dnf install vulnscan-ai</pre>"
        echo "<h2>Packages</h2><ul>"
        for pkg in "$REPO_ROOT/$dist/"*.rpm; do
            [ -e "$pkg" ] || continue
            pn="$(basename "$pkg")"
            sz="$(du -h "$pkg" | cut -f1)"
            echo "<li><a href=\"$pn\">$pn</a> <span style=color:#666>($sz)</span></li>"
        done
        echo "</ul>"
        # Changelog straight from the package(s) so it always matches what is
        # published. HTML-escape it (it contains <email> and other markup).
        echo "<details><summary>Changelog</summary><pre>"
        for pkg in "$REPO_ROOT/$dist/"*.rpm; do
            [ -e "$pkg" ] || continue
            rpm -qp --changelog "$pkg" 2>/dev/null \
                | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
        done
        echo "</pre></details>"
        echo "<p style=color:#666>Packages are GPG-signed; metadata is signed (repo_gpgcheck).</p>"
    } > "$REPO_ROOT/$dist/index.html"
done

echo
echo ">> repo ready at $REPO_ROOT  (dists: ${!DISTS[*]})"
echo "   baseurl : $REPO_BASEURL/el\$releasever"
echo "   key     : $REPO_ROOT/$KEYFILE"
echo "   repofile: $REPO_ROOT/techhack.repo"
