#!/usr/bin/env bash
# On-tag release: build vulnscan-ai for each target dist, then sign + publish to
# the local signed repo and reload nginx. Run on the repo host (or a self-hosted
# CI runner on it).
#
#   packaging/release.sh
#
# Env:
#   DISTS         space-separated targets (default "el9"; e.g. "el9 el10")
#   REPO_ROOT     repo web root (default /srv/repo)
#   REPO_BASEURL  public base (default https://repo.techhack.nl)
#   RELEASE_TAG   if set (e.g. v0.1.5), must match setup.cfg version
#   USE_MOCK=1    force clean-chroot mock build even for the host dist
#   SUDO          command prefix for privileged steps (default empty / root)
#   VULNSCANAI_GPG_EMAIL  signing identity (default security@techhack.nl)
#   VULNSCANAI_GPG_PASSPHRASE_FILE  0600 file with the key passphrase (required
#                 for the production key; passed through to make-repo.sh)
set -euo pipefail
cd "$(dirname "$0")/.."

DISTS="${DISTS:-el9 el10}"
# Extra EL trees to receive the host-built *noarch* RPM with NO rebuild. Empty
# by default: a pyproject/noarch package bakes the build interpreter's versioned
# site-packages path (…/python3.9/…) into its file list, so an el9 build is not
# importable on el10 (Python 3.12) even though it "installs". Each EL is a real
# build target below instead. Only set this for a truly interpreter-independent
# noarch package.
EXTRA_DISTS="${EXTRA_DISTS:-}"
REPO_ROOT="${REPO_ROOT:-/srv/repo}"
REPO_BASEURL="${REPO_BASEURL:-https://repo.techhack.nl}"
HOST_DIST="${HOST_DIST:-el9}"
SUDO="${SUDO:-}"

# Never fan-out into a dist we're already building from source.
_extra=""
for ed in $EXTRA_DISTS; do
    case " $DISTS " in *" $ed "*) ;; *) _extra="$_extra $ed";; esac
done
EXTRA_DISTS="$(echo $_extra | xargs)"

VERSION="$(awk -F'= *' '/^version *=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' setup.cfg)"
if [ -n "${RELEASE_TAG:-}" ] && [ "${RELEASE_TAG#v}" != "$VERSION" ]; then
    echo "ERROR: tag ${RELEASE_TAG} does not match setup.cfg version $VERSION"; exit 1
fi
echo ">> releasing vulnscan-ai $VERSION for: $DISTS"

# Build the RPM natively for one EL release inside its own AlmaLinux container,
# so its files land under that release's Python site-packages (…/python3.12/…
# on el10) and it is genuinely importable there — a plain el9→el10 copy is not.
# Copies the resulting noarch RPM into $OUT.
_build_podman() {
    local dist="$1" rt="${CONTAINER_RT:-podman}"
    echo ">> [$dist] native build in ${rt} almalinux:${dist#el}"
    "$rt" run --rm -v "$PWD":/src:ro -v "$OUT":/out "almalinux:${dist#el}" bash -c '
        set -e
        dnf -y install dnf-plugins-core >/dev/null 2>&1
        dnf config-manager --set-enabled crb >/dev/null 2>&1 || true
        dnf -y install rpm-build rpmdevtools python3-devel pyproject-rpm-macros \
            systemd-rpm-macros python3-setuptools python3-wheel python3-pip >/dev/null 2>&1
        rpmdev-setuptree
        cp -r /src /tmp/build && cd /tmp/build
        bash packaging/build-rpm.sh >/dev/null
        cp "$(find "$HOME"/rpmbuild/RPMS -name "vulnscan-ai-*.noarch.rpm" | head -1)" /out/
    '
}

OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT
for dist in $DISTS; do
    if [ "$dist" = "$HOST_DIST" ] && [ "${USE_MOCK:-0}" != "1" ]; then
        echo ">> [$dist] native build (rpmbuild, runs %check)"
        bash packaging/build-rpm.sh >/dev/null
        find "$(rpm --eval '%{_topdir}')/RPMS" \
             -name "vulnscan-ai-${VERSION}-*.${dist}.*.rpm" -exec cp {} "$OUT/" \;
    elif [ "${USE_MOCK:-0}" = "1" ]; then
        echo ">> [$dist] clean-chroot build (mock)"
        command -v mock >/dev/null || { echo "ERROR: mock not installed for $dist"; exit 1; }
        srpm="$(bash packaging/build-rpm.sh srpm | tail -1)"
        mock -r "alma+epel-${dist#el}-x86_64" --resultdir="$OUT/$dist" --rebuild "$srpm"
    elif command -v "${CONTAINER_RT:-podman}" >/dev/null; then
        _build_podman "$dist"
    else
        echo "ERROR: no builder for $dist (need the host dist, USE_MOCK=1, or podman)"; exit 1
    fi
done

echo ">> signing + publishing to $REPO_ROOT (extra noarch dists: ${EXTRA_DISTS:-none})"
RPMS_SRC="$OUT" REPO_BASEURL="$REPO_BASEURL" PKG_GLOB='vulnscan-ai-*' \
    EXTRA_DISTS="$EXTRA_DISTS" \
    bash packaging/make-repo.sh "$REPO_ROOT"

# SELinux label (no-op off SELinux) + reload nginx.
command -v chcon >/dev/null && $SUDO chcon -R -t httpd_sys_content_t "$REPO_ROOT" || true
$SUDO nginx -t && $SUDO systemctl reload nginx

echo ">> published vulnscan-ai $VERSION -> $REPO_BASEURL/el\$releasever"
