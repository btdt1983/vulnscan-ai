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

DISTS="${DISTS:-el9}"
# noarch packages are mirrored into these extra EL trees with no rebuild
# (default el10; el8 is intentionally excluded — its Python is too old).
EXTRA_DISTS="${EXTRA_DISTS:-el10}"
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

OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT
for dist in $DISTS; do
    if [ "$dist" = "$HOST_DIST" ] && [ "${USE_MOCK:-0}" != "1" ]; then
        echo ">> [$dist] native build (rpmbuild, runs %check)"
        bash packaging/build-rpm.sh >/dev/null
        find "$(rpm --eval '%{_topdir}')/RPMS" \
             -name "vulnscan-ai-${VERSION}-*.${dist}.*.rpm" -exec cp {} "$OUT/" \;
    else
        echo ">> [$dist] clean-chroot build (mock)"
        command -v mock >/dev/null || { echo "ERROR: mock not installed for $dist"; exit 1; }
        srpm="$(bash packaging/build-rpm.sh srpm | tail -1)"
        mock -r "alma+epel-${dist#el}-x86_64" --resultdir="$OUT/$dist" --rebuild "$srpm"
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
