#!/usr/bin/env bash
# Build the vulnscan-ai (S)RPM from a checkout.
#
# Requires: rpm-build, pyproject-rpm-macros, systemd-rpm-macros, python3-devel
#   sudo dnf install rpm-build pyproject-rpm-macros systemd-rpm-macros python3-devel
#
# Usage:
#   packaging/build-rpm.sh          # build binary RPM (rpmbuild -ba)
#   packaging/build-rpm.sh srpm     # build only the SRPM (rpmbuild -bs)
#
# On success the path(s) of the built package(s) are printed; the SRPM path is
# printed on the last line of `srpm` mode so callers (CI/mock) can capture it.
set -euo pipefail

MODE="${1:-rpm}"
NAME=vulnscan-ai
VERSION=$(awk -F'=' '/^version *=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' setup.cfg)
TOPDIR=$(rpm --eval '%{_topdir}')
SRCDIR="${TOPDIR}/SOURCES"
STAGE="/tmp/${NAME}-${VERSION}"

echo ">> staging ${NAME} ${VERSION}" >&2
rm -rf "${STAGE}"
mkdir -p "${STAGE}" "${SRCDIR}" "${TOPDIR}/SPECS"
cp -r vulnscanai packaging tests pyproject.toml setup.cfg README.md COMMANDS.md config.sample.json "${STAGE}/"
# Drop build/cache artefacts so the source tarball is reproducible.
find "${STAGE}" -name '__pycache__' -type d -prune -exec rm -rf {} +
find "${STAGE}" -name '*.pyc' -delete
tar -C /tmp -czf "${SRCDIR}/${NAME}-${VERSION}.tar.gz" "${NAME}-${VERSION}"
cp "packaging/${NAME}.spec" "${TOPDIR}/SPECS/"

if [[ "${MODE}" == "srpm" ]]; then
    rpmbuild -bs "${TOPDIR}/SPECS/${NAME}.spec" >&2
    SRPM=$(find "${TOPDIR}/SRPMS" -name "${NAME}-${VERSION}*.src.rpm" | sort | tail -1)
    echo ">> built SRPM: ${SRPM}" >&2
    echo "${SRPM}"
else
    rpmbuild -ba "${TOPDIR}/SPECS/${NAME}.spec" >&2
    echo ">> built RPMs:" >&2
    find "${TOPDIR}/RPMS" -name "${NAME}-${VERSION}*.rpm" -printf '   %p\n' >&2
    echo ">> install with:  sudo dnf install <path-to>.rpm" >&2
    echo ">> then enable the timer:  sudo systemctl enable --now ${NAME}.timer" >&2
fi
