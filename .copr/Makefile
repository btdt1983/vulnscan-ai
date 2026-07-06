# Copr SRPM entrypoint (SCM / "Custom" source method).
#
# Copr checks out this repo and runs:
#     make -f .copr/Makefile srpm outdir="<dir>" spec="packaging/vulnscan-ai.spec"
# in a minimal chroot. We build the SRPM with the project's own script (which
# stages the tarball + spec and runs `rpmbuild -bs`) and drop it in $(outdir).
# Copr then rebuilds that SRPM in every configured target chroot (EL9/EL10/
# Fedora), which is exactly the multi-distro build coverage we want.
#
# Only SRPM-time deps are needed here; the package's BuildRequires are resolved
# by Copr in the per-target build, not in this step.

srpm:
	dnf -y install rpm-build rpmdevtools
	rpmdev-setuptree
	bash packaging/build-rpm.sh srpm
	cp $$(find $$HOME/rpmbuild/SRPMS -name 'vulnscan-ai-*.src.rpm' | sort | tail -1) $(outdir)
