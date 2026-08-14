# Copr "SCM" build method entry point (build source type "make srpm").
# Copr clones the repo into a mock chroot and runs, as root, with network
# access:
#   make -f .copr/Makefile srpm outdir="<outdir>" spec="<spec_path>"
# (see https://docs.copr.fedorainfracloud.org/user_documentation.html#make-srpm)
# This target must be self-contained: it vendors crates.io deps here (this
# step has network access) so the later mock build of the SRPM itself (no
# network) can run `cargo build --offline`. See vox.spec for the offline
# side. Already root here, so plain dnf -- no sudo (may not even exist in
# the minimal chroot).

outdir ?= $(CURDIR)/outdir
builddir := $(shell mktemp -d)

.PHONY: srpm
srpm:
	dnf -y install --setopt=install_weak_deps=False cargo rust rpm-build git

	mkdir -p "$(outdir)" "$(builddir)/SOURCES" "$(builddir)/SPECS"

	$(eval VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1))

	git archive --prefix=vox-$(VERSION)/ -o "$(builddir)/SOURCES/vox-$(VERSION).tar.gz" HEAD

	# Vendor against the exact Cargo.lock that was just archived from HEAD
	# above, not the ambient working tree's Cargo.lock -- those can drift
	# (e.g. an uncommitted `cargo build` bumping a lockfile entry), which
	# would vendor crate versions that don't match what Source0 ships and
	# break the offline `cargo build` in %build.
	mkdir -p "$(builddir)/src"
	tar -xzf "$(builddir)/SOURCES/vox-$(VERSION).tar.gz" -C "$(builddir)/src"
	cd "$(builddir)/src/vox-$(VERSION)" && cargo vendor --locked "$(builddir)/vendor" >/dev/null
	tar -C "$(builddir)" -czf "$(builddir)/SOURCES/vox-$(VERSION)-vendor.tar.gz" vendor

	cp vox.spec "$(builddir)/SPECS/"

	rpmbuild -bs \
		--define "_topdir $(builddir)" \
		"$(builddir)/SPECS/vox.spec"

	cp "$(builddir)"/SRPMS/*.src.rpm "$(outdir)/"
	rm -rf "$(builddir)"
