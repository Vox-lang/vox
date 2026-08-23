# Copr "SCM" build method entry point (build source type "make srpm").
# Copr clones the repo into a mock chroot and runs, as root, with network
# access:
#   make -f .copr/Makefile srpm outdir="<outdir>" spec="<spec_path>"
# (see https://docs.copr.fedorainfracloud.org/user_documentation.html#make-srpm)
# This target must be self-contained: it vendors crates.io deps here (this
# step has network access) so a later mock build of the SRPM itself (no
# network) can run `cargo build --offline` on the chroots that build vendored.
# See vox.spec for both build paths. Already root here, so plain dnf -- no
# sudo (may not even exist in the minimal chroot).

outdir ?= $(CURDIR)/outdir
builddir := $(shell mktemp -d)

.PHONY: srpm
srpm:
	dnf -y install --setopt=install_weak_deps=False cargo rust rpm-build git curl

	mkdir -p "$(outdir)" "$(builddir)/SOURCES" "$(builddir)/SPECS"

	$(eval VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1))

	# Source0 has to be what vox.spec's Source0 URL actually serves:
	# "sources used to build a package should be the vanilla sources
	# available from upstream" --
	# https://docs.fedoraproject.org/en-US/packaging-guidelines/SourceURL/
	# `git archive` cannot promise the same bytes -- its gzip framing is its
	# own -- so on a RELEASE build (HEAD's tree is the release tag's tree)
	# download the GitHub archive and ship exactly that. If the download
	# fails, reproduce it instead: `git archive --format=tar <tag> | gzip -n -6`
	# produced the identical file for v0.4.10 (sha256 3c7870bf93...), because
	# GitHub's tar stream *is* a plain `git archive` of the tag and only the
	# gzip wrapper differed.
	#
	# On a SNAPSHOT build off main there is no upstream archive to match, so
	# archive HEAD; the checksum a reviewer compares is a released build's.
	# The same fallback covers a clone that arrived without tags.
	#
	# The URL is read out of the spec rather than written again here, so the
	# archive location lives in one place. Version skew between Cargo.toml
	# and vox.spec is fatal: it would name the tarball from one and fetch it
	# from the other.
	set -e; \
	tag="v$(VERSION)"; \
	src="$(builddir)/SOURCES/vox-$(VERSION).tar.gz"; \
	specver="$$(rpmspec -q --qf '%{version}\n' vox.spec | head -1)"; \
	[ "$$specver" = "$(VERSION)" ] || \
		{ echo "vox.spec Version ($$specver) != Cargo.toml version ($(VERSION))" >&2; exit 1; }; \
	url="$$(rpmspec -P vox.spec | sed -n 's/^Source0:[[:space:]]*//p' | head -1)"; \
	if [ -n "$$url" ] && git rev-parse -q --verify "$$tag^{tree}" >/dev/null 2>&1 && \
	   [ "$$(git rev-parse "$$tag^{tree}")" = "$$(git rev-parse 'HEAD^{tree}')" ]; then \
		echo "release build: HEAD is the tree of $$tag, fetching $$url"; \
		if ! curl -fsSL --retry 3 -o "$$src" "$$url"; then \
			echo "download failed; reproducing the upstream archive from $$tag"; \
			git archive --format=tar --prefix=vox-$(VERSION)/ "$$tag" | gzip -n -6 > "$$src"; \
		fi; \
	else \
		echo "snapshot build: HEAD is not $$tag, archiving HEAD"; \
		git archive --prefix=vox-$(VERSION)/ -o "$$src" HEAD; \
	fi

	# Vendor against the exact Cargo.lock inside the tarball that is about to
	# be shipped, not the ambient working tree's Cargo.lock -- those can drift
	# (e.g. an uncommitted `cargo build` bumping a lockfile entry), which
	# would vendor crate versions that don't match what Source0 ships and
	# break the offline `cargo build` on the vendored path.
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
