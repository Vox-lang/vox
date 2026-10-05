# Two build paths, one spec, chosen by the `rpmmacros` bcond.
#
# Vox has no dependencies beyond the Rust standard library: Cargo.lock lists
# only vox-lang itself, so there are no crates to unbundle, vendor or declare.
# What still differs between distributions is the tooling:
#
# Fedora builds with the cargo RPM macros (cargo-rpm-macros), which the
# Rust Packaging Guidelines require of packages that build Rust code with
# cargo (https://docs.fedoraproject.org/en-US/packaging-guidelines/Rust/).
#
# Everywhere else -- EPEL, CentOS Stream, openSUSE, Mageia, Amazon Linux,
# openEuler, Azure Linux, and Fedora ELN -- ships no cargo-rpm-macros, so
# those chroots call `cargo build --release --offline` directly. With no
# crates to fetch, --offline needs no vendor tarball and no source
# replacement.
#
# Copr builds ONE source RPM and feeds it to every chroot, but mock rebuilds
# that SRPM inside each chroot before resolving its BuildRequires, so this
# condition is re-evaluated per chroot and each one gets the path and the
# BuildRequires it can satisfy. `rpmbuild --with rpmmacros` forces the macro
# path anywhere, `--without rpmmacros` the plain cargo one.
#
# %%{fedora} alone is NOT quite the right test: Amazon Linux 2023 defines
# %%{fedora} too (it is Fedora-derived) yet ships no cargo-rpm-macros, so it
# is excluded by %%{amzn} and builds with plain cargo - found when the v0.4.11
# tag build failed on exactly that chroot with 'No matching package to
# install: cargo-rpm-macros'. For everything else, "The ELN buildroot defines the %%{rhel}
# macro ... and does not define the %%{fedora} macro" --
# https://docs.fedoraproject.org/en-US/eln/eln-macros/ -- and neither do RHEL,
# CentOS Stream, openSUSE or Mageia.
%if 0%{?fedora} && !0%{?amzn}
%bcond_without rpmmacros
%else
%bcond_with rpmmacros
%endif

# The test suite compiles and RUNS x86-64 programs, so it can only pass on
# x86_64; %%check is guarded accordingly below. --without check skips it.
%bcond_without check

Name:           vox
Version:        0.4.15
Release:        1%{?dist}
Summary:        Compiler for a constrained, sentence-based English programming language

# The binary links nothing but the Rust standard library, so the licence of
# what ships is vox's own: no crate is linked into it.
License:        GPL-3.0-or-later
URL:            https://github.com/Vox-lang/vox
Source0:        %{url}/archive/v%{version}/vox-%{version}.tar.gz

# The Rust toolchain links through cc, so a C compiler is invoked on both
# paths even though no C is compiled: "If your application is a C or C++
# application you must list a BuildRequires against gcc, gcc-c++ or clang" --
# https://docs.fedoraproject.org/en-US/packaging-guidelines/C_and_C++/
BuildRequires:  gcc

%if %{without rpmmacros}
BuildRequires:  cargo
BuildRequires:  rust >= 1.71
%else
# "Packages that build Rust code with cargo ... MUST add BuildRequires:
# cargo-rpm-macros" (Rust Packaging Guidelines). >= 24 is the bound Fedora's
# own rust2rpm-generated specs carry (rust-ripgrep); it covers every macro
# used below.
BuildRequires:  cargo-rpm-macros >= 24
%endif

%if %{with check}
%ifarch x86_64
# %%check compiles Vox programs and runs them, which shells out to nasm and
# ld. Only on x86_64: see the %%check section for why the suite runs nowhere
# else, and nasm is an x86 assembler that other architectures need not carry.
BuildRequires:  nasm
BuildRequires:  binutils
%endif
%endif

# vox shells out to nasm/ld only when it compiles a *user's* .vox program,
# not to build vox itself, so these are runtime Requires, not BuildRequires.
Requires:       nasm
Requires:       binutils

# Libraries are not part of the compiler and it never needs them -- Vox has no
# standard library by design. Suggests records that they exist without dnf
# pulling them in; a plain `dnf install vox` stays exactly as it was.
Suggests:       vox-libs

%if %{without rpmmacros}
# Debuginfo is skipped on the plain cargo path only, and the guidelines want the reason
# in the spec. find-debuginfo's source-file attribution for this LTO release
# binary is chroot-dependent: it produced a real vox-debugsource package on
# Fedora 44, but on Fedora ELN the debugsourcefiles.list came back empty and
# rpm there treats an empty %%files -f list as fatal ("Empty %%files file ...
# debugsourcefiles.list") -- commit 932174b, which is the failure this line
# was added for. This path is exactly the set of chroots that cannot be tested
# from a Fedora box, ELN among them, so the skip stays here rather than
# chasing per-chroot elfutils behaviour.
#
# The macro path does NOT skip it, and is the path Fedora reviews. There,
# %%cargo_prep writes the build profile itself -- `debug` from
# %%{rustflags_debuginfo}, `strip = "none"` -- so debug info is pinned in
# cargo's own profile rather than only in the RUSTFLAGS that
# %%set_build_flags exports, and normal debuginfo extraction applies.
%global debug_package %{nil}
%endif

%description
%{summary}.

Vox compiles directly to native x86_64 NASM assembly with no libc, no
garbage collector, and no hidden runtime system. All abstractions are
resolved at compile time.

%prep
%autosetup -n vox-%{version}
%if %{with rpmmacros}
%cargo_prep

%generate_buildrequires
%cargo_generate_buildrequires
%endif

%build
%if %{with rpmmacros}
%cargo_build
%else
cargo build --release --offline
%endif

%install
%if %{with rpmmacros}
%cargo_install
%else
install -Dm0755 target/release/%{name} %{buildroot}%{_bindir}/%{name}
%endif

install -d %{buildroot}%{_datadir}/%{name}
cp -r coreasm %{buildroot}%{_datadir}/%{name}/coreasm
find %{buildroot}%{_datadir}/%{name}/coreasm -type d -exec chmod 0755 {} +
find %{buildroot}%{_datadir}/%{name}/coreasm -type f -exec chmod 0644 {} +

install -Dpm0644 man/%{name}.1 %{buildroot}%{_mandir}/man1/%{name}.1

%if %{with check}
%check
# The suite compiles Vox sources to x86-64 assembly and runs the result, so it
# is meaningful only where that result can execute. Other architectures build
# the compiler but cannot run what it emits.
%ifarch x86_64
# Point the compiler at the coreasm in the build tree. Without it the
# resolution order would reach for an installed /usr/share/vox/coreasm, and a
# runtime change in this source tree would go untested.
export VOX_CORE_PATH="$(pwd)/coreasm"
%if %{with rpmmacros}
%cargo_test
%else
cargo test --release --offline
%endif
%endif
%endif

%files
%license LICENSE
%doc README.md
%{_bindir}/%{name}
%{_datadir}/%{name}/
%{_mandir}/man1/%{name}.1*

%changelog
* Sun Sep 06 2026 TheJostler <josj@tegosec.com> - 0.4.15-1
- New upstream release 0.4.15

* Fri Aug 28 2026 TheJostler <josj@tegosec.com> - 0.4.14-1
- New upstream release 0.4.14

* Mon Aug 24 2026 TheJostler <josj@tegosec.com> - 0.4.13-1
- New upstream release 0.4.13

* Mon Aug 24 2026 TheJostler <josj@tegosec.com> - 0.4.12-1
- New upstream release 0.4.12

* Sun Aug 23 2026 TheJostler <josj@tegosec.com> - 0.4.11-1
- New upstream release 0.4.11

* Sat Aug 22 2026 TheJostler <josj@tegosec.com> - 0.4.10-1
- Update to 0.4.10 and ship a manual page, so "man vox" works
- Build against Fedora's packaged crates instead of vendored ones, and run
  the upstream test suite at build time

* Fri Aug 14 2026 TheJostler <josj@tegosec.com> - 0.3.5-1
- Initial COPR packaging
