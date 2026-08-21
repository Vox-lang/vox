Name:           vox
Version:        0.4.9
Release:        1%{?dist}
Summary:        A systems level compiler for Vox (sentence based code)

License:        GPL-3.0-or-later
URL:            https://github.com/Vox-lang/vox
Source0:        %{url}/archive/v%{version}/vox-%{version}.tar.gz
# Vendored crates.io dependencies, built by .copr/Makefile's srpm target so
# the mock chroot build can run fully offline (`cargo build --offline`).
Source1:        vox-%{version}-vendor.tar.gz

BuildRequires:  cargo
BuildRequires:  rust >= 1.71

# vox shells out to nasm/ld only when it compiles a *user's* .vox program,
# not to build vox itself, so these are runtime Requires, not BuildRequires.
Requires:       nasm
Requires:       binutils

# Libraries are not part of the compiler and it never needs them -- Vox has no
# standard library by design. Suggests records that they exist without dnf
# pulling them in; a plain `dnf install vox` stays exactly as it was.
Suggests:       vox-libs

# find-debuginfo's source-file attribution for this LTO release binary is
# rpm/elfutils-version-dependent: it produces a real vox-debugsource package
# on Fedora 44, but on Fedora ELN the resulting debugsourcefiles.list comes
# back empty, and rpm there treats an empty %files -f list as fatal ("Empty
# %files file ... debugsourcefiles.list"). Skip debuginfo subpackage
# generation entirely so this doesn't depend on which chroot builds it.
%global debug_package %{nil}

%description
%{summary}.

Vox compiles directly to native x86_64 NASM assembly with no libc, no
garbage collector, and no hidden runtime system. All abstractions are
resolved at compile time.

%prep
%autosetup -n vox-%{version} -a1
mkdir -p .cargo
cat > .cargo/config.toml <<'EOF'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF

%build
cargo build --release --offline

%install
install -Dm0755 target/release/%{name} %{buildroot}%{_bindir}/%{name}
install -d %{buildroot}%{_datadir}/%{name}
cp -r coreasm %{buildroot}%{_datadir}/%{name}/coreasm
find %{buildroot}%{_datadir}/%{name}/coreasm -type d -exec chmod 0755 {} +
find %{buildroot}%{_datadir}/%{name}/coreasm -type f -exec chmod 0644 {} +

%files
%license LICENSE
%doc README.md
%{_bindir}/%{name}
%{_datadir}/%{name}/

%changelog
* Fri Aug 14 2026 TheJostler <josj@tegosec.com> - 0.3.5-1
- Initial COPR packaging
