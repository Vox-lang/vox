SHELL := /bin/bash

PREFIX ?= /usr/local
BINDIR := $(PREFIX)/bin
DATADIR := $(PREFIX)/share/vox
COREDIR := $(DATADIR)/coreasm
MANDIR := $(PREFIX)/share/man/man1

# Default target architecture (host architecture)
TARGET_ARCH := $(shell uname -m)

BIN := vox
RELEASE_PATH := target/release
RELEASE_BIN := $(RELEASE_PATH)/$(BIN)

.PHONY: all build install uninstall clean

all: build

build: $(RELEASE_BIN)

$(RELEASE_BIN): $(shell find src -name '*.rs' 2>/dev/null) Cargo.toml
	TARGET_ARCH=$(TARGET_ARCH) cargo build --release --manifest-path "Cargo.toml"

install:
	strip $(RELEASE_BIN)
	install -d "$(BINDIR)"
	install -m 0755 "$(RELEASE_BIN)" "$(BINDIR)/$(BIN)"
	install -d "$(DATADIR)"
	rm -rf "$(COREDIR)"
	cp -r coreasm "$(COREDIR)"
# Installed uncompressed: man reads vox.1 as happily as vox.1.gz, and which of
# the two a distribution wants is the distribution's business (rpm compresses
# it itself). $(PREFIX)/share/man is on the default MANPATH, so a plain
# `make install` is all `man vox` needs.
	install -d "$(MANDIR)"
	install -m 0644 man/$(BIN).1 "$(MANDIR)/$(BIN).1"

uninstall:
	rm -f "$(BINDIR)/$(BIN)"
	rm -rf "$(DATADIR)"
	rm -f "$(MANDIR)/$(BIN).1" "$(MANDIR)/$(BIN).1.gz"

clean:
	cargo clean
