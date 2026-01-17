SHELL := /bin/bash

PREFIX ?= /usr/local
BINDIR := $(PREFIX)/bin
DATADIR := $(PREFIX)/share/ec
COREDIR := $(DATADIR)/coreasm

# Default target architecture (host architecture)
TARGET_ARCH := $(shell uname -m)

BIN := ec
RELEASE_PATH := target/release
RELEASE_BIN := $(RELEASE_PATH)/$(BIN)

.PHONY: all build install uninstall clean

all: build

build: $(RELEASE_BIN)

$(RELEASE_BIN): $(shell find src -name '*.rs' 2>/dev/null) Cargo.toml
	TARGET_ARCH=$(TARGET_ARCH) cargo build --release

install:
	install -d "$(BINDIR)"
	install -m 0755 "$(RELEASE_BIN)" "$(BINDIR)/$(BIN)"
	install -d "$(DATADIR)"
	rm -rf "$(COREDIR)"
	cp -r coreasm "$(COREDIR)"

uninstall:
	rm -f "$(BINDIR)/$(BIN)"
	rm -rf "$(DATADIR)"

clean:
	cargo clean
