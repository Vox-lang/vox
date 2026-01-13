SHELL := /bin/bash

PREFIX ?= /usr/local
BINDIR := $(PREFIX)/bin
DATADIR := $(PREFIX)/share/ec
COREDIR := $(DATADIR)/coreasm


BIN := ec
RELEASE_BIN := target/release/$(BIN)

.PHONY: all build release install uninstall clean

all: build

build:
	cargo build

release:
	cargo build --release

install: release
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
