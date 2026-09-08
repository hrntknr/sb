GO ?= go
INSTALL ?= install
DITTO ?= ditto
PREFIX ?= $(HOME)/.local/bin
UNAME_S := $(shell uname -s)

.PHONY: build app install

build:
	$(GO) build -o sb ./cmd/sb

install: build
	$(INSTALL) -m 0755 sb $(PREFIX)/sb
