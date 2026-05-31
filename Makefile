GO ?= go
INSTALL ?= install
DITTO ?= ditto
PREFIX ?= $(HOME)/.local/bin
UNAME_S := $(shell uname -s)

.PHONY: build app install

build:
	$(GO) build -o secretbridge ./cmd/secretbridge

install: build
	$(INSTALL) -m 0755 secretbridge $(PREFIX)/secretbridge
