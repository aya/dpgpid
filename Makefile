MYOS ?= ../myos
-include $(MYOS)/make/include.mk

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

.PHONY: all default install shellcheck-% shellspec-% tests uninstall

default: tests

all: install tests

install:
	mkdir -p "$(BINDIR)"
	install dpgpid "$(BINDIR)/dpgpid"

shellcheck-%:
	shellcheck $*/*.sh

shellspec-%:
	shellspec -f tap $*

tests: shellcheck-specs shellspec-specs

uninstall:
	rm -f "$(BINDIR)/dpgpid"
