.PHONY: all default install shellcheck-% shellspec-% tests uninstall
BINDIR                          ?= $(PREFIX)/bin
PREFIX                          ?= /usr/local

MYOS                            ?= ../myos
MYOS_REPOSITORY                 ?= $(patsubst %/dpgpid,%/myos,$(shell git config --get remote.origin.url 2>/dev/null))
$(MYOS):
	  -@git clone $(MYOS_REPOSITORY) $(MYOS)
-include $(MYOS)/make/include.mk

default: tests

all: install tests

install:
	mkdir -p "$(BINDIR)"
	install dpgpid "$(BINDIR)/dpgpid"
	install keygen "$(BINDIR)/keygen"
	pip install -r requirements.txt

shellcheck-%:
	@shellcheck $*/*.sh

shellspec-%:
	@shellspec -f tap $*

tests: shellcheck-specs shellspec-specs

uninstall:
	rm -f "$(BINDIR)/dpgpid"
	rm -f "$(BINDIR)/keygen"
