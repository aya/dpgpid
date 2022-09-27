.PHONY: all default install shellcheck-% shellspec-% tests uninstall
BINDIR                          ?= $(PREFIX)/bin
PREFIX                          ?= /usr/local

MYOS                            ?= ../myos
MYOS_REPOSITORY                 ?= $(patsubst %/$(THIS),%/myos,$(THIS_REPOSITORY))
THIS                            ?= $(lastword $(subst /, ,$(THIS_REPOSITORY)))
THIS_REPOSITORY                 ?= $(shell git config --get remote.origin.url 2>/dev/null)
$(MYOS):
	  -@git clone $(MYOS_REPOSITORY) $(MYOS)
-include $(MYOS)/make/include.mk

default: tests

all: install tests

install: $(if $(shell which pip3),pip3-install,pip3-not-found)
	mkdir -p "$(BINDIR)"
	install dpgpid "$(BINDIR)/dpgpid"
	install keygen "$(BINDIR)/keygen"

pip3-install:
	pip3 install -r requirements.txt

pip3-not-found:
	printf "WARNING: pip3 not found, please manually install python modules from requirements.txt\n"

shellcheck-%:
	@shellcheck $*/*.sh

shellspec-%:
	@shellspec -f tap $*

tests: shellcheck-specs shellspec-specs

uninstall:
	rm -f "$(BINDIR)/dpgpid"
	rm -f "$(BINDIR)/keygen"
