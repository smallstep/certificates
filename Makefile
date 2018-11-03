PKG?=github.com/smallstep/certificates/cmd/step-ca
BINNAME?=step-ca

# Set V to 1 for verbose output from the Makefile
Q=$(if $V,,@)
PREFIX?=
SRC=$(shell find . -type f -name '*.go' -not -path "./vendor/*")
GOOS_OVERRIDE ?=

# Set shell to bash for `echo -e`
SHELL := /bin/bash

all: build lint test

.PHONY: all

#########################################
# Bootstrapping
#########################################

bootstra%:
	$Q which dep || go get github.com/golang/dep/cmd/dep
	$Q dep ensure

vendor: Gopkg.lock
	$Q dep ensure

BOOTSTRAP=\
	github.com/golang/lint/golint \
	github.com/client9/misspell/cmd/misspell \
	github.com/gordonklaus/ineffassign \
	github.com/tsenart/deadcode \
	github.com/alecthomas/gometalinter

define VENDOR_BIN_TMPL
vendor/bin/$(notdir $(1)): vendor
	$Q go build -o $$@ ./vendor/$(1)
VENDOR_BINS += vendor/bin/$(notdir $(1))
endef

$(foreach pkg,$(BOOTSTRAP),$(eval $(call VENDOR_BIN_TMPL,$(pkg))))

.PHONY: bootstra% vendor

#################################################
# Determine the type of `push` and `version`
#################################################

# Version flags to embed in the binaries
VERSION ?= $(shell [ -d .git ] && git describe --tags --always --dirty="-dev")
VERSION := $(shell echo $(VERSION) | sed 's/^v//')

# If TRAVIS_TAG is set then we know this ref has been tagged.
ifdef TRAVIS_TAG
	PUSHTYPE=release
else
	PUSHTYPE=master
endif

#########################################
# Build
#########################################

DATE    := $(shell date -u '+%Y-%m-%d %H:%M UTC')
LDFLAGS := -ldflags='-w -X "main.Version=$(VERSION)" -X "main.BuildTime=$(DATE)"'
GOFLAGS := CGO_ENABLED=0

build: $(PREFIX)bin/$(BINNAME)
	@echo "Build Complete!"

$(PREFIX)bin/$(BINNAME): vendor $(call rwildcard,*.go)
	$Q mkdir -p $(@D)
	$Q $(GOOS_OVERRIDE) $(GOFLAGS) go build -v -o $(PREFIX)bin/$(BINNAME) $(LDFLAGS) $(PKG)

# Target for building without calling dep ensure
simple:
	$Q mkdir -p bin/
	$Q $(GOOS_OVERRIDE) $(GOFLAGS) go build -v -o bin/$(BINNAME) $(LDFLAGS) $(PKG)
	@echo "Build Complete!"

.PHONY: build simple

#########################################
# Go generate
#########################################

generate:
	$Q go generate ./...

.PHONY: generate

#########################################
# Test
#########################################
test:
	$Q $(GOFLAGS) go test -short -coverprofile=coverage.out ./...

vtest:
	$(Q)for d in $$(go list ./... | grep -v vendor); do \
    echo -e "TESTS FOR: for \033[0;35m$$d\033[0m"; \
    $(GOFLAGS) go test -v -bench=. -run=. -short -coverprofile=coverage.out $$d; \
	out=$$?; \
	if [[ $$out -ne 0 ]]; then ret=$$out; fi;\
    rm -f profile.coverage.out; \
	done; exit $$ret;

.PHONY: test vtest

integrate: integration

integration: bin/$(BINNAME)
	$Q $(GOFLAGS) go test -tags=integration ./integration/...

.PHONY: integrate integration

#########################################
# Linting
#########################################

LINTERS=\
	gofmt \
	golint \
	vet \
	misspell \
	ineffassign \
	deadcode

$(patsubst %,%-bin,$(filter-out gofmt vet,$(LINTERS))): %-bin: vendor/bin/%
gofmt-bin vet-bin:

$(LINTERS): %: vendor/bin/gometalinter %-bin vendor
	$Q PATH=`pwd`/vendor/bin:$$PATH gometalinter --tests --disable-all --vendor \
	     --deadline=5m -s data -s pkg --enable $@ ./...
fmt:
	$Q gofmt -l -w $(SRC)

lint: $(LINTERS)

.PHONY: $(LINTERS) lint fmt

#########################################
# Install
#########################################

INSTALL_PREFIX?=/usr/

install: $(PREFIX)bin/$(BINNAME)
	$Q install -D $(PREFIX)bin/$(BINNAME) $(DESTDIR)$(INSTALL_PREFIX)bin/$(BINNAME)

uninstall:
	$Q rm -f $(DESTDIR)$(INSTALL_PREFIX)/bin/$(BINNAME)

.PHONY: install uninstall

#########################################
# Debian
#########################################

debian:
	$Q mkdir -p $(RELEASE); \
	OUTPUT=../step-ca_*.deb; \
	rm $$OUTPUT; \
	dpkg-buildpackage -b -rfakeroot -us -uc && cp $$OUTPUT $(RELEASE)/

distclean: clean

.PHONY: debian distclean

#################################################
# Build statically compiled step binary for various operating systems
#################################################

OUTPUT_ROOT=output/
BINARY_OUTPUT=$(OUTPUT_ROOT)binary/
BUNDLE_MAKE=v=$v GOOS_OVERRIDE='GOOS=$(1) GOARCH=$(2)' PREFIX=$(3) make $(3)bin/step
RELEASE=./.travis-releases

binary-linux:
	$(call BUNDLE_MAKE,linux,amd64,$(BINARY_OUTPUT)linux/)

binary-darwin:
	$(call BUNDLE_MAKE,darwin,amd64,$(BINARY_OUTPUT)darwin/)

define BUNDLE
	$(q)BUNDLE_DIR=$(BINARY_OUTPUT)$(1)/bundle; \
	stepName=step_$(2); \
 	mkdir -p $$BUNDLE_DIR $(RELEASE); \
	TMP=$$(mktemp -d $$BUNDLE_DIR/tmp.XXXX); \
	trap "rm -rf $$TMP" EXIT INT QUIT TERM; \
	newdir=$$TMP/$$stepName; \
	mkdir -p $$newdir/bin; \
	cp $(BINARY_OUTPUT)$(1)/bin/step $$newdir/bin/; \
	cp README.md $$newdir/; \
	NEW_BUNDLE=$(RELEASE)/step_$(2)_$(1)_$(3).tar.gz; \
	rm -f $$NEW_BUNDLE; \
    tar -zcvf $$NEW_BUNDLE -C $$TMP $$stepName;
endef

bundle-linux: binary-linux
	$(call BUNDLE,linux,$(VERSION),amd64)

bundle-darwin: binary-darwin
	$(call BUNDLE,darwin,$(VERSION),amd64)

.PHONY: binary-linux binary-darwin bundle-linux bundle-darwin

#################################################
# Targets for creating OS specific artifacts
#################################################

artifacts-linux-tag: bundle-linux debian

artifacts-darwin-tag: bundle-darwin

artifacts-tag: artifacts-linux-tag artifacts-darwin-tag

.PHONY: artifacts-linux-tag artifacts-darwin-tag artifacts-tag

#################################################
# Targets for creating step artifacts
#################################################

# For all builds that are not tagged
artifacts-master:

# For all builds with a release tag
artifacts-release: artifacts-tag

# This command is called by travis directly *after* a successful build
artifacts: artifacts-$(PUSHTYPE)

.PHONY: artifacts-master artifacts-release artifacts

#########################################
# Clean
#########################################

clean:
	@echo "You will need to run 'make bootstrap' or 'dep ensure' directly to re-download any dependencies."
	$Q rm -rf vendor
ifneq ($(BINNAME),"")
	$Q rm -f bin/$(BINNAME)
endif

.PHONY: clean
