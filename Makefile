PKG?=github.com/smallstep/certificates/cmd/step-ca
BINNAME?=step-ca
CLOUDKMS_BINNAME?=step-cloudkms-init
CLOUDKMS_PKG?=github.com/smallstep/certificates/cmd/step-cloudkms-init
AWSKMS_BINNAME?=step-awskms-init
AWSKMS_PKG?=github.com/smallstep/certificates/cmd/step-awskms-init
YUBIKEY_BINNAME?=step-yubikey-init
YUBIKEY_PKG?=github.com/smallstep/certificates/cmd/step-yubikey-init
PKCS11_BINNAME?=step-pkcs11-init
PKCS11_PKG?=github.com/smallstep/certificates/cmd/step-pkcs11-init

# Set V to 1 for verbose output from the Makefile
Q=$(if $V,,@)
PREFIX?=
SRC=$(shell find . -type f -name '*.go' -not -path "./vendor/*")
GOOS_OVERRIDE ?=
OUTPUT_ROOT=output/

all: lint test build

ci: lintcgo testcgo build

.PHONY: all ci

#########################################
# Bootstrapping
#########################################

bootstra%:
	# Using a released version of golangci-lint to take into account custom replacements in their go.mod
	$Q GO111MODULE=on go get github.com/golangci/golangci-lint/cmd/golangci-lint@v1.24.0

.PHONY: bootstra%

#################################################
# Determine the type of `push` and `version`
#################################################

# If TRAVIS_TAG is set then we know this ref has been tagged.
ifdef TRAVIS_TAG
VERSION := $(TRAVIS_TAG)
NOT_RC  := $(shell echo $(VERSION) | grep -v -e -rc)
	ifeq ($(NOT_RC),)
PUSHTYPE := release-candidate
	else
PUSHTYPE := release
	endif
# GITHUB Actions
else ifdef GITHUB_REF
VERSION := $(shell echo $(GITHUB_REF) | sed 's/^refs\/tags\///')
NOT_RC  := $(shell echo $(VERSION) | grep -v -e -rc)
	ifeq ($(NOT_RC),)
PUSHTYPE := release-candidate
	else
PUSHTYPE := release
	endif
else
VERSION ?= $(shell [ -d .git ] && git describe --tags --always --dirty="-dev")
# If we are not in an active git dir then try reading the version from .VERSION.
# .VERSION contains a slug populated by `git archive`.
VERSION := $(or $(VERSION),$(shell ./.version.sh .VERSION))
	ifeq ($(TRAVIS_BRANCH),master)
PUSHTYPE := master
	else
PUSHTYPE := branch
	endif
endif

VERSION := $(shell echo $(VERSION) | sed 's/^v//')
DEB_VERSION := $(shell echo $(VERSION) | sed 's/-/~/g')

ifdef V
$(info    TRAVIS_TAG is $(TRAVIS_TAG))
$(info    GITHUB_REF is $(GITHUB_REF))
$(info    VERSION is $(VERSION))
$(info    DEB_VERSION is $(DEB_VERSION))
$(info    PUSHTYPE is $(PUSHTYPE))
endif

include make/docker.mk

#########################################
# Build
#########################################

DATE    := $(shell date -u '+%Y-%m-%d %H:%M UTC')
LDFLAGS := -ldflags='-w -X "main.Version=$(VERSION)" -X "main.BuildTime=$(DATE)"'
GOFLAGS := CGO_ENABLED=0

download:
	$Q go mod download

build: $(PREFIX)bin/$(BINNAME) $(PREFIX)bin/$(CLOUDKMS_BINNAME) $(PREFIX)bin/$(AWSKMS_BINNAME) $(PREFIX)bin/$(YUBIKEY_BINNAME) $(PREFIX)bin/$(PKCS11_BINNAME)
	@echo "Build Complete!"

$(PREFIX)bin/$(BINNAME): download $(call rwildcard,*.go)
	$Q mkdir -p $(@D)
	$Q $(GOOS_OVERRIDE) $(GOFLAGS) go build -v -o $(PREFIX)bin/$(BINNAME) $(LDFLAGS) $(PKG)

$(PREFIX)bin/$(CLOUDKMS_BINNAME): download $(call rwildcard,*.go)
	$Q mkdir -p $(@D)
	$Q $(GOOS_OVERRIDE) $(GOFLAGS) go build -v -o $(PREFIX)bin/$(CLOUDKMS_BINNAME) $(LDFLAGS) $(CLOUDKMS_PKG)

$(PREFIX)bin/$(AWSKMS_BINNAME): download $(call rwildcard,*.go)
	$Q mkdir -p $(@D)
	$Q $(GOOS_OVERRIDE) $(GOFLAGS) go build -v -o $(PREFIX)bin/$(AWSKMS_BINNAME) $(LDFLAGS) $(AWSKMS_PKG)

$(PREFIX)bin/$(YUBIKEY_BINNAME): download $(call rwildcard,*.go)
	$Q mkdir -p $(@D)
	$Q $(GOOS_OVERRIDE) $(GOFLAGS) go build -v -o $(PREFIX)bin/$(YUBIKEY_BINNAME) $(LDFLAGS) $(YUBIKEY_PKG)

$(PREFIX)bin/$(PKCS11_BINNAME): download $(call rwildcard,*.go)
	$Q mkdir -p $(@D)
	$Q $(GOOS_OVERRIDE) $(GOFLAGS) go build -v -o $(PREFIX)bin/$(PKCS11_BINNAME) $(LDFLAGS) $(PKCS11_PKG)

# Target to force a build of step-ca without running tests
simple: build

.PHONY: download build simple

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

testcgo:
	$Q go test -short -coverprofile=coverage.out ./...

.PHONY: test testcgo

integrate: integration

integration: bin/$(BINNAME)
	$Q $(GOFLAGS) go test -tags=integration ./integration/...

.PHONY: integrate integration

#########################################
# Linting
#########################################

fmt:
	$Q gofmt -l -w $(SRC)

lint:
	$Q $(GOFLAGS) LOG_LEVEL=error golangci-lint run --timeout=30m

lintcgo:
	$Q LOG_LEVEL=error golangci-lint run --timeout=30m

.PHONY: fmt lint lintcgo

#########################################
# Install
#########################################

INSTALL_PREFIX?=/usr/

install: $(PREFIX)bin/$(BINNAME) $(PREFIX)bin/$(CLOUDKMS_BINNAME) $(PREFIX)bin/$(AWSKMS_BINNAME)
	$Q install -D $(PREFIX)bin/$(BINNAME) $(DESTDIR)$(INSTALL_PREFIX)bin/$(BINNAME)
	$Q install -D $(PREFIX)bin/$(CLOUDKMS_BINNAME) $(DESTDIR)$(INSTALL_PREFIX)bin/$(CLOUDKMS_BINNAME)
	$Q install -D $(PREFIX)bin/$(AWSKMS_BINNAME) $(DESTDIR)$(INSTALL_PREFIX)bin/$(AWSKMS_BINNAME)

uninstall:
	$Q rm -f $(DESTDIR)$(INSTALL_PREFIX)/bin/$(BINNAME)
	$Q rm -f $(DESTDIR)$(INSTALL_PREFIX)/bin/$(CLOUDKMS_BINNAME)
	$Q rm -f $(DESTDIR)$(INSTALL_PREFIX)/bin/$(AWSKMS_BINNAME)

.PHONY: install uninstall

#########################################
# Clean
#########################################

clean:
ifneq ($(BINNAME),"")
	$Q rm -f bin/$(BINNAME)
endif
ifneq ($(CLOUDKMS_BINNAME),"")
	$Q rm -f bin/$(CLOUDKMS_BINNAME)
endif
ifneq ($(AWSKMS_BINNAME),"")
	$Q rm -f bin/$(AWSKMS_BINNAME)
endif
ifneq ($(YUBIKEY_BINNAME),"")
	$Q rm -f bin/$(YUBIKEY_BINNAME)
endif
ifneq ($(PKCS11_BINNAME),"")
	$Q rm -f bin/$(PKCS11_BINNAME)
endif

.PHONY: clean

#########################################
# Dev
#########################################

run:
	$Q go run cmd/step-ca/main.go $(shell step path)/config/ca.json

.PHONY: run

#########################################
# Debian
#########################################

changelog:
	$Q echo "step-ca ($(DEB_VERSION)) unstable; urgency=medium" > debian/changelog
	$Q echo >> debian/changelog
	$Q echo "  * See https://github.com/smallstep/certificates/releases" >> debian/changelog
	$Q echo >> debian/changelog
	$Q echo " -- Smallstep Labs, Inc. <techadmin@smallstep.com>  $(shell date -uR)" >> debian/changelog

debian: changelog
	$Q mkdir -p $(RELEASE); \
	OUTPUT=../step-ca*.deb; \
	rm $$OUTPUT; \
	dpkg-buildpackage -b -rfakeroot -us -uc && cp $$OUTPUT $(RELEASE)/

distclean: clean

.PHONY: changelog debian distclean

#################################################
# Build statically compiled step binary for various operating systems
#################################################

BINARY_OUTPUT=$(OUTPUT_ROOT)binary/
RELEASE=./.releases

define BUNDLE_MAKE
	# $(1) -- Go Operating System (e.g. linux, darwin, windows, etc.)
	# $(2) -- Go Architecture (e.g. amd64, arm, arm64, etc.)
	# $(3) -- Go ARM architectural family (e.g. 7, 8, etc.)
	# $(4) -- Parent directory for executables generated by 'make'.
	$(q) GOOS_OVERRIDE='GOOS=$(1) GOARCH=$(2) GOARM=$(3)' PREFIX=$(4) make $(4)bin/$(BINNAME) $(4)bin/$(CLOUDKMS_BINNAME) $(4)bin/$(AWSKMS_BINNAME)
endef

binary-linux:
	$(call BUNDLE_MAKE,linux,amd64,,$(BINARY_OUTPUT)linux/)

binary-linux-arm64:
	$(call BUNDLE_MAKE,linux,arm64,,$(BINARY_OUTPUT)linux.arm64/)

binary-linux-armv7:
	$(call BUNDLE_MAKE,linux,arm,7,$(BINARY_OUTPUT)linux.armv7/)

binary-darwin:
	$(call BUNDLE_MAKE,darwin,amd64,,$(BINARY_OUTPUT)darwin/)

.PHONY: binary-linux binary-linux-arm64 binary-linux-armv7 binary-darwin

#################################################
# Targets for creating step artifacts
#################################################

docker-artifacts: docker-$(PUSHTYPE)

.PHONY: docker-artifacts
