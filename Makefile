PKG?=github.com/smallstep/certificates/cmd/step-ca
BINNAME?=step-ca
CLOUDKMS_BINNAME?=step-cloudkms-init
CLOUDKMS_PKG?=github.com/smallstep/certificates/cmd/step-cloudkms-init
AWSKMS_BINNAME?=step-awskms-init
AWSKMS_PKG?=github.com/smallstep/certificates/cmd/step-awskms-init
YUBIKEY_BINNAME?=step-yubikey-init
YUBIKEY_PKG?=github.com/smallstep/certificates/cmd/step-yubikey-init

# Set V to 1 for verbose output from the Makefile
Q=$(if $V,,@)
PREFIX?=
SRC=$(shell find . -type f -name '*.go' -not -path "./vendor/*")
GOOS_OVERRIDE ?=
OUTPUT_ROOT=output/

all: build test lint

.PHONY: all

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
else
VERSION ?= $(shell [ -d .git ] && git describe --tags --always --dirty="-dev")
# If we are not in an active git dir then try reading the version from .VERSION.
# .VERSION contains a slug populated by `git archive`.
VERSION := $(or $(VERSION),$(shell ./.version.sh .VERSION))
PUSHTYPE := master
endif

VERSION := $(shell echo $(VERSION) | sed 's/^v//')

ifdef V
$(info    TRAVIS_TAG is $(TRAVIS_TAG))
$(info    VERSION is $(VERSION))
$(info    PUSHTYPE is $(PUSHTYPE))
endif

#########################################
# Build
#########################################

DATE    := $(shell date -u '+%Y-%m-%d %H:%M UTC')
LDFLAGS := -ldflags='-w -X "main.Version=$(VERSION)" -X "main.BuildTime=$(DATE)"'
GOFLAGS := CGO_ENABLED=0

download:
	$Q go mod download

build: $(PREFIX)bin/$(BINNAME) $(PREFIX)bin/$(CLOUDKMS_BINNAME) $(PREFIX)bin/$(AWSKMS_BINNAME) $(PREFIX)bin/$(YUBIKEY_BINNAME)
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

.PHONY: test

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
	$Q LOG_LEVEL=error golangci-lint run --timeout=30m

.PHONY: lint fmt

#########################################
# Install
#########################################

INSTALL_PREFIX?=/usr/

install: $(PREFIX)bin/$(BINNAME) $(PREFIX)bin/$(CLOUDKMS_BINNAME)
	$Q install -D $(PREFIX)bin/$(BINNAME) $(DESTDIR)$(INSTALL_PREFIX)bin/$(BINNAME)
	$Q install -D $(PREFIX)bin/$(CLOUDKMS_BINNAME) $(DESTDIR)$(INSTALL_PREFIX)bin/$(CLOUDKMS_BINNAME)

uninstall:
	$Q rm -f $(DESTDIR)$(INSTALL_PREFIX)/bin/$(BINNAME)
	$Q rm -f $(DESTDIR)$(INSTALL_PREFIX)/bin/$(CLOUDKMS_BINNAME)

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

.PHONY: clean

#########################################
# Dev
#########################################

run:
	$Q go run cmd/step-ca/main.go $(shell step path)/config/ca.json

.PHONY: run

#########################################
# Building Docker Image
#
# Builds a dockerfile for step by building a linux version of the step-cli and
# then copying the specific binary when building the container.
#
# This ensures the container is as small as possible without having to deal
# with getting access to private repositories inside the container during build
# time.
#########################################

# XXX We put the output for the build in 'output' so we don't mess with how we
# do rule overriding from the base Makefile (if you name it 'build' it messes up
# the wildcarding).
DOCKER_OUTPUT=$(OUTPUT_ROOT)docker/

DOCKER_MAKE=V=$V GOOS_OVERRIDE='GOOS=linux GOARCH=amd64' PREFIX=$(1) make $(1)bin/$(2)
DOCKER_BUILD=$Q docker build -t smallstep/$(1):latest -f docker/$(2) --build-arg BINPATH=$(DOCKER_OUTPUT)bin/$(1) .

docker: docker-make docker/Dockerfile.step-ca
	$(call DOCKER_BUILD,step-ca,Dockerfile.step-ca)

docker-make:
	mkdir -p $(DOCKER_OUTPUT)
	$(call DOCKER_MAKE,$(DOCKER_OUTPUT),step-ca)

.PHONY: docker docker-make

#################################################
# Releasing Docker Images
#
# Using the docker build infrastructure, this section is responsible for
# logging into docker hub and pushing the built docker containers up with the
# appropriate tags.
#################################################

DOCKER_TAG=docker tag smallstep/$(1):latest smallstep/$(1):$(2)
DOCKER_PUSH=docker push smallstep/$(1):$(2)

docker-tag:
	$(call DOCKER_TAG,step-ca,$(VERSION))

docker-push-tag: docker-tag
	$(call DOCKER_PUSH,step-ca,$(VERSION))

docker-push-tag-latest:
	$(call DOCKER_PUSH,step-ca,latest)

# Rely on DOCKER_USERNAME and DOCKER_PASSWORD being set inside the CI or
# equivalent environment
docker-login:
	$Q docker login -u="$(DOCKER_USERNAME)" -p="$(DOCKER_PASSWORD)"

.PHONY: docker-login docker-tag docker-push-tag docker-push-tag-latest

#################################################
# Targets for pushing the docker images
#################################################

# For all builds we build the docker container
docker-master: docker

# For all builds with a release candidate tag
docker-release-candidate: docker-master docker-login docker-push-tag

# For all builds with a release tag
docker-release: docker-release-candidate docker-push-tag-latest

.PHONY: docker-master docker-release-candidate docker-release

#########################################
# Debian
#########################################

changelog:
	$Q echo "step-certificates ($(VERSION)) unstable; urgency=medium" > debian/changelog
	$Q echo >> debian/changelog
	$Q echo "  * See https://github.com/smallstep/certificates/releases" >> debian/changelog
	$Q echo >> debian/changelog
	$Q echo " -- Smallstep Labs, Inc. <techadmin@smallstep.com>  $(shell date -uR)" >> debian/changelog

debian: changelog
	$Q mkdir -p $(RELEASE); \
	OUTPUT=../step-certificates_*.deb; \
	rm $$OUTPUT; \
	dpkg-buildpackage -b -rfakeroot -us -uc && cp $$OUTPUT $(RELEASE)/

distclean: clean

.PHONY: changelog debian distclean

#################################################
# Build statically compiled step binary for various operating systems
#################################################

BINARY_OUTPUT=$(OUTPUT_ROOT)binary/
RELEASE=./.travis-releases

define BUNDLE_MAKE
	# $(1) -- Go Operating System (e.g. linux, darwin, windows, etc.)
	# $(2) -- Go Architecture (e.g. amd64, arm, arm64, etc.)
	# $(3) -- Go ARM architectural family (e.g. 7, 8, etc.)
	# $(4) -- Parent directory for executables generated by 'make'.
	$(q) GOOS_OVERRIDE='GOOS=$(1) GOARCH=$(2) GOARM=$(3)' PREFIX=$(4) make $(4)bin/$(BINNAME) $(4)bin/$(CLOUDKMS_BINNAME)
endef

binary-linux:
	$(call BUNDLE_MAKE,linux,amd64,,$(BINARY_OUTPUT)linux/)

binary-linux-arm64:
	$(call BUNDLE_MAKE,linux,arm64,,$(BINARY_OUTPUT)linux.arm64/)

binary-linux-armv7:
	$(call BUNDLE_MAKE,linux,arm,7,$(BINARY_OUTPUT)linux.armv7/)

binary-darwin:
	$(call BUNDLE_MAKE,darwin,amd64,,$(BINARY_OUTPUT)darwin/)

define BUNDLE
    # $(1) -- Binary Output Dir Name
	# $(2) -- Step Platform Name
	# $(3) -- Step Binary Architecture
	# $(4) -- Step Binary Name (For Windows Comaptibility)
	$(q) ./make/bundle.sh "$(BINARY_OUTPUT)$(1)" "$(RELEASE)" "$(VERSION)" "$(2)" "$(3)" "$(4)" "$(5)"
endef

bundle-linux: binary-linux binary-linux-arm64 binary-linux-armv7
	$(call BUNDLE,linux,linux,amd64,$(BINNAME),$(CLOUDKMS_BINNAME))
	$(call BUNDLE,linux.arm64,linux,arm64,$(BINNAME),$(CLOUDKMS_BINNAME))
	$(call BUNDLE,linux.armv7,linux,armv7,$(BINNAME),$(CLOUDKMS_BINNAME))

bundle-darwin: binary-darwin
	$(call BUNDLE,darwin,darwin,amd64,$(BINNAME),$(CLOUDKMS_BINNAME))

.PHONY: binary-linux binary-darwin bundle-linux bundle-darwin

#################################################
# Targets for creating OS specific artifacts and archives
#################################################

artifacts-linux-tag: bundle-linux debian

artifacts-darwin-tag: bundle-darwin

artifacts-archive-tag:
	$Q mkdir -p $(RELEASE)
	$Q git archive v$(VERSION) | gzip > $(RELEASE)/step-certificates_$(VERSION).tar.gz

artifacts-tag: artifacts-linux-tag artifacts-darwin-tag artifacts-archive-tag

.PHONY: artifacts-linux-tag artifacts-darwin-tag artifacts-archive-tag artifacts-tag

#################################################
# Targets for creating step artifacts
#################################################

# For all builds that are not tagged
artifacts-master:

# For all builds with a release-candidate (-rc) tag
artifacts-release-candidate: artifacts-tag

# For all builds with a release tag
artifacts-release: artifacts-tag

# This command is called by travis directly *after* a successful build
artifacts: artifacts-$(PUSHTYPE) docker-$(PUSHTYPE)

.PHONY: artifacts-master artifacts-release-candidate artifacts-release artifacts
