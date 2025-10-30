PKG?=github.com/smallstep/certificates/cmd/step-ca
BINNAME?=step-ca

# Set V to 1 for verbose output from the Makefile
Q=$(if $V,,@)
PREFIX?=
SRC=$(shell find . -type f -name '*.go' -not -path "./vendor/*")
GOOS_OVERRIDE ?=

all: lint test build

ci: testcgo build

.PHONY: all ci

#########################################
# Bootstrapping
#########################################

bootstra%:
	$Q curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin latest
	$Q go install golang.org/x/vuln/cmd/govulncheck@latest
	$Q go install gotest.tools/gotestsum@latest
	$Q go install github.com/goreleaser/goreleaser/v2@latest
	$Q go install github.com/sigstore/cosign/v2/cmd/cosign@latest

.PHONY: bootstra%

#################################################
# Determine the type of `push` and `version`
#################################################

# GITHUB Actions
ifdef GITHUB_REF
VERSION ?= $(shell echo $(GITHUB_REF) | sed 's/^refs\/tags\///')
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
PUSHTYPE := branch
endif

VERSION := $(shell echo $(VERSION) | sed 's/^v//')

ifdef V
$(info    GITHUB_REF is $(GITHUB_REF))
$(info    VERSION is $(VERSION))
$(info    PUSHTYPE is $(PUSHTYPE))
endif

#########################################
# Build
#########################################

DATE    := $(shell date -u '+%Y-%m-%d %H:%M UTC')
LDFLAGS := -ldflags='-w -X "main.Version=$(VERSION)" -X "main.BuildTime=$(DATE)"'

# Always explicitly enable or disable cgo,
# so that go doesn't silently fall back on
# non-cgo when gcc is not found.
ifeq (,$(findstring CGO_ENABLED,$(GO_ENVS)))
	ifneq ($(origin GOFLAGS),undefined)
		# This section is for backward compatibility with 
		# 
		# $ make build GOFLAGS=""
		#
		# which is how we recommended building step-ca with cgo support
		# until June 2023.
		GO_ENVS := $(GO_ENVS) CGO_ENABLED=1
	else
		GO_ENVS := $(GO_ENVS) CGO_ENABLED=0
	endif
endif

download:
	$Q go mod download

build: $(PREFIX)bin/$(BINNAME)
	@echo "Build Complete!"

$(PREFIX)bin/$(BINNAME): download $(call rwildcard,*.go)
	$Q mkdir -p $(@D)
	$Q $(GOOS_OVERRIDE) GOFLAGS="$(GOFLAGS)" $(GO_ENVS) go build -v -o $(PREFIX)bin/$(BINNAME) $(LDFLAGS) $(PKG)

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
test: testdefault testtpmsimulator combinecoverage

testdefault:
	$Q $(GO_ENVS) gotestsum -- -coverprofile=defaultcoverage.out -short -covermode=atomic ./...

testtpmsimulator:
	$Q CGO_ENABLED=1 gotestsum -- -coverprofile=tpmsimulatorcoverage.out -short -covermode=atomic -tags tpmsimulator ./acme 

testcgo:
	$Q gotestsum -- -coverprofile=coverage.out -short -covermode=atomic ./...

combinecoverage:
	cat defaultcoverage.out tpmsimulatorcoverage.out > coverage.out

.PHONY: test testdefault testtpmsimulator testcgo combinecoverage

integrate: integration

integration: bin/$(BINNAME)
	$Q $(GO_ENVS) gotestsum -- -tags=integration ./integration/...

.PHONY: integrate integration

#########################################
# Linting
#########################################

fmt:
	$Q goimports -l -w $(SRC)

lint: SHELL:=/bin/bash
lint:
	$Q LOG_LEVEL=error golangci-lint run --config <(curl -s https://raw.githubusercontent.com/smallstep/workflows/master/.golangci.yml) --timeout=30m
	$Q govulncheck ./...

.PHONY: fmt lint

#########################################
# Install
#########################################

INSTALL_PREFIX?=/usr/local/

install: $(PREFIX)bin/$(BINNAME)
	$Q install -D $(PREFIX)bin/$(BINNAME) $(DESTDIR)$(INSTALL_PREFIX)bin/$(BINNAME)

uninstall:
	$Q rm -f $(DESTDIR)$(INSTALL_PREFIX)/bin/$(BINNAME)

.PHONY: install uninstall

#########################################
# Clean
#########################################

clean:
ifneq ($(BINNAME),"")
	$Q rm -f bin/$(BINNAME)
endif

.PHONY: clean

#########################################
# Dev
#########################################

run:
	$Q go run cmd/step-ca/main.go $(shell step path)/config/ca.json

.PHONY: run

