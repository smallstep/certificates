PKG?=github.com/smallstep/certificates/cmd/step-ca
BINNAME?=step-ca

all: build lint test

.PHONY: all

bootstrap:
	$Q which dep || go get github.com/golang/dep/cmd/dep
	$Q dep ensure

.PHONY: bootstrap

# Version flags to embed in the binaries
VERSION ?= $(shell [ -d .git ] && git describe --tags --always --dirty="-dev")
# If we are not in an active git dir then try reading the version from .VERSION.
# .VERSION contains a slug populated by `git archive`.
VERSION := $(or $(VERSION),$(shell ./.version.sh .VERSION))

-include vendor/github.com/smallstep/cli/make/common.mk

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

# Rely on DOCKER_USERNAME and DOCKER_PASSWORD being set inside the CI or
# equivalent environment
docker-login:
	$Q docker login -u="$(DOCKER_USERNAME)" -p="$(DOCKER_PASSWORD)"

.PHONY: docker-login docker-tag docker-push-tag

#################################################
# Targets for pushing the docker images
#################################################

# For all builds on the master branch, we actually build the container
docker-master: docker

# For all builds on the master branch with an rc tag
docker-release: docker-master docker-login docker-push-tag

.PHONY: docker-master docker-release

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
BUNDLE_MAKE=v=$v GOOS_OVERRIDE='GOOS=$(1) GOARCH=$(2)' PREFIX=$(3) make $(3)bin/$(BINNAME)
RELEASE=./.travis-releases

binary-linux:
	$(call BUNDLE_MAKE,linux,amd64,$(BINARY_OUTPUT)linux/)

binary-darwin:
	$(call BUNDLE_MAKE,darwin,amd64,$(BINARY_OUTPUT)darwin/)

define BUNDLE
	$(q)BUNDLE_DIR=$(BINARY_OUTPUT)$(1)/bundle; \
	stepName=step-certificates_$(2); \
 	mkdir -p $$BUNDLE_DIR $(RELEASE); \
	TMP=$$(mktemp -d $$BUNDLE_DIR/tmp.XXXX); \
	trap "rm -rf $$TMP" EXIT INT QUIT TERM; \
	newdir=$$TMP/$$stepName; \
	mkdir -p $$newdir/bin; \
	cp $(BINARY_OUTPUT)$(1)/bin/$(BINNAME) $$newdir/bin/; \
	cp README.md $$newdir/; \
	NEW_BUNDLE=$(RELEASE)/step-certificates_$(2)_$(1)_$(3).tar.gz; \
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
artifacts: artifacts-$(PUSHTYPE) docker-$(PUSHTYPE)

.PHONY: artifacts-master artifacts-release artifacts
