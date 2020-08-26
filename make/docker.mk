#########################################
# Building Docker Image
#
# This uses a multi-stage build file. The first stage is a builder (that might
# be large in size). After the build has succeeded, the statically linked
# binary is copied to a new image that is optimized for size.
#########################################

ifeq (, $(shell which docker))
	DOCKER_CLIENT_OS := linux
else
	DOCKER_CLIENT_OS := $(strip $(shell docker version -f '{{.Client.Os}}' 2>/dev/null))
endif

DOCKER_PLATFORMS = linux/amd64,linux/386,linux/arm,linux/arm64
DOCKER_IMAGE_NAME = smallstep/step-ca

docker-prepare:
	# Ensure, we can build for ARM architecture
ifeq (linux,$(DOCKER_CLIENT_OS))
	[ -f /proc/sys/fs/binfmt_misc/qemu-arm ] || docker run --rm --privileged linuxkit/binfmt:v0.8-amd64
endif

	# Register buildx builder
	mkdir -p $$HOME/.docker/cli-plugins

	test -f $$HOME/.docker/cli-plugins/docker-buildx || \
		(wget -q -O $$HOME/.docker/cli-plugins/docker-buildx https://github.com/docker/buildx/releases/download/v0.4.1/buildx-v0.4.1.$(DOCKER_CLIENT_OS)-amd64 && \
		chmod +x $$HOME/.docker/cli-plugins/docker-buildx)

	docker buildx create --use --name mybuilder --platform="$(DOCKER_PLATFORMS)" || true

.PHONY: docker-prepare

#################################################
# Releasing Docker Images
#
# Using the docker build infrastructure, this section is responsible for
# logging into docker hub.
#################################################

# Rely on DOCKER_USERNAME and DOCKER_PASSWORD being set inside the CI or
# equivalent environment
docker-login:
	$Q docker login -u="$(DOCKER_USERNAME)" -p="$(DOCKER_PASSWORD)"

.PHONY: docker-login

#################################################
# Targets for different type of builds
#################################################

define DOCKER_BUILDX
	# $(1) -- Image Tag
	# $(2) -- Push (empty is no push | --push will push to dockerhub)
	docker buildx build . --progress plain -t $(DOCKER_IMAGE_NAME):$(1) -f docker/Dockerfile.step-ca --platform="$(DOCKER_PLATFORMS)" $(2)
endef

# For non-master builds don't build the docker containers.
docker-branch:

# For master builds don't build the docker containers.
docker-master:

# For all builds with a release candidate tag build and push the containers.
docker-release-candidate: docker-prepare docker-login
	$(call DOCKER_BUILDX,$(VERSION),--push)

# For all builds with a release tag build and push the containers.
docker-release: docker-prepare docker-login
	$(call DOCKER_BUILDX,latest,--push)
	$(call DOCKER_BUILDX,$(VERSION),--push)

.PHONY: docker-branch docker-master docker-release-candidate docker-release

# XXX We put the output for the build in 'output' so we don't mess with how we
# do rule overriding from the base Makefile (if you name it 'build' it messes up
# the wildcarding).
DOCKER_OUTPUT=$(OUTPUT_ROOT)docker/

DOCKER_MAKE=V=$V GOOS_OVERRIDE='GOOS=linux GOARCH=amd64' PREFIX=$(1) make $(1)bin/$(BINNAME)
DOCKER_BUILD=$Q docker build -t $(DOCKER_IMAGE_NAME):latest -f docker/Dockerfile.step-ca --build-arg BINPATH=$(DOCKER_OUTPUT)bin/$(BINNAME) .

docker-dev: docker/Dockerfile.step-ca
	mkdir -p $(DOCKER_OUTPUT)
	$(call DOCKER_MAKE,$(DOCKER_OUTPUT),step-ca)
	$(call DOCKER_BUILD)

.PHONY: docker-dev
