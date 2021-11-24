all: binaries build up

binaries:
	CGO_ENABLED=0 GOOS=linux go build -o ca/step-ca github.com/smallstep/certificates/cmd/step-ca

build: build-nginx build-ca build-renewer
build-nginx:
	docker build -t nginx-test:latest nginx
build-ca:
	docker build -t step-ca-test:latest ca
build-renewer:
	docker build -t step-renewer-test:latest renewer

up:
	docker-compose up

down:
	docker-compose down

inspect:
	step certificate inspect https://localhost:4443 --insecure

.PHONY: all binaries up down inspect
.PHONY: build build-nginx build-ca build-renewer
