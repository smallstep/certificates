all: binaries build deploy

binaries:
	GOOS=linux go build -o ca/step-ca github.com/smallstep/certificates/cmd/step-ca
	GOOS=linux go build -o renewer/step github.com/smallstep/cli/cmd/step

build: build-nginx build-ca build-renewer

build-nginx:
	docker build -t nginx-test:latest nginx
build-ca:
	docker build -t step-ca-test:latest ca
build-renewer:
	docker build -t step-renewer-test:latest renewer

deploy:
	docker stack deploy -c docker-compose.yml steplab

clean:
	docker service rm steplab_ca steplab_nginx steplab_renewer
	sleep 20
	docker volume rm -f steplab_certificates

ls: 
	docker service ls

ps:
	docker ps

logs:
	docker service ls | grep steplab | awk '{print $1}' | xargs -n 1 docker service logs

inspect:
	step certificate inspect https://localhost:4443 --insecure