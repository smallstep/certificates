## Example [Podman Quadlet container](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html#container-units-container) file

* `~/.config/containers/systemd/stepca.container` (rootless)
* `/etc/containers/systemd/stepca.container`      (rootful)

```
[Unit]
Description=Smallstep Certificate Authority
After=network-online.target

[Container]
PodmanArgs=--memory 25m --cpus 0.20
PidsLimit=50
DropCapability=ALL
AutoUpdate=registry
ContainerName=stepca
DropCapability=ALL
Environment=TZ="Europe/London"
Environment="DOCKER_STEPCA_INIT_NAME=Example CA"
Environment=DOCKER_STEPCA_INIT_DNS_NAMES=ca.custom.domain,10.89.0.10,localhost,127.0.0.1
Environment=DOCKER_STEPCA_INIT_PROVISIONER_NAME=admin@custom.domain
Environment=DOCKER_STEPCA_INIT_SSH=true
Environment=DOCKER_STEPCA_INIT_ACME=true
Environment=DOCKER_STEPCA_INIT_PASSWORD_FILE=/run/secrets/stepca
HostName=stepca
PodmanArgs=--privileged
# Alpine image
Image=docker.io/smallstep/step-ca
# Debian image with TPM support
#Image=docker.io/smallstep/step-ca:hsm
PublishPort=10.89.0.10:9000:9000/tcp
PublishPort=127.0.0.1:9000:9000/tcp
Secret=source=stepca,type=mount,uid=1000,gid=1000,mode=400
Volume=/path/to/volumes/stepca/config:/home/step:Z
DNS=10.89.0.1
DNSOption=~custom.domain

[Service]
Restart=always

[Install]
WantedBy=default.target
```

* Contributed by: [Stuart Cardall](https://github.com/itoffshore)
