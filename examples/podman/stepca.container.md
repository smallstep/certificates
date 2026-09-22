## Example [Podman Quadlet container](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html#container-units-container) file

* `~/.config/containers/systemd/stepca.container` (rootless)
* `/etc/containers/systemd/stepca.container`      (rootful)

```
[Unit]
Description=Smallstep Certificate Authority
After=network-online.target

[Container]
PodmanArgs=--memory 50m --cpus 0.25
PidsLimit=100
DropCapability=ALL
NoNewPrivileges=true
AutoUpdate=registry
ContainerName=stepca
Environment=TZ="UTC"
Environment="DOCKER_STEPCA_INIT_NAME=Example CA"
Environment=DOCKER_STEPCA_INIT_DNS_NAMES=ca.custom.domain,10.89.0.10,localhost,127.0.0.1
Environment=DOCKER_STEPCA_INIT_PROVISIONER_NAME=admin@custom.domain
Environment=DOCKER_STEPCA_INIT_SSH=true
Environment=DOCKER_STEPCA_INIT_ACME=true
Environment=DOCKER_STEPCA_INIT_PASSWORD_FILE=/run/secrets/stepca
HostName=stepca
Image=docker.io/smallstep/step-ca
PublishPort=10.89.0.10:9000:9000/tcp
PublishPort=127.0.0.1:9000:9000/tcp
Secret=source=stepca,type=mount,uid=1000,gid=1000,mode=400
Volume=/path/to/volumes/stepca/config:/home/step:Z
DNS=10.89.0.1
DNSOption=~custom.domain
ReloadSignal=SIGHUP
# Use systemd restart policy
HealthOnFailure=kill
HealthStartPeriod=90s
HealthStartupCmd=sleep 5
HealthCmd=step ca health
HealthInterval=30m
HealthRetries=3
HealthTimeout=20s

[Service]
Restart=always
# Extend Timeout for image pulls
TimeoutStartSec=900

[Install]
WantedBy=default.target
```
