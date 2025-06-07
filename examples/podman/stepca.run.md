## Example creation of a Podman container & secret

* Using a [cryptographically strong secret from `openssl` with an `8192` character `hex` string](https://docs.podman.io/en/latest/markdown/podman-secret-create.1.html#examples)

see also:

- [Create a "quadlet"](https://github.com/containers/podlet)
- [examples/podman/stepca.container.md](https://github.com/smallstep/certificates/tree/master/examples/podman/stepca.container.md)

```
iface=wt0 # running over Netbird VPN
ctr=stepca
ip=$(ip -f inet addr show $iface | sed -En -e 's/.*inet ([0-9.]+).*/\1/p')
repo=docker.io/smallstep/step-ca
# TPM supported image
# repo=docker.io/smallstep/step-ca:hsm
ca="My CA"
email="admin@custom.domain"
dns="ca.custom.domain,$ip,localhost,127.0.0.1"
volume="${HOME}/volumes/$ctr/config}"

###############
# auto config #
###############

bytes=8192
mkdir -p $volume
openssl rand -hex $bytes | podman secret create --replace $ctr -

podman run -d --replace \
    --name $ctr \
    --hostname $ctr \
    --secret source=$ctr,type=mount,uid=1000,gid=1000,mode=400 \
    --env "DOCKER_STEPCA_INIT_NAME=$ca" \
    --env "DOCKER_STEPCA_INIT_DNS_NAMES=$dns" \
    --env "DOCKER_STEPCA_INIT_PROVISIONER_NAME=$email" \
    --env "DOCKER_STEPCA_INIT_SSH=true" \
    --env "DOCKER_STEPCA_INIT_ACME=true" \
    --env "DOCKER_STEPCA_PASSWORD_FILE=/run/secrets/$ctr" \
    --cap-drop ALL \
    --restart always \
    --label "io.containers.autoupdate=registry" \
    -v $volume:/home/step:Z \
$repo
```

* Running the container with `--privileged` should only be needed to [configure a TPM](https://smallstep.com/blog/trusted-platform-modules-tpms/).
