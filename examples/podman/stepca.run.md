## Example creation of a Podman container & secret

* Using a [cryptographically strong secret of 378,000 characters](https://docs.podman.io/en/latest/markdown/podman-secret-create.1.html#examples)

see also:

- [Create a "quadlet"](https://github.com/containers/podlet)
- [Netbird VPN](https://github.com/netbirdio/netbird)
- [examples/podman/stepca.container.md](https://github.com/smallstep/certificates/tree/master/examples/podman/stepca.container.md)

```
iface=wt0 # running over netbird
ctr=stepca
ip=$(ip -f inet addr show $iface | sed -En -e 's/.*inet ([0-9.]+).*/\1/p')
repo=docker.io/smallstep/step-ca
# TPM supported image
# repo=docker.io/smallstep/step-ca:hsm
dns="ca.custom.domain,$ip,localhost,127.0.0.1"
email="admin@custom.domain"
ca="My CA"

####################
# auto config      #
####################

bytes=378000
openssl rand -base64 $bytes | podman secret create --replace $ctr -

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
    --privileged \
    --label "io.containers.autoupdate=registry" \
    -v ${HOME}/volumes/$ctr/config:/home/step:Z \
$repo
```

* Contributed by: [Stuart Cardall](https://github.com/itoffshore)
