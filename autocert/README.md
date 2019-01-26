![Autocert architecture diagram](https://raw.githubusercontent.com/smallstep/certificates/autocert/autocert/autocert-logo.png)

# Autocert
[![GitHub stars](https://img.shields.io/github/stars/smallstep/certificates.svg)](https://github.com/smallstep/certificates/stargazers)
[![GitHub release](https://img.shields.io/github/release/smallstep/certificates.svg)](https://github.com/smallstep/certificates/releases)
[![CA Image](https://images.microbadger.com/badges/image/smallstep/step-ca.svg)](https://microbadger.com/images/smallstep/step-ca)
[![Go Report Card](https://goreportcard.com/badge/github.com/smallstep/certificates)](https://goreportcard.com/report/github.com/smallstep/certificates)

<!--- [![Build Status](https://travis-ci.org/smallstep/certificates.svg?branch=master)](https://travis-ci.org/smallstep/certificates)
[![Coverage Status](https://coveralls.io/repos/github/smallstep/certificates/badge.svg?branch=master)](https://coveralls.io/github/smallstep/certificates?branch=master)
[![Autocert Image](https://images.microbadger.com/badges/image/smallstep/autocert-controller.svg)](https://microbadger.com/images/smallstep/autocert-controller)
[![Renewer Image](https://images.microbadger.com/badges/image/smallstep/autocert-renewer.svg)](https://microbadger.com/images/smallstep/autocert-renewer) -->

**Autocert** is a kubernetes add-on that automatically injects TLS/HTTPS certificates into your containers.

<!--- 👋 Welcome. We ❤️ feedback. Submit an issue. Fork and send a PR. Give us a ⭐ if you like what we're doing. --->

To get a certificate **simply annotate your pods** with a name. An X.509 (TLS/HTTPS) certificate is automatically created and mounted at `/var/run/autocert.step.sm/` along with a corresponding private key and root certificate (everything you need for [mTLS](#motivation)).

> *Note: this project is in **ALPHA**. DON'T use it for anything mission critical. EXPECT breaking changes in minor revisions with little or not warning. PLEASE provide feedback:*

TODO: Twitter, Slack, Issues (tagged with #autocert / special template)...

![Autocert demo gif](https://raw.githubusercontent.com/smallstep/certificates/autocert/autocert/demo.gif)

## Table of Contents

* [Features](#features)
* [Motivation](#motivation)
* [Getting Started](#getting-started)
  * [Prerequisites](#prerequisites)
  * [Installation](#install)
  * [Enabling autocert](#enable-autocert)
  * [Annotating pods](#annotate-pods)
* [Examples](#example)
  * [Mutual TLS](#mutual-tls)
  * [Getting a certificate locally](#local-certificate)
* [How it works](#how-it-works)
* [Uninstalling](#uninstalling)
* [Questions](#questions)

## Features

Autocert uses [`step certificates`](https://github.com/smallstep/certificates) to generate keys and issue certificates from your own **internal certificate authority**. This process is secure and automatic, all you have to do is [install autocert](#install) and [annotate your pods](#annotate-pods). Features include:

 * A complete **public key infrastructure** (PKI) for your kubernetes clusters
   * A fully featured internal **certificate authority** (CA) that you control so you can **use mTLS to control access to services**
   * Ability to run subnordinate to or federated with an existing PKI
   * CA and PKI artifacts are installed in their own namespace (`step`) for easy access control
 * Modern certificate best practices
   * Automated certificate management (auto enrollment and renewal)
   * Short-lived certificates
   * Private keys are never transmitted across the network (and aren't stored in `etcd`)
   * RFC5280 and CA/Browser Forum compliant certificates that work with browsers and other standard TLS implementations
 * Easily enable/disable per-namespace [using labels](#enable-autocert)
 * Builds on [`step certificates`](https://github.com/smallstep/certificates) so you can also issue certificates to servers, people, and code running in a different cluster and outside of kubernetes

## Motivation

TLS (e.g., HTTPS) is the most widely deployed cryptographic protocol in the world. Mutual TLS (mTLS) provides end-to-end security for service-to-service communication and can **replace complex VPNs** to secure communication into, out of, and between kubernetes clusters. But **to use mTLS to secure internal services you need certificates issued by your own certificate authority (CA)**.

Building and operating a CA, issuing certificates, and making sure they're renewed before they expire is tricky. Autocert does all of this for you.

## Getting Started

These instructions will get `autocert` installed quickly on an existing kubernetes cluster.

### Prerequisites

You'll need `kubectl` and a kubernetes cluster running version `1.9` or later with [webhook admission controllers](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#admission-webhooks) enabled:

```bash
$ kubectl version --short
Client Version: v1.13.1
Server Version: v1.10.11
$ kubectl api-versions | grep "admissionregistration.k8s.io/v1beta1"
admissionregistration.k8s.io/v1beta1
```

For [manual installation](INSTALL.md) you'll also need to [`install step`](https://github.com/smallstep/cli#installing) version `0.8.3` or later.

```bash
$ step version
Smallstep CLI/0.8.3 (darwin/amd64)
Release Date: 2019-01-16 01:46 UTC
```

### Install

To install `step certificates` and `autocert` in one step run:

```bash
$ kubectl run autocert-init -it --rm --image smallstep/autocert-init --restart Never
```

The init script will end by printing:

 * The admin provisioner password (also used to encrypt the CA's key material)
 * The `autocert` provisioner password (used by the mutating webhook)
 * Your CA's root certificate fingerprint (used to bootstrap secure communication)

Feel free to store these some place safe. The passwords are also stored as secrets in the `step` namespace.

> 🤔 **Tip:** If you lose your root certificate fingerprint you can calculate it again by running:
> 
> ```
> $ export CA_POD=$(kubectl -n step get pods -l app=ca \
>     -o jsonpath={$.items[0].metadata.name})
> $ kubectl -n step exec -it $CA_POD -- step certificate fingerprint /home/step/.step/certs/root_ca.crt
> ```

> 🤯 **Note:** You may need to adjust your RBAC policies to run `autocert-init`:
> 
> ```bash
> $ kubectl create clusterrolebinding autocert-init-binding \
>   --clusterrole cluster-admin \
>   --user "system:serviceaccount:default:default"
> ```
> 
> Once `autocert-init` is complete you can delete this binding:
> 
> ```bash
> $ kubectl delete clusterrolebinding autocert-init-binding
> ```

Feel free to [check out what the `autocert-init` container does](init/autocert.sh) if you're curious. You can also [install manually](INSTALL.md).

### Enable autocert

To enable `autocert` for a namespace it must be labelled `autocert.step.sm=enabled`. To label the `default` namespace run:

```bash
$ kubectl label namespace default autocert.step.sm=enabled
```

To check which namespaces have `autocert` enabled run:

```bash
$ kubectl get namespace -L autocert.step.sm
NAME          STATUS   AGE   AUTOCERT.STEP.SM
default       Active   59m   enabled
...
```

### Annotate pods

For `autocert` to inject a certificate pods must use the `autocert.step.sm/name` annotation to specify their name. The value of this annotation will appear as the name in the issued certificate (the X.509 common name and SAN).

```yaml
$ cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata: {name: sleep}
spec:
  replicas: 1
  selector: {matchLabels: {app: sleep}}
  template:
    metadata:
      annotations:
        # Autocert annotation
        autocert.step.sm/name: sleep.default.svc.cluster.local
      labels: {app: sleep}
    spec:
      containers:
      - name: sleep
        image: alpine
        command: ["/bin/sleep", "86400"]
EOF
```

Once the pod has started we can check that our certificate, private key, and root certificate have been properly mounted in our container at `/var/run/autocert.step.sm`.

```bash
$ export SLEEP_POD=$(kubectl get pods -l app=sleep \
    -o jsonpath={$.items[0].metadata.name})
$ kubectl exec -it $SLEEP_POD -c sleep -- ls /var/run/autocert.step.sm
root.crt  site.crt  site.key
```

> 🤔 **Tip:** The `autocert-renewer` sidecar also installs the [`step` CLI tool](https://github.com/smallstep/cli), which we can use to inspect the issued certificate.
> 
> ```bash
> $ kubectl exec -it $SLEEP_POD -c autocert-renewer -- step \
>     certificate inspect /var/run/autocert.step.sm/site.crt
> Certificate:
>     Data:
>         Version: 3 (0x2)
>         Serial Number: 38872628668914277126045555806003435350 (0x1d3e9890a42ae5861b8a6cb51aa29756)
>     Signature Algorithm: ECDSA-SHA256
>         Issuer: CN=Autocert Intermediate CA
>         Validity
>             Not Before: Jan 19 01:59:06 2019 UTC
>             Not After : Jan 20 01:59:06 2019 UTC
>         Subject: CN=sleep.default.svc.cluster.local
>         Subject Public Key Info:
>             Public Key Algorithm: ECDSA
>                 Public-Key: (256 bit)
>                 X:
>                     e9:f7:f6:04:c5:b5:af:c7:ff:95:19:69:09:74:57:
>                     31:a9:24:a7:31:d8:e4:f1:2a:0e:8c:89:fa:b5:aa:
>                     fa:d9
>                 Y:
>                     26:bc:6c:0f:ad:57:6e:75:ea:8e:d5:ca:bf:b0:c9:
>                     43:61:dc:42:8a:ef:42:79:17:b7:02:8a:07:2e:58:
>                     4c:50
>                 Curve: P-256
>         X509v3 extensions:
>             X509v3 Key Usage: critical
>                 Digital Signature, Key Encipherment
>             X509v3 Extended Key Usage:
>                 TLS Web Server Authentication, TLS Web Client Authentication
>             X509v3 Subject Key Identifier:
>                 BE:3E:92:68:7D:82:61:91:93:C2:E0:DF:77:1F:CD:EF:36:2D:8E:41
>             X509v3 Authority Key Identifier:
>                 keyid:69:BA:E5:9C:6D:66:39:B3:3E:8B:28:85:26:75:34:A6:91:07:F6:4E
>             X509v3 Subject Alternative Name:
>                 DNS:sleep.default.svc.cluster.local
>             X509v3 Step Provisioner:
>                 Type: JWK
>                 Name: autocert
>                 CredentialID: 7OOZUAEgixopdF_Yk7wMtkHv-op6p8FqSfEk3B6nry0
> 
>     Signature Algorithm: ECDSA-SHA256
>          30:45:02:20:6c:79:31:69:11:65:88:48:fc:a0:a0:f4:8e:bd:
>          81:62:83:6a:d7:66:fa:9c:d0:43:1e:15:69:3a:3c:e0:8e:2b:
>          02:21:00:c2:4a:51:85:25:4f:c1:68:de:07:50:53:8c:36:b3:
>          2c:a3:56:d1:1d:11:3d:aa:77:d1:2e:1e:54:75:1d:f3:0d
> ```

## Examples

With `autocert` issuing and rotating certificates we can start using mTLS between services. The [`examples/hello-mtls`](examples/hello-mtls) directory demonstrates the right way to do mTLS in several languages (contributions welcome :). Let's deploy one.

### Mutual TLS

Build and deploy the `hello-mtls` server for golang:

```bash
$ cd examples/hello-mtls/go
$ docker build -f Dockerfile.server -t hello-mtls-server-go .
$ kubectl apply -f hello-mtls.server.yaml
```

Build and deploy the `hello-mtls` client for golang:

```bash
$ docker build -f Dockerfile.client -t hello-mtls-client-go .
$ kubectl apply -f hello-mtls.client.yaml
```

Check that the client is connecting and working as expected:

```bash
$ export HELLO_MTLS=$(kubectl get pods -l app=hello-mtls-client \
    -o jsonpath={$.items[0].metadata.name})
$ kubectl logs $HELLO_MTLS -c hello-mtls-client -f
2019-01-25T01:36:57Z: Hello, hello-mtls-client.default.pod.cluster.local!
2019-01-25T01:37:02Z: Hello, hello-mtls-client.default.pod.cluster.local!
2019-01-25T01:37:07Z: Hello, hello-mtls-client.default.pod.cluster.local!
...
```

We can also `exec` into the `sleep` container we deployed earlier

```bash
$ kubectl exec -it $SLEEP_POD -c sleep -- sh
```

install `curl`, and hit `hello-mtls` from there:

```bash
sleep# apk add curl
sleep# curl --cacert /var/run/autocert.step.sm/root.crt \
            --cert /var/run/autocert.step.sm/site.crt \
            --key /var/run/autocert.step.sm/site.key \
            https://hello-mtls.default.svc.cluster.local
Hello, sleep.default.svc.cluster.local!
```

> 🤯 **A few ways things that can go sideways:**
>
> If we don't provide a client certificate for authentication the request will fail because we haven't authenticated ourselves to the server:
> 
> ```
> sleep# curl --cacert /var/run/autocert.step.sm/root.crt \
>             https://hello-mtls.default.svc.cluster.local
> curl: (35) error:1401E412:SSL routines:CONNECT_CR_FINISHED:sslv3 alert bad certificate
> ```
> 
> `curl` will also balk if we don't tell it to trust our `root.crt`, this time because it can't validate the server's certificate:
> 
> ```
> sleep# curl https://hello-mtls.default.svc.cluster.local
> curl: (60) SSL certificate problem: unable to get local issuer certificate
> More details here: https://curl.haxx.se/docs/sslcerts.html
> 
> curl failed to verify the legitimacy of the server and therefore could not
> establish a secure connection to it. To learn more about this situation and
> how to fix it, please visit the web page mentioned above.
> ```
> 
> You'll get similar errors from other tools, libraries, and applications if they're not properly configured to use the `autocert` certificates and keys. Minimally, for (non-mutual) TLS:
> 
>  * Clients must be configured to trust the `autocert` root certificate (`/var/run/autocert.step.sm/root.crt`) to authenticate a server
>  * Servers must be configured to use the key and certificate issued by `autocert` (`/var/run/autocert.step.sm/site.crt` and `/var/run/autocert.step.sm/site.key`) to authenticate *to* a client
>
> If you're doing mTLS the inverse is also true: the server must trust the root certificate to authenticate client, and the client must be configured to use the `autocert`-issued key and certificate. In other words, for mTLS both the client and server should be configured to use `autocert`'s `root.crt`, `site.crt`, and `site.key`. With `curl` this is done using the `--cacert`, `--cert`, and `--key` flags, respectively.

### Exposing services using mTLS

With properly configured mTLS, services can be safely exposed directly to the public internet: **only clients that have a certificate issued by the internal certificate authority will be allowed to connect**. To demonstrate let's expose our `hello-mtls` service.

If you need a refresher, here's a rough approximation of how an mTLS handshake works:

![mTLS handshake diagram](https://raw.githubusercontent.com/smallstep/certificates/autocert/autocert/mtls-handshake.png)

A few things to note:

 * It's the signing of random numbers that proves we're talking to the right remote. It's the digital equivalent of asking someone to send you a photo of them with today's newspaper.
 * The client and server need to have prior knowledge of the root certificate(s) used for signing other certificates.
 * The client and server need to be configured to use the correct certificate and private key (the certificate must have been issued by a CA with a trusted root certificate)

#### Exposing `hello-mtls`

Because `hello-mtls` does proper mTLS itself we can expose it simply using a [service with type LoadBalancer](https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer).

```
$ kubectl expose deployment hello-mtls --name=hello-mtls-lb --port=443 --target-port=443 --type=LoadBalancer
service/loadbalancer exposed
$ kubectl get svc hello-mtls-lb
NAME            TYPE           CLUSTER-IP    EXTERNAL-IP       PORT(S)   AGE
hello-mtls-lb   LoadBalancer   10.0.65.118   104.198.149.140   443/TCP    5m
```

#### Obtaining a certificate locally

To connect to `hello-mtls` from outside kubernetes we need a certificate issued by our internal CA. Since `autocert` is built on `step certificates` we can securely issue certificates to users, devices, and workloads running in other environments.

> 🤯 **Note:** To follow along you'll need `step` [installed locally](https://github.com/smallstep/cli#installing).

First, port-forward from localhost to the `step-ca` pod:

```
$ export CA_POD=$(kubectl -n step get pods -l app=ca \
    -o jsonpath={$.items[0].metadata.name})
$ kubectl -n step port-forward $CA_POD 4443:4443
```

Now we can use `step` to securely grab the CA's root certificate and obtain a certificate. You'll be prompted to select a provisioner and enter the correct password to continue:

```bash
# Get root certificate fingerprint
$ export FINGERPRINT="$(kubectl -n step exec -it $CA_POD -- \
    step certificate fingerprint /home/step/.step/certs/root_ca.crt | tr -d '[:space:]')"

# Fetch and verify root certificate
$ step ca root root.crt \
    --ca-url https://127.0.0.1:4443 \
    --fingerprint $FINGERPRINT

# Get a certificate locally
$ step ca certificate snarf.local.dev snarf.crt snarf.key \
    --ca-url https://127.0.0.1:4443 \
    --root root.crt
✔ Key ID: H4vH5VfvaMro0yrk-UIkkeCoPFqEfjF6vg0GHFdhVyM (admin)
✔ Please enter the password to decrypt the provisioner key: 0QOC9xcq56R1aEyLHPzBqN18Z3WfGZ01
✔ CA: https://127.0.0.1:4443/1.0/sign
✔ Certificate: snarf.crt
✔ Private Key: snarf.key
$ step ca certificate snarf.local.dev snarf.crt snarf.key
```

We can inspect our newly minted certificate and verify that it's been issued by `autocert` and includes the right common name:

```
$ step certificate inspect --format json snarf.crt | jq '{issuer,subject}'
{
  "issuer": {
    "common_name": [
      "Autocert Intermediate CA"
    ]
  },
  "subject": {
    "common_name": [
      "snarf.local.dev"
    ]
  }
}
```

> 🤔 **Tip:** If you want someone (or something) to have a certificate with a particular name, but don't want to give them the ability to provision arbitrary certificates, you can generate a bootstrap token for them:
> 
> ```bash
> $ step ca token snarf.local.dev \
>     --ca-url https://127.0.0.1:4443 \
>     --root root.crt
> eyJhbG...
> ```
> 
> They can use the token to obtain a certificate (once):
> 
> ```bash
> $ step ca certificate snarf.local.dev snarf.crt snarf.key --token "eyJhbG..."
> ```
>
> Actually, this is exactly what the `autocert` mutating webhook is doing for your pods! Read [how it works](#how-it-works) for more info.

#### Connecting to `hello-mtls`

We're ready to securely connect to `hello-mtls`.

```
$ export HELLO_MTLS_IP=$(kubectl get svc hello-mtls-lb -ojsonpath={$.status.loadBalancer.ingress...?})
$ export HELLO_MTLS_IP="127.0.0.1"
$ curl --resolve hello-mtls.default.svc.cluster.local:443:$HELLO_MTLS_IP \
       --cacert root.crt \
       --cert snarf.crt \
       --key snarf.key \
       https://hello-mtls.default.svc.cluster.local
Hello, snarf.local.dev!
```

🎉

> 🤯 **Note:**  HTTPS clients check that the name in the server's cerificate match the `authority` portion of the URL (e.g., `https://smallstep.com/` must present a certificate with the name `smallstep.com`). (See [RFC2818](https://tools.ietf.org/html/rfc2818#section-3).)
> 
> Our `hello-mtls` service's certificate binds the name `hello-mtls.default.svc.cluster.local` so we *must* connect to it using that name. If we use a different authority we'll get an error:
> 
> ```
> $ curl --cacert root.crt \
>        --cert snarf.crt \
>        --key snarf.key \
>        https://127.0.0.1
> curl: (51) SSL: no alternative certificate subject name matches target host name '127.0.0.1'
> ```
> 
> In a real production environment you'd address this by either:
> 
>  * using a properly registered domain name and configuring DNS either globally (e.g., using [ExternalDNS](https://github.com/kubernetes-incubator/external-dns/)), or
>  * using internal names and configuring DNS locally in each environment (e.g., using an [ExternalName service](https://kubernetes.io/docs/concepts/services-networking/service/#externalname))
> 
> In any case, `hello-mtls.default.svc.cluster.local` must resolve to the right IP.
> 
> You could use `/etc/hosts`. Since we're testing with `curl` it's even easier to use the `--resolve` flag to override resolution for a single request.

## How it works

### Architecture

`Autocert` consists of a [webhook admission controllers](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#admission-webhooks) that injects one init container and one sidecar container to handle obtaining a certificate for the first time and renewing a certificate, respectively.

The `autocert` admission webhook will intercept this pod creation request and inject an [init container](bootstrapper/) and [sidecar](renewer/) to manage certificate issuance and renewal, respectively.

![Autocert architecture diagram](https://raw.githubusercontent.com/smallstep/certificates/autocert/autocert/autocert-arch.png)

### Enrollment & renewal

It integrates with [`step certificates`](https://github.com/smallstep/certificates) and uses the single-use token bootstrap protocol from that project to mutually authenticate a new pod with your certificate authority.

![Autocert bootstrap protocol diagram](https://raw.githubusercontent.com/smallstep/certificates/autocert/autocert/autocert-bootstrap.png)

### Further reading

* Link to ExternalDNS example
* Link to multiple cluster with Service type ExternalDNS so they can communicate

### Uninstall

* Delete the `sleep` deployment (if you created it)
* Remove labels (show how to find labelled namespaces)
* Remove annotations (show how to find any annotated pods)
* Remove secrets (show how to find labelled secrets)
* Delete `step` namespace

### Questions

#### How is this different than [`cert-manager`](https://github.com/jetstack/cert-manager)

#### Doesn't kubernetes already ship with a certificate authority?

Yes, but it's designed for use by the kubernetes control plane rather than by your data plane services. You could use the kubernetes CA to issue certificates for data plane communication, but it's probably not a good idea.

#### Why not use kubernetes CSR resources for this?

It's harder and less secure.

#### Why not use kubernetes service accounts instead of bootstrap tokens?

#### Why does the mutating webhook have to create secrets / need cluster role bindings?

#### Why do I have to tell you the name to put in a certificate? Why can't you automatically bind service names?

#### What are `autocert` certificates good for?

Autocert certificates let you secure your data plane (service-to-service) communication using mutual TLS (mTLS). Services and proxies can limit access to clients that also have a certificate issued by your certificate authority (CA). Servers can identify which client is connecting improving visibility and enabling granular access control.

Once certificates are issued you can use mTLS to secure communication in to, out of, and between kubernetes clusters. Services can use mTLS to only allow connections from clients that have their own certificate issued from your CA.

It's like your own Let's Encrypt, but you control who gets a certificate.

#### How is this different than a service mesh?

Certificate management is a necessary building block for any service mesh that uses mutual TLS for authenticated encryption (e.g., istio, linkerd, consul connect). Typically, service mesh systems will provide their own certificate management solution. However, these systems 

#### What about DaemonSets, ReplicaSets, StatefulSets, and all the other things that might need certificates?

...?

## Building

...

## Contributing

...

## License

Copyright 2019 Smallstep Labs

Licensed under [the Apache License, Version 2.0](https://github.com/smallstep/certificates/blob/master/LICENSE)
