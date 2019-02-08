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

<!--- TODO: 👋 Welcome. We ❤️ feedback. Submit an issue. Fork and send a PR. Give us a ⭐ if you like what we're doing. --->

**Autocert** is a kubernetes add-on that automatically injects TLS/HTTPS certificates into your containers.

To get a certificate **simply annotate your pods** with a name. An X.509 (TLS/HTTPS) certificate is automatically created and mounted at `/var/run/autocert.step.sm/` along with a corresponding private key and root certificate (everything you need for [mTLS](#motivation)).

> *Note: this project is in **ALPHA**. DON'T use it for anything mission critical. EXPECT breaking changes in minor revisions with little or not warning. PLEASE provide feedback:*

TODO: Twitter, Slack, Issues (tagged with #autocert / special template)...

![Autocert demo gif](https://raw.githubusercontent.com/smallstep/certificates/autocert/autocert/demo.gif)

## Motivation

`Autocert` exists to **make it easy to use mTLS** (mutual TLS) to **improve security** within a cluster and to **secure communication into, out of, and between kubernetes clusters**. The goal is to make right and proper public key infrastructure (PKI) more accessible to people running kubernetes.

TLS (and HTTPS, which is HTTP over TLS) provides _authenticated encryption_: an _identity dialtone_ and _end-to-end encryption_ for your workloads. It's like a secure line with caller ID. This has all sorts of benefits: better security, compliance, and easier auditability for starters. It makes workloads identity-aware, improving observability and enabling granular access control. Perhaps most compelling, [mutual TLS](#) (mTLS) lets you securely communicate with workloads running anywhere, not just inside kubernetes.

TODO: Diagram

If you know how to operate and scale DNS and proxy infrastructure then you already know how to scale and operate secure service-to-service communication using mTLS (mutual TLS). There's just one problem: **you need certificates issued by your own certificate authority (CA)**. Building and operating a CA, issuing certificates, and making sure they're renewed before they expire is tricky. `Autocert` does all of this for you.

Because `autocert` is built on [`step certificates`](#) you can easily extend access to developers, endpoints, and workloads running outside your cluster.

## Features

First and foremost, `autocert` is easy. You can **get started in minutes**.

`Autocert` uses [`step certificates`](https://github.com/smallstep/certificates) to generate keys and issue certificates. This process is secure and automatic, all you have to do is [install autocert](#install) and [annotate your pods](#annotate-pods).

Features include:

 * A fully featured private **certificate authority** (CA) for workloads running on kubernetes and elsewhere
 * [RFC5280](#) and [CA/Browser Forum](#) compliant certificates that work **for TLS**
 * Namespaced installation into the `step` namespace so it's **easy to lock down** your CA
 * Short-lived certificates with **fully automated** enrollment and renewal
 * Private keys are never transmitted across the network and aren't stored in `etcd`

## Getting Started

### Prerequisites

All you need to get started is [`kubectl`](https://kubernetes.io/docs/tasks/tools/install-kubectl/#install-kubectl) and a cluster running kubernetes `1.9` or later with [admission webhooks](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#admission-webhooks) enabled:

```bash
$ kubectl version --short
Client Version: v1.13.1
Server Version: v1.10.11
$ kubectl api-versions | grep "admissionregistration.k8s.io/v1beta1"
admissionregistration.k8s.io/v1beta1
```

### Install

To install `autocert` run:

```bash
kubectl run autocert-init -it --rm --image smallstep/autocert-init --restart Never
```

💥 installation complete.

> You might want to [check out what this command does](init/autocert.sh) before running it. You can also [install `autocert` manually](INSTALL.md) if that's your style.

## Usage

### Enable autocert (per namespace)

To enable `autocert` for a namespace it must be labelled `autocert.step.sm=enabled`.

To label the `default` namespace run:

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

### Annotate pods to get certificates

To tell `autocert` to issue certificates to a pod's containers you need to [specify a name](RUNBOOK.md#naming-considerations) using the `autocert.step.sm/name` annotation. This name will appear in the issued certificate (as the X.509 common name and SAN).

To test your installation apply this annotated deployment, which starts a [simple server](examples/hello-mtls/go/server.go) that uses mTLS:

```yaml
cat <<EOF | kubectl apply -f - 
apiVersion: apps/v1
kind: Deployment
metadata: {name: hello-mtls, labels: {app: hello-mtls}}
spec:
  replicas: 1
  selector: {matchLabels: {app: hello-mtls}}
  template:
    metadata:
      annotations:
        # AUTOCERT ANNOTATION HERE -v
        autocert.step.sm/name: hello-mtls.default.svc.cluster.local
        # AUTOCERT ANNOTATION HERE -^
      labels: {app: hello-mtls}
    spec:
      containers:
      - name: hello-mtls
        image: smallstep/hello-mtls-server-go:latest
EOF
```

Our new container should have a certificate, private key, and root certificate mounted at `/var/run/autocert.step.sm`:

```bash
$ export HELLO_MTLS=$(kubectl get pods -l app=hello-mtls -o jsonpath={$.items[0].metadata.name})
$ kubectl exec -it $HELLO_MTLS -c hello-mtls -- ls /var/run/autocert.step.sm
root.crt  site.crt  site.key
$ kubectl exec -it $HELLO_MTLS -c autocert-renewer -- step certificate inspect /var/run/autocert.step.sm/site.crt | grep "Subject: CN" | awk -F= '{print $2}'
hello-mts.default.svc.cluster.local
```

We're done. Our container has a certificate, issued by our CA, and `autocert` will take care of renewal automatically.

✅ Certificates.

## Hello mTLS

It's easy to deploy certificates automatically with `autocert`, but it's up to you to use them correctly. To get you started, [`hello-mtls`](examples/hello-mtls) demonstrates the right way to use mTLS with various tools and languages (contributions welcome :). If you're a bit fuzzy on how mTLS works, [the `hello-mtls` README](examples/hello-mtls) is a great place to start.

To finish out this tutorial let's keep things simple and try `curl`ing the server we just deployed from inside and outside the cluster.

### Connecting from inside the cluster

First, let's expose our workload to the rest of the cluster using a service:

```
kubectl expose deployment hello-mtls --port 443
```

Now we can `curl` our server from another container using a certificate issued by `autocert`:

```yaml
$ cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata: {name: hello-mtls-client, labels: {app: hello-mtls-client}}
spec:
  replicas: 1
  selector: {matchLabels: {app: hello-mtls-client}}
  template:
    metadata:
      annotations:
        # AUTOCERT ANNOTATION HERE -v
        autocert.step.sm/name: hello-mtls-client.default.pod.cluster.local
        # AUTOCERT ANNOTATION HERE -^
      labels: {app: hello-mtls-client}
    spec:
      containers:
      - name: hello-mtls-client
        image: smallstep/hello-mtls-client-curl:latest
        env: [{name: HELLO_MTLS_URL, value: https://hello-mtls.default.svc.cluster.local}]
EOF
```

Once deployed the client logs should indicate that it's successfully connecting to our server using mTLS, which is [echoing the client's name](examples/hello-mtls/go/server.go#L71-L72) in response.

```
$ export HELLO_MTLS_CLIENT=$(kubectl get pods -l app=hello-mtls-client -o jsonpath={$.items[0].metadata.name})
$ kubectl logs $HELLO_MTLS_CLIENT -c hello-mtls-client
Thu Feb  7 23:35:23 UTC 2019: Hello, hello-mtls-client.default.pod.cluster.local!
Thu Feb  7 23:35:28 UTC 2019: Hello, hello-mtls-client.default.pod.cluster.local!
```

For kicks, let's `exec` into this pod and try `curl`ing ourselves:

```
$ kubectl exec $HELLO_MTLS_CLIENT -c hello-mtls-client -- curl -sS \
       --cacert /var/run/autocert.step.sm/root.crt \
       --cert /var/run/autocert.step.sm/site.crt \
       --key /var/run/autocert.step.sm/site.key \
       https://hello-mtls.default.svc.cluster.local
Hello, hello-mtls-client.default.pod.cluster.local!
```

✅ mTLS inside cluster.

### Connecting from outside the cluster

Connecting from outside the cluster is a bit more complicated. We need to handle DNS and obtain a certificate ourselves (tasks which were handled automatically inside the cluster by kubernetes and `autocert`, respectively).

That said, since we're using mTLS our server can be safely exposed directly to the public internet using a [LoadBalancer service type](https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer): **only clients that have a certificate issued by our certificate authority will be allowed to connect**.


```
kubectl expose deployment hello-mtls --name=hello-mtls-lb --port=443 --type=LoadBalancer
```

To connect we need a certificate, which we'll need to obtain from the CA. There are a [couple](RUNBOOK.md#federation) [ways](RUNBOOK.md#exposing-the-ca) to do this, but for simplicity we'll just forward a port.

To follow along you'll need to [`install step`](https://github.com/smallstep/cli#installing).

```
$ export CA_POD=$(kubectl -n step get pods -l app=ca -o jsonpath={$.items[0].metadata.name})
$ kubectl -n step port-forward $CA_POD 4443:4443
```

In another window we can use `step` to grab the root certificate, generate a key pair, and get a certificate to use with `curl`. You'll need the admin password and CA fingerprint output during installation (see [here](RUNBOOK.md#recovering-fingerprint) and [here](#RUNBOOK.md#recovering-admin-password) if you already lost them :).

```bash
$ export CA_POD=$(kubectl -n step get pods -l app=ca -o jsonpath={$.items[0].metadata.name})
$ step ca root root.crt \
    --ca-url https://127.0.0.1:4443 \
    --fingerprint <fingerprint>
$ step ca certificate snarf.local.dev snarf.crt snarf.key \
    --ca-url https://127.0.0.1:4443 \
    --root root.crt
✔ Key ID: H4vH5VfvaMro0yrk-UIkkeCoPFqEfjF6vg0GHFdhVyM (admin)
✔ Please enter the password to decrypt the provisioner key: 0QOC9xcq56R1aEyLHPzBqN18Z3WfGZ01
✔ CA: https://127.0.0.1:4443/1.0/sign
✔ Certificate: snarf.crt
✔ Private Key: snarf.key
```

Now we can simply `curl` the service:

```
$ export HELLO_MTLS_IP=$(kubectl get svc hello-mtls-lb -ojsonpath={$.status.loadBalancer.ingress[0].ip})
$ curl --resolve hello-mtls.default.svc.cluster.local:443:$HELLO_MTLS_IP \
       --cacert root.crt \
       --cert snarf.crt \
       --key snarf.key \
       https://hello-mtls.default.svc.cluster.local
Hello, snarf.local.dev!
```

> If you're using minikube or docker for mac the load balancer's "IP" might be `localhost`, which won't work. In that case, simply `export HELLO_MTLS_IP=127.0.0.1` and try again.

> Note that we're using the `--resolve` flag to tell `curl` to resolve the name in our workload's certificate to its public IP address. In a real production infrastructure you could configure DNS manually, or you could propagate DNS to workloads outside kubernetes using something like [ExternalDNS](#).

✅ mTLS outside cluster.

### Cleanup & uninstall

To clean up after running through the tutorial remove the `hello-mtls` and `hello-mtls-client` deployments and services:

```
kubectl delete deployment hello-mtls
kubectl delete deployment hello-mtls-client
kubectl delete service hello-mtls
kubectl delete service hello-mtls-lb
```

The runbook contains instructions for [uninstalling `autocert` complete](RUNBOOK.md#uninstalling).

<!--- TODO: CTA or Further Reading... Move "How it works" maybe? Or put this below that? --->

## How it works

### Architecture

`Autocert` is an [admission webhook](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#admission-webhooks) that intercepts and patches pod creation requests with [some YAML](install/02-autocert.yaml#L26-L44) to inject an [init container](bootstrapper/) and [sidecar](renewer/) that handle obtaining and renewing certificates, respectively.

![Autocert architecture diagram](https://raw.githubusercontent.com/smallstep/certificates/autocert/autocert/autocert-arch.png)

### Enrollment & renewal

It integrates with [`step certificates`](https://github.com/smallstep/certificates) and uses the [one-time token bootstrap protocol](https://smallstep.com/blog/...) from that project to mutually authenticate a new pod with your certificate authority, and obtain a certificate.

![Autocert bootstrap protocol diagram](https://raw.githubusercontent.com/smallstep/certificates/autocert/autocert/autocert-bootstrap.png)

Tokens are [generated by the admission webhook](controller/provisioner.go#L46-L72) and [transmitted to the injected init container via a kubernetes secret](controller/main.go#L91-L125). The init container [uses the one-time token](bootstrapper/bootstrapper.sh) to obtain a certificate. A sidecar is also installed to [renew certificates](renewer/Dockerfile#L8) before they expire. Renewal simply uses mTLS with the CA.

## Questions

#### How is this different than [`cert-manager`](https://github.com/jetstack/cert-manager)

`Cert-manager` is a great project. However, it's designed primarily for managing certificates issued by [Let's Encrypt's](https://letsencrypt.org/) public certificate authority. These certificates are useful for TLS ingress from web browsers. `Autocert` is different. It's purpose-built to manage certificates issued by your own private CA to support the use of mTLS for internal communication (e.g., service-to-service).

#### Doesn't kubernetes already ship with a certificate authority?

Yes, actually it can have [a bunch of them](https://jvns.ca/blog/2017/08/05/how-kubernetes-certificates-work/) for different sorts of control plane communication.

Wait, no, _actually_
it doesn't _ship_ with _any_ CA. It's complicated. Kubernetes doesn't come with a CA, it has integration points that allow you to use any CA (e.g., [Kubernetes the hard way](https://github.com/kelseyhightower/kubernetes-the-hard-way) [uses CFSSL](https://github.com/kelseyhightower/kubernetes-the-hard-way/blob/2983b28f13b294c6422a5600bb6f14142f5e7a26/docs/02-certificate-authority.md). You could use [`step certificates`](https://github.com/smallstep/certificates), which `autocert` is based on, instead.

In any case, none of these CAs are meant for issuing certificates to your workloads for service-to-service communication. Rather, they're meant to secure communication between various control plane components. You could use them for your data plane, but it's probably not a good idea.

#### What permissions does `autocert` require in my cluster and why?

By default we ask for the narrowest permissions we can: the ability to create and delete secrets cluster-wide. You can [check out our RBAC config here](install/03-rbac.yaml).

We need these permissions in order to transmit one-time tokens to workloads using secrets, and to clean up afterwards. We'd love to scope these permissions down further if anyone has any ideas.

#### Why does the mutating webhook have to create secrets?

The `autocert` admission webhook needs to securely transmit one-time bootstrap tokens to containers. This could be accomplished without using secrets by simply patching a token directly into the pod's environment via the admission webhook response. Unfortunately, the kubernetes API server does not authenticate itself to admission webhooks by default, and configuring it to do so [requires passing a custom config file](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#authenticate-apiservers) at apiserver startup. This isn't an option for everyone (e.g., on GKE) so we opted not to rely on it.

Since our webhook can't tell who is calling it, including bootstrap tokens in patch responses would be dangerous. By using secrets an attacker can still trick us into generating superflous bootstrap tokens, but they'd also need read access to cluster secrets to do anything with them.

Hopefully this story will improve with time.

#### Why not use kubernetes service accounts instead of bootstrap tokens?

Great idea! This should be pretty easy to add. However, existing service accounts are [somewhat broken](https://github.com/kubernetes/community/pull/1460) for this use case. The upcoming [TokenRequest API](https://github.com/kubernetes/kubernetes/issues/58790) should fix most of these issues.

TODO: Link to issue for people who want this.

#### Too. many. containers. Why do you need to install an init container and sidecar?

We don't. Your containers can generate key pairs, exchange them for certificates, and manage renewals themselves. This is pretty easy if you [install `step`](https://github.com/smallstep/cli#installing) in your containers, or integrate with our [golang SDK](https://godoc.org/github.com/smallstep/certificates/ca). To support this we'd need to add the option to  inject a bootstrap token without injecting these containers.

TODO: Link to issue for people who want this.

That said, the init container and sidecar are both super lightweight.

#### Why are keys and certificates managed via volume mounts? Why not use a secret or some custom resource?

Because, by default, kubernetes secrets are stored in plaintext in `etcd` and might even be transmitted unencrypted across the network. Even if secrets were properly encrypted, transmitting a private key across the network violates PKI best practices. Key pairs should always be generated where they're used, and private keys should never be shared with anyone but their owners.

That said, there are use cases where a certificate mounted in a secret resource is desirable (e.g., for use with a kubernetes `Ingress`). We may add support for this in the future. However, we think the current method is easier and better.

TODO: Link to issue for people who want this.

#### Why not use kubernetes CSR resources for this?

It's harder and less secure. If any good and simple design exists for securely automating CSR approval using this resource we'd love to see it!

#### Why do I have to tell you the name to put in a certificate? Why can't you automatically bind service names?

Mostly because monitoring the API server to figure out which services are associated with which workloads is complicated and somewhat magical. And it might not be what you want.

That said, we're not totally opposed to this idea if anyone has strong feels and a good design.

#### What sorts of keys are issued and how often are certificates rotated?

`Autocert` builds on `step certificates` which issues ECDSA certificates using the P256 curve with ECDSA-SHA256 signatures by default. If this is all Greek to you, rest assured these are safe, sane, and modern defaults that are suitable for the vast majority of environments.

#### What crypto library is under the hood?

https://golang.org/pkg/crypto/

## Building

TODO

## Contributing

TODO

## License

Copyright 2019 Smallstep Labs

Licensed under [the Apache License, Version 2.0](https://github.com/smallstep/certificates/blob/master/LICENSE)
