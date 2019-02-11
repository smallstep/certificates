![Autocert architecture diagram](https://raw.githubusercontent.com/smallstep/certificates/autocert/autocert/autocert-logo.png)

# Autocert
[![GitHub release](https://img.shields.io/github/release/smallstep/certificates.svg)](https://github.com/smallstep/certificates/releases)
[![CA Image](https://images.microbadger.com/badges/image/smallstep/step-ca.svg)](https://microbadger.com/images/smallstep/step-ca)
[![Go Report Card](https://goreportcard.com/badge/github.com/smallstep/certificates)](https://goreportcard.com/report/github.com/smallstep/certificates)

[![GitHub stars](https://img.shields.io/github/stars/smallstep/certificates.svg?style=social)](https://github.com/smallstep/certificates/stargazers)
[![Twitter followers](https://img.shields.io/twitter/follow/smallsteplabs.svg?label=Follow&style=social)](https://twitter.com/intent/follow?screen_name=smallsteplabs)

<!--- [![Build Status](https://travis-ci.org/smallstep/certificates.svg?branch=master)](https://travis-ci.org/smallstep/certificates)
[![Coverage Status](https://coveralls.io/repos/github/smallstep/certificates/badge.svg?branch=master)](https://coveralls.io/github/smallstep/certificates?branch=master)
[![Autocert Image](https://images.microbadger.com/badges/image/smallstep/autocert-controller.svg)](https://microbadger.com/images/smallstep/autocert-controller)
[![Renewer Image](https://images.microbadger.com/badges/image/smallstep/autocert-renewer.svg)](https://microbadger.com/images/smallstep/autocert-renewer) -->

**Autocert** is a kubernetes add-on that automatically injects TLS/HTTPS certificates into your containers.

To get a certificate **simply annotate your pods** with a name. An X.509 (TLS/HTTPS) certificate is automatically created and mounted at `/var/run/autocert.step.sm/` along with a corresponding private key and root certificate (everything you need for [mTLS](#motivation)).

We ❤️ feedback. [Submit an issue](#TODO). [Fork](https://github.com/smallstep/certificates/fork) and send a PR. [Give us a ⭐](https://github.com/smallstep/certificates/stargazers) if you like what we're doing.

![Autocert demo gif](https://raw.githubusercontent.com/smallstep/certificates/autocert/autocert/demo.gif)

## Motivation

`Autocert` exists to **make it easy to use mTLS** ([mutual TLS](#)) to **improve security** within a cluster and to **secure communication into, out of, and between kubernetes clusters**.

TLS (and HTTPS, which is HTTP over TLS) provides _authenticated encryption_: an _identity dialtone_ and _end-to-end encryption_ for your workloads. It's like a secure line with caller ID. This has all sorts of benefits: better security, compliance, and easier auditability for starters. It **makes workloads identity-aware**, improving observability and enabling granular access control. Perhaps most compelling, mTLS lets you securely communicate with workloads running anywhere, not just inside kubernetes.

![Connect with mTLS diagram](https://raw.githubusercontent.com/smallstep/certificates/autocert/autocert/connect-with-mtls.png)

Unlike VPNs & SDNs, deploying and scaling mTLS is pretty easy. You're (hopefully) already using TLS, and your existing tools and standard libraries will provide most of what you need. If you know how to operate DNS and reverse proxies, you know how to operate mTLS infrastructure.

There's just one problem: **you need certificates issued by your own certificate authority (CA)**. Building and operating a CA, issuing certificates, and making sure they're renewed before they expire is tricky. `Autocert` does all of this for you.

## Features

First and foremost, `autocert` is easy. You can **get started in minutes**.

`Autocert` uses [`step certificates`](https://github.com/smallstep/certificates) to generate keys and issue certificates. This process is secure and automatic, all you have to do is [install autocert](#install) and [annotate your pods](#enable-autocert-per-namespace).

Features include:

 * A fully featured private **certificate authority** (CA) for workloads running on kubernetes and elsewhere
 * [RFC5280](https://tools.ietf.org/html/rfc5280) and [CA/Browser Forum](https://cabforum.org/baseline-requirements-documents/) compliant certificates that work **for TLS**
 * Namespaced installation into the `step` namespace so it's **easy to lock down** your CA
 * Short-lived certificates with **fully automated** enrollment and renewal
 * Private keys are never transmitted across the network and aren't stored in `etcd`

 Because `autocert` is built on [`step certificates`](https://github.com/smallstep/certificates) you can easily [extend access](#connecting-from-outside-the-cluster) to developers, endpoints, and workloads running outside your cluster, too.

## Getting Started

> ⚠️ Warning: *this project is in **ALPHA**. DON'T use it for anything mission critical. EXPECT breaking changes in minor revisions with little or not warning. PLEASE provide feedback:*

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

Using `autocert` is also easy:

 * Enable `autocert` for a namespace by labelling it with `autocert.step.sm=enabled`, then
 * Inject certificates into containers by annotating pods with `autocert.step.sm/name: <name>`

### Enable autocert (per namespace)

To enable `autocert` for a namespace it must be labelled `autocert.step.sm=enabled`.

To label the `default` namespace run:

```bash
kubectl label namespace default autocert.step.sm=enabled
```

To check which namespaces have `autocert` enabled run:

```bash
$ kubectl get namespace -L autocert.step.sm
NAME          STATUS   AGE   AUTOCERT.STEP.SM
default       Active   59m   enabled
...
```

### Annotate pods to get certificates

To get a certificate you need to tell `autocert` your workload's name using the `autocert.step.sm/name` annotation (this name will appear as the X.509 common name and SAN).

Let's deploy a [simple mTLS server](examples/hello-mtls/go/server.go) named  `hello-mtls.default.svc.cluster.local`:

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
        # AUTOCERT ANNOTATION HERE -v ###############################
        autocert.step.sm/name: hello-mtls.default.svc.cluster.local #
        # AUTOCERT ANNOTATION HERE -^ ###############################
      labels: {app: hello-mtls}
    spec:
      containers:
      - name: hello-mtls
        image: smallstep/hello-mtls-server-go:latest
EOF
```

In our new container we should find a certificate, private key, and root certificate mounted at `/var/run/autocert.step.sm`:

```bash
$ export HELLO_MTLS=$(kubectl get pods -l app=hello-mtls -o jsonpath={$.items[0].metadata.name})
$ kubectl exec -it $HELLO_MTLS -c hello-mtls -- ls /var/run/autocert.step.sm
root.crt  site.crt  site.key
```

We're done. Our container has a certificate, issued by our CA, which `autocert` will automatically renew.

✅ Certificates.

## Hello mTLS

It's easy to deploy certificates using `autocert`, but it's up to you to use them correctly. To get you started, [`hello-mtls`](examples/hello-mtls) demonstrates the right way to use mTLS with various tools and languages (contributions welcome :). If you're a bit fuzzy on how mTLS works, [the `hello-mtls` README](examples/hello-mtls) is a great place to start.

To finish out this tutorial let's keep things simple and try `curl`ing the server we just deployed from inside and outside the cluster.

### Connecting from inside the cluster

First, let's expose our workload to the rest of the cluster using a service:

```
kubectl expose deployment hello-mtls --port 443
```

Now let's deploy a client, with its own certificate, that [`curl`s our server in a loop](examples/hello-mtls/curl/client.sh):

```yaml
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata: {name: hello-mtls-client, labels: {app: hello-mtls-client}}
spec:
  replicas: 1
  selector: {matchLabels: {app: hello-mtls-client}}
  template:
    metadata:
      annotations:
        # AUTOCERT ANNOTATION HERE -v ######################################
        autocert.step.sm/name: hello-mtls-client.default.pod.cluster.local #
        # AUTOCERT ANNOTATION HERE -^ ######################################
      labels: {app: hello-mtls-client}
    spec:
      containers:
      - name: hello-mtls-client
        image: smallstep/hello-mtls-client-curl:latest
        env: [{name: HELLO_MTLS_URL, value: https://hello-mtls.default.svc.cluster.local}]
EOF
```

> Note that **the authority portion of the URL** (the `HELLO_MTLS_URL` env var) **matches the name of the server we're connecting to** (both are `hello-mtls.default.svc.cluster.local`). That's required for standard HTTPS and can sometimes require some DNS trickery.

Once deployed we should start seeing the client log responses from the server [saying hello](examples/hello-mtls/go/server.go#L71-L72):

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

Connecting from outside the cluster is a bit more complicated. We need to handle DNS and obtain a certificate ourselves. These tasks were handled automatically inside the cluster by kubernetes and `autocert`, respectively.

That said, because our server uses mTLS **only clients that have a certificate issued by our certificate authority will be allowed to connect**. That means it can be safely and easily exposed directly to the public internet using a [LoadBalancer service type](https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer):

```
kubectl expose deployment hello-mtls --name=hello-mtls-lb --port=443 --type=LoadBalancer
```

To connect we need a certificate. There are a [couple](RUNBOOK.md#federation) [different](RUNBOOK.md#multiple-intermediates) [ways](RUNBOOK.md#exposing-the-ca) to get one, but for simplicity we'll just forward a port.

```
kubectl -n step port-forward $(kubectl -n step get pods -l app=ca -o jsonpath={$.items[0].metadata.name}) 4443:4443
```

In another window we'll use `step` to grab the root certificate, generate a key pair, and get a certificate.

> To follow along you'll need to [`install step`](https://github.com/smallstep/cli#installing) if you haven't already. You'll also need your admin password and CA fingerprint, which were output during installation (see [here](RUNBOOK.md#recover-admin-and-ca-password) and [here](#RUNBOOK.md#recompute-root-certificate-fingerprint) if you already lost them :).

```bash
$ export CA_POD=$(kubectl -n step get pods -l app=ca -o jsonpath={$.items[0].metadata.name})
$ step ca root root.crt --ca-url https://127.0.0.1:4443 --fingerprint <fingerprint>
$ step ca certificate mike mike.crt mike.key --ca-url https://127.0.0.1:4443 --root root.crt
✔ Key ID: H4vH5VfvaMro0yrk-UIkkeCoPFqEfjF6vg0GHFdhVyM (admin)
✔ Please enter the password to decrypt the provisioner key: 0QOC9xcq56R1aEyLHPzBqN18Z3WfGZ01
✔ CA: https://127.0.0.1:4443/1.0/sign
✔ Certificate: mike.crt
✔ Private Key: mike.key
```

Now we can simply `curl` the service:

> If you're using minikube or docker for mac the load balancer's "IP" might be `localhost`, which won't work. In that case, simply `export HELLO_MTLS_IP=127.0.0.1` and try again.

```
$ export HELLO_MTLS_IP=$(kubectl get svc hello-mtls-lb -ojsonpath={$.status.loadBalancer.ingress[0].ip})
$ curl --resolve hello-mtls.default.svc.cluster.local:443:$HELLO_MTLS_IP \
       --cacert root.crt \
       --cert mike.crt \
       --key mike.key \
       https://hello-mtls.default.svc.cluster.local
Hello, mike!
```

> Note that we're using `--resolve` to tell `curl` to override DNS and resolve the name in our workload's certificate to its public IP address. In a real production infrastructure you could configure DNS manually, or you could propagate DNS to workloads outside kubernetes using something like [ExternalDNS](https://github.com/kubernetes-incubator/external-dns).

✅ mTLS outside cluster.

<!--- TODO: CTA or Further Reading... Move "How it works" maybe? Or put this below that? --->

### Cleanup & uninstall

To clean up after running through the tutorial remove the `hello-mtls` and `hello-mtls-client` deployments and services:

```
kubectl delete deployment hello-mtls
kubectl delete deployment hello-mtls-client
kubectl delete service hello-mtls
kubectl delete service hello-mtls-lb
```

See the runbook for instructions on [uninstalling `autocert`](RUNBOOK.md#uninstalling).

## How it works

### Architecture

`Autocert` is an [admission webhook](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#admission-webhooks) that intercepts and patches pod creation requests with [some YAML](install/02-autocert.yaml#L26-L44) to inject an [init container](bootstrapper/) and [sidecar](renewer/) that handle obtaining and renewing certificates, respectively.

![Autocert architecture diagram](https://raw.githubusercontent.com/smallstep/certificates/autocert/autocert/autocert-arch.png)

### Enrollment & renewal

It integrates with [`step certificates`](https://github.com/smallstep/certificates) and uses the [one-time token bootstrap protocol](https://smallstep.com/blog/step-certificates.html#automated-certificate-management) from that project to mutually authenticate a new pod with your certificate authority, and obtain a certificate.

![Autocert bootstrap protocol diagram](https://raw.githubusercontent.com/smallstep/certificates/autocert/autocert/autocert-bootstrap.png)

Tokens are [generated by the admission webhook](controller/provisioner.go#L46-L72) and [transmitted to the injected init container via a kubernetes secret](controller/main.go#L91-L125). The init container [uses the one-time token](bootstrapper/bootstrapper.sh) to obtain a certificate. A sidecar is also installed to [renew certificates](renewer/Dockerfile#L8) before they expire. Renewal simply uses mTLS with the CA.

## Further Reading

 * We tweet [@smallsteplabs](https://twitter.com/smallsteplabs)
 * Read [our blog](https://smallstep.com/blog)
 * Check out the [runbook](RUNBOOK.md)
 * Check out [`step` CLI](https://github.com/smallstep/cli)

## Questions

#### Wait, so any pod can get a certificate with any identity? How is that secure?

 1. Don't give people `kubectl` access to your production clusters
 2. Use a deploy pipeline based on `git` artifacts
 3. Enforce code review on those `git` artifacts

 If that doesn't work for you, or if you have a better idea, we'd love to hear! Please [open an issue](https://github.com/smallstep/certificates/issues/new?template=autocert_feature.md)!

 #### Why do I have to tell you the name to put in a certificate? Why can't you automatically bind service names?

Mostly because monitoring the API server to figure out which services are associated with which workloads is complicated and somewhat magical. And it might not be what you want.

That said, we're not totally opposed to this idea. If anyone has strong feels and a good design please [open an issue](https://github.com/smallstep/certificates/issues/new?template=autocert_feature.md).

#### Doesn't kubernetes already ship with a certificate authority?

Yes, it uses [a bunch of CAs](https://jvns.ca/blog/2017/08/05/how-kubernetes-certificates-work/) for different sorts of control plane communication. Technically, kubernetes doesn't _come with_ a CA. It has integration points that allow you to use any CA (e.g., [Kubernetes the hard way](https://github.com/kelseyhightower/kubernetes-the-hard-way) [uses CFSSL](https://github.com/kelseyhightower/kubernetes-the-hard-way/blob/2983b28f13b294c6422a5600bb6f14142f5e7a26/docs/02-certificate-authority.md). You could use [`step certificates`](https://github.com/smallstep/certificates), which `autocert` is based on, instead.

In any case, these CAs are meant for control plane communication. You could use them for your service-to-service data plane, but it's probably not a good idea.

#### What permissions does `autocert` require in my cluster and why?

`Autocert` needs permission to create and delete secrets cluster-wide. You can [check out our RBAC config here](install/03-rbac.yaml). These permissions are needed in order to transmit one-time tokens to workloads using secrets, and to clean up afterwards. We'd love to scope these permissions down further. If anyone has any ideas please [open an issue](https://github.com/smallstep/certificates/issues/new?template=autocert_feature.md).

#### Why does `autocert` create secrets?

The `autocert` admission webhook needs to securely transmit one-time bootstrap tokens to containers. This could be accomplished without using secrets. The webhook returns a [JSONPatch](https://tools.ietf.org/html/rfc6902) response that's applied to the pod spec. This response could patch the literal token value into our init container's environment.

Unfortunately, the kubernetes API server does not authenticate itself to admission webhooks by default, and configuring it to do so [requires passing a custom config file](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#authenticate-apiservers) at apiserver startup. This isn't an option for everyone (e.g., on GKE) so we opted not to rely on it.

Since our webhook can't authenticate callers, including bootstrap tokens in patch responses would be dangerous. By using secrets an attacker can still trick `autocert` into generating superflous bootstrap tokens, but they'd also need read access to cluster secrets to do anything with them.

Hopefully this story will improve with time.

#### Why not use kubernetes service accounts instead of bootstrap tokens?

Great idea! This should be pretty easy to add. However, existing service accounts are [somewhat broken](https://github.com/kubernetes/community/pull/1460) for this use case. The upcoming [TokenRequest API](https://github.com/kubernetes/kubernetes/issues/58790) should fix most of these issues.

TODO: Link to issue for people who want this.

#### Too. many. containers. Why do you need to install an init container and sidecar?

We don't. It's just easier for you. Your containers can generate key pairs, exchange them for certificates, and manage renewals themselves. This is pretty easy if you [install `step`](https://github.com/smallstep/cli#installing) in your containers, or integrate with our [golang SDK](https://godoc.org/github.com/smallstep/certificates/ca). To support this we'd need to add the option to inject a bootstrap token without injecting these containers.

TODO: Link to issue for people who want this.

That said, the init container and sidecar are both super lightweight.

#### Why are keys and certificates managed via volume mounts? Why not use a secret or some custom resource?

Because, by default, kubernetes secrets are stored in plaintext in `etcd` and might even be transmitted unencrypted across the network. Even if secrets were properly encrypted, transmitting a private key across the network violates PKI best practices. Key pairs should always be generated where they're used, and private keys should never be known by anyone but their owners.

That said, there are use cases where a certificate mounted in a secret resource is desirable (e.g., for use with a kubernetes `Ingress`). We may add support for this in the future. However, we think the current method is easier and a better default.

TODO: Link to issue for people who want this.

#### Why not use kubernetes CSR resources for this?

It's harder and less secure. If any good and simple design exists for securely automating CSR approval using this resource we'd love to see it!

#### How is this different than [`cert-manager`](https://github.com/jetstack/cert-manager)

`Cert-manager` is a great project. But it's design is focused on managing Web PKI certificates issued by [Let's Encrypt's](https://letsencrypt.org/) public certificate authority. These certificates are useful for TLS ingress from web browsers. `Autocert` is different. It's purpose-built to manage certificates issued by your own private CA to support the use of mTLS for internal communication (e.g., service-to-service).

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
