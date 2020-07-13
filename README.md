# Step Certificates

`step-ca` is an online certificate authority for secure, automated certificate management.

You can use it to:
- Issue X.509 certificates for all of your internal infrastructure
- Enable mutual TLS for encryption and authentication to your VMs, containers, devices, databases, APIs, and anything else you can think of, using internal hostnames
- Issue SSH certificates in exchange for single sign-on tokens and cloud instance identity documents.
- Easily automate certificate management with any ACME v2 client
- And do a _lot_ more...

It's easy to use and hard to misuse, thanks to [safe, sane defaults](https://github.com/smallstep/certificates/blob/master/docs/defaults.md).

For automation, `step-ca` has full ACME v2 support, a JSON API, and a [Go wrapper](https://github.com/smallstep/certificates/tree/master/examples#user-content-basic-client-usage).

For human use, `step-ca` has a command line counterpart: the [`step` CLI tool](https://github.com/smallstep/cli).

**Questions? Find us [on gitter](https://gitter.im/smallstep/community).**

[Website](https://smallstep.com/certificates) |
[Documentation](#documentation) |
[Installation Guide](#installation-guide) |
[Quickstart](https://github.com/smallstep/certificates#quickstart) |
[Getting Started](./docs/GETTING_STARTED.md) |
[Contribution Guide](./docs/CONTRIBUTING.md)

[![GitHub release](https://img.shields.io/github/release/smallstep/certificates.svg)](https://github.com/smallstep/certificates/releases)
[![Join the chat at https://gitter.im/smallstep/community](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/smallstep/community)
[![CA Image](https://images.microbadger.com/badges/image/smallstep/step-ca.svg)](https://microbadger.com/images/smallstep/step-ca)
[![Go Report Card](https://goreportcard.com/badge/github.com/smallstep/certificates)](https://goreportcard.com/report/github.com/smallstep/certificates)
[![Build Status](https://travis-ci.com/smallstep/certificates.svg?branch=master)](https://travis-ci.com/smallstep/certificates)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CLA assistant](https://cla-assistant.io/readme/badge/smallstep/certificates)](https://cla-assistant.io/smallstep/certificates)

[![GitHub stars](https://img.shields.io/github/stars/smallstep/certificates.svg?style=social)](https://github.com/smallstep/certificates/stargazers)
[![Twitter followers](https://img.shields.io/twitter/follow/smallsteplabs.svg?label=Follow&style=social)](https://twitter.com/intent/follow?screen_name=smallsteplabs)

![Animated terminal showing step certificates in practice](https://github.com/smallstep/certificates/raw/master/docs/images/step-ca-2-legged.gif)

## Features

### A fast, stable, private CA you run yourself

- Issue certificates for VMs, containers, devices, databases, APIs, and anything else you can think of, using internal hostnames.
- Issue TLS and SSH certificates for people, using their emails.
- Certificates work with TLS and HTTPS (they are [RFC5280](https://tools.ietf.org/html/rfc5280) and [CA/Browser Forum](https://cabforum.org/baseline-requirements-documents/) compliant).
- Choose key types (RSA, ECDSA, EdDSA) & lifetimes to suit your needs
- Kubernetes [helm charts](https://hub.helm.sh/charts/smallstep/step-certificates), [autocert](https://github.com/smallstep/autocert), and [cert-manager integration](https://github.com/smallstep/step-issuer)
- [Short-lived certificates](https://smallstep.com/blog/passive-revocation.html) with automated enrollment, renewal, and revocation
- Capable of high availability (HA) deployment using [root federation](https://smallstep.com/blog/step-v0.8.3-federation-root-rotation.html) and/or multiple intermediaries
- Operate as [an online intermediate CA](https://github.com/smallstep/certificates/blob/master/docs/questions.md#i-already-have-pki-in-place-can-i-use-this-with-my-own-root-certificate) for an existing root CA
- [Pluggable database backends](https://github.com/smallstep/certificates/blob/master/docs/database.md) for persistence

### Lots of (automatable) ways to get certificates

Configure the CA to issue certificates in exchange for:

- [Single sign-on tokens](https://smallstep.com/blog/easily-curl-services-secured-by-https-tls.html) from Okta, GSuite, Active Directory, or any OAuth OIDC provider
- [Cloud instance identity documents](https://smallstep.com/blog/embarrassingly-easy-certificates-on-aws-azure-gcp/) for VMs on AWS, GCP, and Azure
- [Single-use, short-lived JWK tokens](https://smallstep.com/docs/design-document/#jwk-provisioner) issued by your CD tool — Puppet, Chef, Ansible, Terraform, etc.
- Responding to an ACME challenge from the CA (see below!)

### Your own private ACME server

ACME is the protocol used by Let's Encrypt. It's _super easy_ to issue certificates to any ACMEv2 ([RFC8555](https://tools.ietf.org/html/rfc8555)) client.

- [Use ACME in development & pre-production](https://smallstep.com/blog/private-acme-server/#local-development--pre-production)
- Supports the most popular [ACME challenge types](https://letsencrypt.org/docs/challenge-types/):
  - For `http-01`, place a token at a well-known URL to prove that you control the web server
  - For `dns-01`, add a `TXT` record to prove that you control the DNS record set
  - For `tls-alpn-01`, respond to the challenge at the TLS layer ([as Caddy does](https://caddy.community/t/caddy-supports-the-acme-tls-alpn-challenge/4860)) to prove that you control the web server

- Works with any ACME client. We've written examples for:
  - [certbot](https://smallstep.com/blog/private-acme-server/#certbotuploadsacme-certbotpng-certbot-example)
  - [acme.sh](https://smallstep.com/blog/private-acme-server/#acmeshuploadsacme-acme-shpng-acmesh-example)
  - [Caddy](https://smallstep.com/blog/private-acme-server/#caddyuploadsacme-caddypng-caddy-example)
  - [Traefik](https://smallstep.com/blog/private-acme-server/#traefikuploadsacme-traefikpng-traefik-example)
  - [Apache](https://smallstep.com/blog/private-acme-server/#apacheuploadsacme-apachepng-apache-example)
  - [nginx](https://smallstep.com/blog/private-acme-server/#nginxuploadsacme-nginxpng-nginx-example)
- Get certificates programmatically using ACME, using these libraries:
  - [`lego`](https://github.com/go-acme/lego) for Golang ([example usage](https://smallstep.com/blog/private-acme-server/#golanguploadsacme-golangpng-go-example))
  - certbot's [`acme` module](https://github.com/certbot/certbot/tree/master/acme) for Python ([example usage](https://smallstep.com/blog/private-acme-server/#pythonuploadsacme-pythonpng-python-example))
  - [`acme-client`](https://github.com/publishlab/node-acme-client) for Node.js ([example usage](https://smallstep.com/blog/private-acme-server/#nodejsuploadsacme-node-jspng-nodejs-example))
- Our own [`step` CLI tool](github.com/smallstep/cli) is also an ACME client!
- See our [ACME docs](https://smallstep.com/blog/private-acme-server/) for more

### [SSH Certificates](https://smallstep.com/blog/use-ssh-certificates/)

- Use [certificate authentication for SSH](https://smallstep.com/blog/use-ssh-certificates/): connect SSH to SSO, improve security, and eliminate warnings & errors
- Issue SSH user certificates using OAuth OIDC
- Issue SSH host certificates to cloud VMs using instance identity documents

### Easy certificate management and automation via [`step` CLI](https://github.com/smallstep/cli) [integration](https://smallstep.com/docs/cli/ca/)

- Generate key pairs where they're needed so private keys are never transmitted across the network
- [Authenticate and obtain a certificate](https://smallstep.com/docs/cli/ca/certificate/) using any enrollment mechanism supported by `step-ca`
- Securely [distribute root certificates](https://smallstep.com/docs/cli/ca/root/) and [bootstrap](https://smallstep.com/docs/cli/ca/bootstrap/) PKI relying parties
- [Renew](https://smallstep.com/docs/cli/ca/renew/) and [revoke](https://smallstep.com/docs/cli/ca/revoke/) certificates issued by `step-ca`
- [Install root certificates](https://smallstep.com/docs/cli/certificate/install/) so your CA is trusted by default (issue development certificates **that [work in browsers](https://smallstep.com/blog/step-v0-8-6-valid-HTTPS-certificates-for-dev-pre-prod.html)**)
- [Inspect](https://smallstep.com/docs/cli/certificate/inspect/) and [lint](https://smallstep.com/docs/cli/certificate/lint/) certificates

## Motivation

Managing your own *public key infrastructure* (PKI) can be tedious and error
prone. Good security hygiene is hard. Setting up simple PKI is out of reach for
many small teams, and following best practices like proper certificate
revocation and rolling is challenging even for experts.

Amongst numerous use cases, proper PKI makes it easy to use mTLS (mutual TLS)
to improve security and to make it possible to connect services across the
public internet. Unlike VPNs & SDNs, deploying and scaling mTLS is pretty
easy. You're (hopefully) already using TLS, and your existing tools and
standard libraries will provide most of what you need. If you know how to
operate DNS and reverse proxies, you know how to operate mTLS
infrastructure.

![Connect it all with
mTLS](https://raw.githubusercontent.com/smallstep/certificates/master/docs/images/connect-with-mtls-2.png)

There's just one problem: **you need certificates issued by your own
certificate authority (CA)**. Building and operating a CA, issuing
certificates, and making sure they're renewed before they expire is tricky.
This project provides the infrastructure, automations, and workflows you'll
need.

`step certificates` is part of smallstep's broader security architecture, which
makes it much easier to implement good security practices early, and
incrementally improve them as your system matures.

For more information and [docs](https://smallstep.com/docs) see [the smallstep
website](https://smallstep.com/certificates) and the [blog
post](https://smallstep.com/blog/step-certificates.html) announcing this project.

## Installation Guide

These instructions will install an OS specific version of the `step-ca` binary on
your local machine.

### Mac OS

Install `step`  and `step-ca` together via [Homebrew](https://brew.sh/):

```
$ brew install step
```

### Linux

> **Note:** While the `step` CLI tool is not required to run `step-ca`, it will make your life easier so you'll probably want to [install it](https://github.com/smallstep/cli#installation-guide) too.

#### Debian

1. [Optional] Install `step`.

    Download the Debian package from the
    [latest `step` release](https://github.com/smallstep/cli/releases/latest):

    ```
    $ wget https://github.com/smallstep/cli/releases/download/vX.Y.Z/step-cli_X.Y.Z_amd64.deb
    ```

    Install the Debian package:

    ```
    $ sudo dpkg -i step-cli_X.Y.Z_amd64.deb
    ```

2. Install `step-ca`.

    Download the Debian package from the [latest `step-ca` release](https://github.com/smallstep/certificates/releases/latest):

    ```
    $ wget https://github.com/smallstep/certificates/releases/download/vX.Y.Z/step-certificates_X.Y.Z_amd64.deb
    ```

    Install the Debian package:

    ```
    $ sudo dpkg -i step-certificates_X.Y.Z_amd64.deb
    ```

#### Arch Linux

We are using the [Arch User Repository](https://aur.archlinux.org) to distribute
`step` binaries for Arch Linux.

* [Optional] The `step` binary tarball can be found [here](https://aur.archlinux.org/packages/step-cli-bin/).
* The `step-ca` binary tarball can be found [here](https://aur.archlinux.org/packages/step-ca-bin/).

You can use [pacman](https://www.archlinux.org/pacman/) to install the packages.

#### RHEL/CentOS

1. [Optional] Install `step`.

    Download the Linux tarball from the 
    [latest `step` release](https://github.com/smallstep/cli/releases/latest):

    ```
    $ wget -O step-cli.tar.gz https://github.com/smallstep/cli/releases/download/vX.Y.Z/step_linux_X.Y.Z_amd64.tar.gz
    ```

    Install `step` by unzipping and copying the executable over to `/usr/bin`:

    ```
    $ tar -xf step-cli.tar.gz
    $ sudo cp step_X.Y.Z/bin/step /usr/bin
    ```

2. Install `step-ca`.

    Download the Linux package from the [latest `step-ca` release](https://github.com/smallstep/certificates/releases/latest):

    ```
    $ wget -O step-ca.tar.gz https://github.com/smallstep/cli/releases/download/vX.Y.Z/step_linux_X.Y.Z_amd64.tar.gz
    ```

    Install `step-ca` by unzipping and copying the executable over to `/usr/bin`:

    ```
    $ tar -xf step-ca.tar.gz
    $ sudo cp step-certificates_X.Y.Z/bin/step-ca /usr/bin
    ```

See the [`systemctl` setup section](./docs/GETTING_STARTED.md#systemctl) for a
guide on configuring `step-ca` as a daemon.


### Kubernetes

We publish [helm charts](https://hub.helm.sh/charts/smallstep/step-certificates) for easy installation on kubernetes:

```
helm install step-certificates
```

> <a href="https://github.com/smallstep/autocert"><img width="25%" src="https://raw.githubusercontent.com/smallstep/autocert/master/autocert-logo.png"></a>
>
> If you're using Kubernetes, make sure you [check out
> autocert](https://github.com/smallstep/autocert): a kubernetes add-on that builds on `step
> certificates` to automatically inject TLS/HTTPS certificates into your containers.

### Test

<pre><code><b>$ step version</b>
Smallstep CLI/0.10.0 (darwin/amd64)
Release Date: 2019-04-30 19:01 UTC

<b>$ step-ca version</b>
Smallstep CA/0.10.0 (darwin/amd64)
Release Date: 2019-04-30 19:02 UTC</code></pre>

## Quickstart

In the following guide we'll run a simple `hello` server that requires clients
to connect over an authorized and encrypted channel using HTTPS. `step-ca`
will issue certificates to our server, allowing it to authenticate and encrypt
communication. Let's get started!

### Prerequisites

* [`step`](#installation-guide)
* [golang](https://golang.org/doc/install)

### Let's get started!

#### 1. Run `step ca init` to create your CA's keys & certificates and configure `step-ca`:

<pre><code><b>$ step ca init</b>
✔ What would you like to name your new PKI? (e.g. Smallstep): <b>Example Inc.</b>
✔ What DNS names or IP addresses would you like to add to your new CA? (e.g. ca.smallstep.com[,1.1.1.1,etc.]): <b>localhost</b>
✔ What address will your new CA listen at? (e.g. :443): <b>127.0.0.1:8080</b>
✔ What would you like to name the first provisioner for your new CA? (e.g. you@smallstep.com): <b>bob@example.com</b>
✔ What do you want your password to be? [leave empty and we'll generate one]: <b>abc123</b>

Generating root certificate...
all done!

Generating intermediate certificate...
all done!

✔ Root certificate: /Users/bob/src/github.com/smallstep/step/.step/certs/root_ca.crt
✔ Root private key: /Users/bob/src/github.com/smallstep/step/.step/secrets/root_ca_key
✔ Root fingerprint: 702a094e239c9eec6f0dcd0a5f65e595bf7ed6614012825c5fe3d1ae1b2fd6ee
✔ Intermediate certificate: /Users/bob/src/github.com/smallstep/step/.step/certs/intermediate_ca.crt
✔ Intermediate private key: /Users/bob/src/github.com/smallstep/step/.step/secrets/intermediate_ca_key
✔ Default configuration: /Users/bob/src/github.com/smallstep/step/.step/config/defaults.json
✔ Certificate Authority configuration: /Users/bob/src/github.com/smallstep/step/.step/config/ca.json

Your PKI is ready to go. To generate certificates for individual services see 'step help ca'.</code></pre>

This command will:

- Generate [password protected](https://github.com/smallstep/certificates/blob/master/docs/GETTING_STARTED.md#passwords)  private keys for your CA to sign certificates
- Generate a root and [intermediate signing certificate](https://security.stackexchange.com/questions/128779/why-is-it-more-secure-to-use-intermediate-ca-certificates) for your CA
- Create a JSON configuration file for `step-ca` (see [getting started](./docs/GETTING_STARTED.md) for details)

You can find these artifacts in `$STEPPATH` (or `~/.step` by default).

#### 2. Start `step-ca`:

You'll be prompted for your password from the previous step, to decrypt the CA's private signing key:

<pre><code><b>$ step-ca $(step path)/config/ca.json</b>
Please enter the password to decrypt /Users/bob/src/github.com/smallstep/step/.step/secrets/intermediate_ca_key: <b>abc123</b>
2019/02/18 13:28:58 Serving HTTPS on 127.0.0.1:8080 ...</code></pre>

#### 3. Copy our `hello world` golang server.

```
$ cat > srv.go <<EOF
package main

import (
    "net/http"
    "log"
)

func HiHandler(w http.ResponseWriter, req *http.Request) {
    w.Header().Set("Content-Type", "text/plain")
    w.Write([]byte("Hello, world!\n"))
}

func main() {
    http.HandleFunc("/hi", HiHandler)
    err := http.ListenAndServeTLS(":8443", "srv.crt", "srv.key", nil)
    if err != nil {
        log.Fatal(err)
    }
}
EOF
```

#### 4. Get an identity for your server from the Step CA.

<pre><code><b>$ step ca certificate localhost srv.crt srv.key</b>
✔ Key ID: rQxROEr7Kx9TNjSQBTETtsu3GKmuW9zm02dMXZ8GUEk (bob@example.com)
✔ Please enter the password to decrypt the provisioner key: abc123
✔ CA: https://localhost:8080/1.0/sign
✔ Certificate: srv.crt
✔ Private Key: srv.key

<b>$ step certificate inspect --bundle srv.crt</b>
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 140439335711218707689123407681832384336 (0x69a7a1d7f6f22f68059d2d9088307750)
    Signature Algorithm: ECDSA-SHA256
        Issuer: CN=Example Inc. Intermediate CA
        Validity
            Not Before: Feb 18 21:32:35 2019 UTC
            Not After : Feb 19 21:32:35 2019 UTC
        Subject: CN=localhost
...
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 207035091234452090159026162349261226844 (0x9bc18217bd560cf07db23178ed90835c)
    Signature Algorithm: ECDSA-SHA256
        Issuer: CN=Example Inc. Root CA
        Validity
            Not Before: Feb 18 21:27:21 2019 UTC
            Not After : Feb 15 21:27:21 2029 UTC
        Subject: CN=Example Inc. Intermediate CA
...</code></pre>

Note that `step` and `step-ca` handle details like [certificate bundling](https://smallstep.com/blog/everything-pki.html#intermediates-chains-and-bundling) for you.

#### 5. Run the simple server.

<pre><code><b>$ go run srv.go &</b></code></pre>

#### 6. Get the root certificate from the Step CA.

In a new Terminal window:

<pre><code><b>$ step ca root root.crt</b>
The root certificate has been saved in root.crt.</code></pre>

#### 7. Make an authenticated, encrypted curl request to your server using HTTP over TLS.

<pre><code><b>$ curl --cacert root.crt https://localhost:8443/hi</b>
Hello, world!</code></pre>

*All Done!*

Check out the [Getting Started](./docs/GETTING_STARTED.md) guide for more examples
and best practices on running Step CA in production.

## Documentation

Documentation can be found in a handful of different places:

1. The [docs](./docs/README.md) sub-repo has an index of documentation and tutorials.

2. On the command line with `step help ca xxx` where `xxx` is the subcommand
you are interested in. Ex: `step help ca provisioner list`.

3. On the web at https://smallstep.com/docs/certificates.

4. On your browser by running `step help --http=:8080 ca` from the command line
and visiting http://localhost:8080.


## The Future

We plan to build more tools that facilitate the use and management of zero trust
networks.

* Tell us what you like and don't like about managing your PKI - we're eager to
help solve problems in this space.
* Tell us what features you'd like to see - open issues or hit us on
[Twitter](https://twitter.com/smallsteplabs).

## Further Reading

Check out the [Getting Started](https://smallstep.com/docs/getting-started/) guide for more examples
and best practices on running Step CA in production.
