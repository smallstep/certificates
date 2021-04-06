# Step Certificates

`step-ca` is an online certificate authority for secure, automated certificate management. It's the server counterpart to the [`step` CLI tool](https://github.com/smallstep/cli).

You can use it to:
- Issue X.509 certificates for your internal infrastructure:
  - HTTPS certificates that [work in browsers](https://smallstep.com/blog/step-v0-8-6-valid-HTTPS-certificates-for-dev-pre-prod.html) ([RFC5280](https://tools.ietf.org/html/rfc5280) and [CA/Browser Forum](https://cabforum.org/baseline-requirements-documents/) compliance)
  - TLS certificates for VMs, containers, APIs, mobile clients, database connections, printers, wifi networks, toaster ovens...
  - Client certificates to [enable mutual TLS (mTLS)](https://smallstep.com/hello-mtls) in your infra. mTLS is an optional feature in TLS where both client and server authenticate each other. Why add the complexity of a VPN when you can safely use mTLS over the public internet?
- Issue SSH certificates:
  - For people, in exchange for single sign-on ID tokens
  - For hosts, in exchange for cloud instance identity documents
- Easily automate certificate management:
  - It's an ACME v2 server
  - It has a JSON API
  - It comes with a [Go wrapper](./examples#user-content-basic-client-usage)
  - ... and there's a [command-line client](https://github.com/smallstep/cli) you can use in scripts!

Whatever your use case, `step-ca` is easy to use and hard to misuse, thanks to [safe, sane defaults](https://smallstep.com/docs/step-ca/certificate-authority-server-production#sane-cryptographic-defaults).

**Questions? Find us in [Discussions](https://github.com/smallstep/certificates/discussions).**

[Website](https://smallstep.com/certificates) |
[Documentation](https://smallstep.com/docs) |
[Installation](https://smallstep.com/docs/step-ca/installation) |
[Getting Started](https://smallstep.com/docs/step-ca/getting-started) |
[Contributor's Guide](./docs/CONTRIBUTING.md)

[![GitHub release](https://img.shields.io/github/release/smallstep/certificates.svg)](https://github.com/smallstep/certificates/releases/latest)
[![CA Image](https://images.microbadger.com/badges/image/smallstep/step-ca.svg)](https://microbadger.com/images/smallstep/step-ca)
[![Go Report Card](https://goreportcard.com/badge/github.com/smallstep/certificates)](https://goreportcard.com/report/github.com/smallstep/certificates)
[![Build Status](https://travis-ci.com/smallstep/certificates.svg?branch=master)](https://travis-ci.com/smallstep/certificates)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CLA assistant](https://cla-assistant.io/readme/badge/smallstep/certificates)](https://cla-assistant.io/smallstep/certificates)

[![GitHub stars](https://img.shields.io/github/stars/smallstep/certificates.svg?style=social)](https://github.com/smallstep/certificates/stargazers)
[![Twitter followers](https://img.shields.io/twitter/follow/smallsteplabs.svg?label=Follow&style=social)](https://twitter.com/intent/follow?screen_name=smallsteplabs)

## Features

### 🦾 A fast, stable, flexible private CA

Setting up a *public key infrastructure* (PKI) is out of reach for many small teams. `step-ca` makes it easier.

- Choose key types (RSA, ECDSA, EdDSA) and lifetimes to suit your needs
- [Short-lived certificates](https://smallstep.com/blog/passive-revocation.html) with automated enrollment, renewal, and passive revocation
- Capable of high availability (HA) deployment using [root federation](https://smallstep.com/blog/step-v0.8.3-federation-root-rotation.html) and/or multiple intermediaries
- Can operate as [an online intermediate CA for an existing root CA](https://smallstep.com/docs/tutorials/intermediate-ca-new-ca)
- [Badger, BoltDB, and MySQL database backends](https://smallstep.com/docs/step-ca/configuration#databases)

### ⚙️ Many ways to automate

There are several ways to authorize a request with the CA and establish a chain of trust that suits your flow.

You can issue certificates in exchange for:
- [ACME challenge responses](#your-own-private-acme-server) from any ACMEv2 client
- [OAuth OIDC single sign-on tokens](https://smallstep.com/blog/easily-curl-services-secured-by-https-tls.html), eg:
  - ID tokens from Okta, GSuite, Azure AD, Auth0.
  - ID tokens from an OAuth OIDC service that you host, like [Keycloak](https://www.keycloak.org/) or [Dex](https://github.com/dexidp/dex)
- [Cloud instance identity documents](https://smallstep.com/blog/embarrassingly-easy-certificates-on-aws-azure-gcp/), for VMs on AWS, GCP, and Azure
- [Single-use, short-lived JWK tokens]() issued by your CD tool — Puppet, Chef, Ansible, Terraform, etc.
- A trusted X.509 certificate (X5C provisioner)
- Expiring SSH host certificates needing rotation (the SSHPOP provisioner)
- Learn more in our [provisioner documentation](https://smallstep.com/docs/step-ca/configuration#jwk)

### 🏔 Your own private ACME server

ACME is the protocol used by Let's Encrypt to automate the issuance of HTTPS certificates. It's _super easy_ to issue certificates to any ACMEv2 ([RFC8555](https://tools.ietf.org/html/rfc8555)) client.

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
- Our own [`step` CLI tool](https://github.com/smallstep/cli) is also an ACME client!
- See our [ACME tutorial](https://smallstep.com/docs/tutorials/acme-challenge) for more

### 👩🏽‍💻 An online SSH Certificate Authority

- Delegate SSH authentication to `step-ca` by using [SSH certificates](https://smallstep.com/blog/use-ssh-certificates/) instead of public keys and `authorized_keys` files
- For user certificates, [connect SSH to your single sign-on provider](https://smallstep.com/blog/diy-single-sign-on-for-ssh/), to improve security with short-lived certificates and MFA (or other security policies) via any OAuth OIDC provider.
- For host certificates, improve security, [eliminate TOFU warnings](https://smallstep.com/blog/use-ssh-certificates/), and set up automated host certificate renewal.

### 🤓 A general purpose PKI tool, via [`step` CLI](https://github.com/smallstep/cli) [integration](https://smallstep.com/docs/step-cli/reference/ca/)

- Generate key pairs where they're needed so private keys are never transmitted across the network
- [Authenticate and obtain a certificate](https://smallstep.com/docs/step-cli/reference/ca/certificate/) using any provisioner supported by `step-ca`
- Securely [distribute root certificates](https://smallstep.com/docs/step-cli/reference/ca/root/) and [bootstrap](https://smallstep.com/docs/step-cli/reference/ca/bootstrap/) PKI relying parties
- [Renew](https://smallstep.com/docs/step-cli/reference/ca/renew/) and [revoke](https://smallstep.com/docs/step-cli/reference/ca/revoke/) certificates issued by `step-ca`
- [Install root certificates](https://smallstep.com/docs/step-cli/reference/certificate/install/) on your machine and browsers, so your CA is trusted
- [Inspect](https://smallstep.com/docs/step-cli/reference/certificate/inspect/) and [lint](https://smallstep.com/docs/step-cli/reference/certificate/lint/) certificates

## Installation

See our installation docs [here](https://smallstep.com/docs/step-ca/installation).

## Documentation

Documentation can be found in a handful of different places:

1. On the web at https://smallstep.com/docs/step-ca.

2. On the command line with `step help ca xxx` where `xxx` is the subcommand
you are interested in. Ex: `step help ca provisioner list`.

3. In your browser, by running `step help --http=:8080 ca` from the command line
and visiting http://localhost:8080.

4. The [docs](./docs/README.md) folder is being deprecated, but it still has some documentation and tutorials.

## Feedback?

* Tell us what you like and don't like about managing your PKI - we're eager to help solve problems in this space.
* Tell us about a feature you'd like to see! [Add a feature request Issue](https://github.com/smallstep/certificates/issues/new?assignees=&labels=enhancement%2C+needs+triage&template=enhancement.md&title=), [ask on Discussions](https://github.com/smallstep/certificates/discussions), or hit us up on [Twitter](https://twitter.com/smallsteplabs).
