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

---

**Don't want to run your own CA?**
To get up and running quickly, or as an alternative to running your own `step-ca` server, consider creating a [free hosted smallstep Certificate Manager authority](https://info.smallstep.com/certificate-manager-early-access-mvp/).

---

**Questions? Find us in [Discussions](https://github.com/smallstep/certificates/discussions) or [Join our Discord](https://u.step.sm/discord).**

[Website](https://smallstep.com/certificates) |
[Documentation](https://smallstep.com/docs) |
[Installation](https://smallstep.com/docs/step-ca/installation) |
[Getting Started](https://smallstep.com/docs/step-ca/getting-started) |
[Contributor's Guide](./docs/CONTRIBUTING.md)

[![GitHub release](https://img.shields.io/github/release/smallstep/certificates.svg)](https://github.com/smallstep/certificates/releases/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/smallstep/certificates)](https://goreportcard.com/report/github.com/smallstep/certificates)
[![Build Status](https://github.com/smallstep/certificates/actions/workflows/test.yml/badge.svg)](https://github.com/smallstep/certificates)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CLA assistant](https://cla-assistant.io/readme/badge/smallstep/certificates)](https://cla-assistant.io/smallstep/certificates)

[![GitHub stars](https://img.shields.io/github/stars/smallstep/certificates.svg?style=social)](https://github.com/smallstep/certificates/stargazers)
[![Twitter followers](https://img.shields.io/twitter/follow/smallsteplabs.svg?label=Follow&style=social)](https://twitter.com/intent/follow?screen_name=smallsteplabs)

![star us](https://github.com/smallstep/certificates/raw/master/docs/images/star.gif)

## Features

### 🦾 A fast, stable, flexible private CA

Setting up a *public key infrastructure* (PKI) is out of reach for many small teams. `step-ca` makes it easier.

- Choose key types (RSA, ECDSA, EdDSA) and lifetimes to suit your needs
- [Short-lived certificates](https://smallstep.com/blog/passive-revocation.html) with automated enrollment, renewal, and passive revocation
- Capable of high availability (HA) deployment using [root federation](https://smallstep.com/blog/step-v0.8.3-federation-root-rotation.html) and/or multiple intermediaries
- Can operate as [an online intermediate CA for an existing root CA](https://smallstep.com/docs/tutorials/intermediate-ca-new-ca)
- [Badger, BoltDB, Postgres, and MySQL database backends](https://smallstep.com/docs/step-ca/configuration#databases)

### ⚙️ Many ways to automate

There are several ways to authorize a request with the CA and establish a chain of trust that suits your flow.

You can issue certificates in exchange for:
- [ACME challenge responses](#your-own-private-acme-server) from any ACMEv2 client
- [OAuth OIDC single sign-on tokens](https://smallstep.com/blog/easily-curl-services-secured-by-https-tls.html), eg:
  - ID tokens from Okta, GSuite, Azure AD, Auth0.
  - ID tokens from an OAuth OIDC service that you host, like [Keycloak](https://www.keycloak.org/) or [Dex](https://github.com/dexidp/dex)
- [Cloud instance identity documents](https://smallstep.com/blog/embarrassingly-easy-certificates-on-aws-azure-gcp/), for VMs on AWS, GCP, and Azure
- [Single-use, short-lived JWK tokens](https://smallstep.com/docs/step-ca/provisioners#jwk) issued by your CD tool — Puppet, Chef, Ansible, Terraform, etc.
- A trusted X.509 certificate (X5C provisioner)
- A host certificate from your Nebula network
- A SCEP challenge (SCEP provisioner)
- An SSH host certificates needing renewal (the SSHPOP provisioner)
- Learn more in our [provisioner documentation](https://smallstep.com/docs/step-ca/provisioners)

### 🏔 Your own private ACME server

ACME is the protocol used by Let's Encrypt to automate the issuance of HTTPS certificates. It's _super easy_ to issue certificates to any ACMEv2 ([RFC8555](https://tools.ietf.org/html/rfc8555)) client.

- [Use ACME in development & pre-production](https://smallstep.com/blog/private-acme-server/#local-development--pre-production)
- Supports the most popular [ACME challenge types](https://letsencrypt.org/docs/challenge-types/):
  - For `http-01`, place a token at a well-known URL to prove that you control the web server
  - For `dns-01`, add a `TXT` record to prove that you control the DNS record set
  - For `tls-alpn-01`, respond to the challenge at the TLS layer ([as Caddy does](https://caddy.community/t/caddy-supports-the-acme-tls-alpn-challenge/4860)) to prove that you control the web server

- Works with any ACME client. We've written examples for:
  - [certbot](https://smallstep.com/docs/tutorials/acme-protocol-acme-clients#certbot)
  - [acme.sh](https://smallstep.com/docs/tutorials/acme-protocol-acme-clients#acmesh)
  - [win-acme](https://smallstep.com/docs/tutorials/acme-protocol-acme-clients#win-acme)
  - [Caddy](https://smallstep.com/docs/tutorials/acme-protocol-acme-clients#caddy-v2)
  - [Traefik](https://smallstep.com/docs/tutorials/acme-protocol-acme-clients#traefik)
  - [Apache](https://smallstep.com/docs/tutorials/acme-protocol-acme-clients#apache)
  - [nginx](https://smallstep.com/docs/tutorials/acme-protocol-acme-clients#nginx)
- Get certificates programmatically using ACME, using these libraries:
  - [`lego`](https://github.com/go-acme/lego) for Golang ([example usage](https://smallstep.com/docs/tutorials/acme-protocol-acme-clients#golang))
  - certbot's [`acme` module](https://github.com/certbot/certbot/tree/master/acme) for Python ([example usage](https://smallstep.com/docs/tutorials/acme-protocol-acme-clients#python))
  - [`acme-client`](https://github.com/publishlab/node-acme-client) for Node.js ([example usage](https://smallstep.com/docs/tutorials/acme-protocol-acme-clients#node))
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
