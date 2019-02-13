# hello-mtls

This repository contains examples of dockerized [m]TLS clients and servers in
various languages. There's a lot of confusion and misinformation regarding how
to do mTLS properly with an internal public key infrastructure. The goal of
this repository is to demonstrate best practices like:

  * Properly configuring TLS to use your internal CA's root certificate
  * mTLS (client certificates / client authentication)
  * Short-lived certificate support (clients and servers automatically load
    renewed certificates)

Examples use multi-stage docker builds and can be built via without any
required local dependencies (except `docker`):

```
docker build -f Dockerfile.server -t hello-mtls-server-<lang> .
docker build -f Dockerfile.client -t hello-mtls-client-<lang> .
```

Once built, you should be able to deploy via:

```
kubectl apply -f hello-mtls.server.yaml
kubectl apply -f hello-mtls.client.yaml
```

## Mutual TLS

Unlike the _server auth TLS_ that's typical with web browsers, where the browser authenticates the server but not vice versa, _mutual TLS_ (mTLS) connections have both remote peers (client and server) authenticate to one another by presenting certificates. mTLS is not a different protocol. It's just a variant of TLS that's not usually turned on by default. This respository demonstrates **how to turn on mTLS** with different tools and languages. It also demonstrates other **TLS best practices** like certificate rotation.

mTLS provides _authenticated encryption_: an _identity dialtone_ and _end-to-end encryption_ for your workloads. It's like a secure line with caller ID. This has [all sorts of benefits](https://smallstep.com/blog/use-tls.html): better security, compliance, and easier auditability for starters. It **makes workloads identity-aware**, improving observability and enabling granular access control. Perhaps most compelling, mTLS lets you securely communicate with workloads running anywhere. Code, containers, devices, people, and anything else can connect securely using mTLS as long as they know one anothers' names and can resolve those names to routable IP addresses.

With properly configured mTLS, services can be safely exposed directly to the public internet: **only clients that have a certificate issued by the internal certificate authority will be allowed to connect**.

Here's a rough approximation of how an mTLS handshake works:

![mTLS handshake diagram](https://raw.githubusercontent.com/smallstep/certificates/autocert/autocert/mtls-handshake.png)

A few things to note:

 * It's the signing of random numbers that proves we're talking to the right remote. It's the digital equivalent of asking someone to send you a photo of them with today's newspaper.
 * The client and server need to have prior knowledge of the root certificate(s) used for signing other certificates.
 * The client and server need to be configured to use the correct certificate and private key (the certificate must have been issued by a CA with a trusted root certificate)
 * Private keys are never shared. This is the magic of public key cryptography: unlike passwords or access tokens, certificates let you prove who you are without giving anyone the ability to impersonate you.

## Feature matrix

This matrix shows the set of features we'd like to demonstrate in each language
and where each language is. Bug fixes, improvements, and examples in new
languages are appreciated!

[go/](go/)
- [X] Server using autocert certificate & key
  - [X] mTLS (client authentication using internal root certificate)
  - [X] Automatic certificate renewal
  - [X] Restrict to safe ciphersuites and TLS versions
  - [ ] TLS stack configuration loaded from `step-ca`
  - [ ] Root certificate rotation
- [X] Client using autocert root certificate
  - [X] mTLS (send client certificate if server asks for it)
  - [X] Automatic certificate rotation
  - [X] Restrict to safe ciphersuites and TLS versions
  - [ ] TLS stack configuration loaded from `step-ca`
  - [ ] Root certificate rotation

[go-grpc/](go-grpc/)
- [X] Server using autocert certificate & key
  - [X] mTLS (client authentication using internal root certificate)
  - [X] Automatic certificate renewal
  - [X] Restrict to safe ciphersuites and TLS versions
  - [ ] TLS stack configuration loaded from `step-ca`
  - [ ] Root certificate rotation
- [X] Client using autocert root certificate
  - [X] mTLS (send client certificate if server asks for it)
  - [X] Automatic certificate rotation
  - [X] Restrict to safe ciphersuites and TLS versions
  - [ ] TLS stack configuration loaded from `step-ca`
  - [ ] Root certificate rotation

[curl/](curl/)
- [X] Client
  - [X] mTLS (send client certificate if server asks for it)
  - [X] Automatic certificate rotation
  - [ ] Restrict to safe ciphersuites and TLS versions
  - [ ] TLS stack configuration loaded from `step-ca`
  - [ ] Root certificate rotation

[nginx/](nginx/)
- [X] Server
  - [X] mTLS (client authentication using internal root certificate)
  - [X] Automatic certificate renewal
  - [X] Restrict to safe ciphersuites and TLS versions
  - [ ] TLS stack configuration loaded from `step-ca`
  - [ ] Root certificate rotation

[node/](node/)
- [X] Server
  - [X] mTLS (client authentication using internal root certificate)
  - [X] Automatic certificate renewal
  - [X] Restrict to safe ciphersuites and TLS versions
  - [ ] TLS stack configuration loaded from `step-ca`
  - [ ] Root certificate rotation
- [X] Client using autocert root certificate
  - [X] mTLS (send client certificate if server asks for it)
  - [X] Automatic certificate rotation
  - [X] Restrict to safe ciphersuites and TLS versions
  - [ ] TLS stack configuration loaded from `step-ca`
  - [ ] Root certificate rotation

[envoy/](envoy/)
- [X] Server
  - [X] mTLS (client authentication using internal root certificate)
  - [X] Automatic certificate renewal
  - [X] Restrict to safe ciphersuites and TLS versions
  - [ ] TLS stack configuration loaded from `step-ca`
  - [ ] Root certificate rotation
