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
  - [ ] Automatic certificate rotation
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
