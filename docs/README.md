# Step Certificates Documentation

## Note: Much of [our documentation has moved](https://smallstep.com/docs)

Index of Documentation and Tutorials for using and deploying the `step certificates`.

[![GitHub release](https://img.shields.io/github/release/smallstep/certificates.svg)](https://github.com/smallstep/certificates/releases)
[![CA Image](https://images.microbadger.com/badges/image/smallstep/step-ca.svg)](https://microbadger.com/images/smallstep/step-ca)
[![Go Report Card](https://goreportcard.com/badge/github.com/smallstep/certificates)](https://goreportcard.com/report/github.com/smallstep/certificates)
[![Build Status](https://travis-ci.com/smallstep/certificates.svg?branch=master)](https://travis-ci.com/smallstep/certificates)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CLA assistant](https://cla-assistant.io/readme/badge/smallstep/certificates)](https://cla-assistant.io/smallstep/certificates)

[![GitHub stars](https://img.shields.io/github/stars/smallstep/certificates.svg?style=social)](https://github.com/smallstep/certificates/stargazers)
[![Twitter followers](https://img.shields.io/twitter/follow/smallsteplabs.svg?label=Follow&style=social)](https://twitter.com/intent/follow?screen_name=smallsteplabs)

## Table of Contents

* **General Info**
    * [Website](https://smallstep.com)
    * [Installation Guide](https://smallstep.com/docs/step-ca/installation)
    * [Getting Started](https://smallstep.com/docs/step-ca/getting-started): in depth guide on getting started
      with `step-ca`, including all configuration options.
    * [Contributor's Guide](./CONTRIBUTING.md)
    * [Sane Defaults](https://smallstep.com/docs/step-ca/certificate-authority-server-production#sane-cryptographic-defaults): default algorithms and attributes used
      in cryptographic primitives and why they were selected.
    * [Frequently Asked Questions](./questions.md)
    * Check out our [Blog](https://smallstep.com/blog/). We post quality
      educational content as well as periodic updates on new releases.
* **API**: Guides to using the API via the `step` CLI.
    * [Revoking Certificates](https://smallstep.com/docs/step-ca/revocation)
    * [Persistence Layer](https://smallstep.com/docs/step-ca/configuration#databases): description and guide to using `step certificates`'
      persistence layer for storing certificate management metadata.
* **Tutorials**: Guides for deploying and getting started with `step` in various environments.
    * [Docker](./docker.md)
    * [Kubernetes](../autocert/README.md)

## Further Reading

* [Use TLS Everywhere](https://smallstep.com/blog/use-tls.html)
* [Everything you should know about certificates and PKI but are too afraid to ask](https://smallstep.com/blog/everything-pki.html)
