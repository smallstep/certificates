# Step Certificates

An online certificate authority and related tools for secure automated certificate management, so you can use TLS everywhere.

[Website](https://smallstep.com) |
[Documentation](https://smallstep.com/docs/certificates) |
[Installation Guide](#installation-guide) |
[Getting Started](./docs/GETTING_STARTED.md) |
[Contribution Guide](./docs/CONTRIBUTING.md)

[![GitHub release](https://img.shields.io/github/release/smallstep/certificates.svg)](https://github.com/smallstep/certificates/releases)
[![CA Image](https://images.microbadger.com/badges/image/smallstep/step-ca.svg)](https://microbadger.com/images/smallstep/step-ca)
[![Go Report Card](https://goreportcard.com/badge/github.com/smallstep/certificates)](https://goreportcard.com/report/github.com/smallstep/certificates)
[![Build Status](https://travis-ci.com/smallstep/certificates.svg?branch=master)](https://travis-ci.com/smallstep/certificates)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CLA assistant](https://cla-assistant.io/readme/badge/smallstep/certificates)](https://cla-assistant.io/smallstep/certificates)

[![GitHub stars](https://img.shields.io/github/stars/smallstep/certificates.svg?style=social)](https://github.com/smallstep/certificates/stargazers)
[![Twitter followers](https://img.shields.io/twitter/follow/smallsteplabs.svg?label=Follow&style=social)](https://twitter.com/intent/follow?screen_name=smallsteplabs)

![Animated terminal showing step certificates in practice](https://github.com/smallstep/certificates/raw/master/images/step-ca-2-legged.gif)

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
mTLS](https://raw.githubusercontent.com/smallstep/certificates/master/images/connect-with-mtls-2.png)

There's just one problem: **you need certificates issued by your own
certificate authority (CA)**. Building and operating a CA, issuing
certificates, and making sure they're renewed before they expire is tricky.
This project provides the infratructure, automations, and workflows you'll
need.

`step certificates` is part of smallstep's broader security architecture, which
makes it much easier to implement good security practices early, and
incrementally improve them as your system matures.

For more information and docs see [the Step
website](https://smallstep.com/certificates) and the [blog
post](https://smallstep.com/blog/step-certificates.html) announcing Step
Certificate Authority.

> ## 🆕 Autocert <a href="autocert/README.md"><img width="50%" src="https://raw.githubusercontent.com/smallstep/certificates/autocert/autocert/autocert-logo.png"></a>
>
> If you're using Kubernetes, make sure you [check out
> autocert](autocert/README.md): a kubernetes add-on that builds on `step
> certificates` to automatically inject TLS/HTTPS certificates into your containers.

## Installation Guide

These instructions will install an OS specific version of the `step-ca` binary on
your local machine.

> NOTE: While `step` is not required to run the Step Certificate Authority (CA)
> we strongly recommend installing both `step cli` and `step certificates`
> because the Step CA is much easier to initialize, manage, and debug using
> the `step cli` toolkit.

### Mac OS

Install `step` via [Homebrew](https://brew.sh/). The
[Homebrew Formula](https://github.com/Homebrew/homebrew-core/blob/master/Formula/step.rb)
installs both `step cli` and `step certificates`.

<pre><code>
<b>$ brew install step</b>

# Test installation ...
<b>$ step certificate inspect https://smallstep.com</b>
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 326381749415081530968054238478851085504954 (0x3bf265673332db2d0c70e48a163fb7d11ba)
    Signature Algorithm: SHA256-RSA
        Issuer: C=US,O=Let's Encrypt,CN=Let's Encrypt Authority X3
...
</code></pre>

> Note: If you have installed `step` previously through the `smallstep/smallstep`
> tap you will need to run the following commands before installing:
```
$ brew untap smallstep/smallstep
$ brew uninstall step
```

### Linux

1. [Optional] Install `step cli`.

    Download the latest Debian package from
    [`step cli` releases](https://github.com/smallstep/cli/releases):

    ```
    $ wget https://github.com/smallstep/cli/releases/download/X.Y.Z/step_X.Y.Z_amd64.deb
    ```

    Install the Debian package:

    ```
    $ sudo dpkg -i step_X.Y.Z_amd64.deb
    ```

2. Install `step certificates`.

    Download the latest Debian package from
    [`step certificates` releases](https://github.com/smallstep/certificates/releases):

    ```
    $ wget https://github.com/smallstep/certificates/releases/download/X.Y.Z/step-certificates_X.Y.Z_amd64.deb
    ```

    Install the Debian package:

    ```
    $ sudo dpkg -i step-certificates_X.Y.Z_amd64.deb
    ```

3. Test.

    <pre><code>
    <b>$ step version</b>
    Smallstep CLI/0.8.5 (darwin/amd64)
    Release Date: 2019-02-13 22:17 UTC

    <b>$ step-ca version</b>
    Smallstep CA/0.8.4 (darwin/amd64)
    Release Date: 2019-02-18 18:56 UTC
    </code></pre>

## Quickstart

In the following guide we'll run a simple `hello` server that requires clients
to connect over an authorized and encrypted channel (HTTP over TLS). The Step
Certificate Authority (CA) will issue an identity dial tone to our server
enabling it to authenticate and encrypt communication. Let's get started!

### Prerequisites

* [`step`](#installation-guide)
* [golang](https://golang.org/doc/install)

### Let's get started!

<a name="GetStartedInit"></a>1. Initialize and run the Step CA.

    `step ca init` initializes the CA and accomplishes two tasks.

    1. Generate a Public Key Infrastructure (PKI) with Root and Intermediate
X.509 Certificates and private keys.

       The root X.509 Certificate is a fancy public key that will be
       distributed to clients enabling them to authenticate all certificates
       generated by your PKI. The root private key should be kept in a very
       private place - but as this is just a demo we won't worry about that
       right now ([more info on storing sensitive
       data](./docs/GETTING_STARTED.md#passwords)). The intermediate
       private key will be used to sign new certificates ([Why is it more
       secure to use intermediate CA
       certificates?](https://security.stackexchange.com/questions/128779/why-is-it-more-secure-to-use-intermediate-ca-certificates))
       and the intermediate certificate will be distributed along with newly
       minted leaf certificates. In our demo, the server will present the
       intermediate certificate along with it's *server* (leaf) certificate
       allowing our client to validate the full chain using the root.

    2. Generate the configuration file required by the Step CA.

       See the [Getting Started](./docs/GETTING_STARTED.md) guide for an in depth
       explanation of the Step CA configuration file.

    <pre><code>
    <b>$ step ca init</b>
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

    Your PKI is ready to go. To generate certificates for individual services see 'step help ca'.

    <b>$ step-ca $(step path)/config/ca.json</b>
    Please enter the password to decrypt /Users/bob/src/github.com/smallstep/step/.step/secrets/intermediate_ca_key: <b>abc123</b>
    2019/02/18 13:28:58 Serving HTTPS on 127.0.0.1:8080 ...
    </code></pre>

    Now we've got an 'up and running' online CA!

2. Copy our `hello world` golang server.

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

3. Get an identity for your server from the Step CA.<a name="GetStartedCert"></a>

    <pre><code>
    <b>$ step ca certificate localhost srv.crt srv.key</b>
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
    ...
    </code></pre>

    Notice that when you inspect `srv.crt` there are actually two certificates
    present. The first is your **server** (leaf) certificate and the second is
    the intermediate certificate. When an intermediate CA is used to sign
    **leaf** certificates it is not enough for the server to only show it's
    **leaf** certificate because the client (which only has access to the root
    certificate) will not be able to validate the full chain.

4. Run the simple server.

    <pre><code>
    <b>$ go run srv.go &</b>
    </code></pre>

5. Get the root certificate from the Step CA.

    In a new Terminal window:

    <pre><code>
    <b>$ step ca root root.crt</b>
    The root certificate has been saved in root.crt.
    </code></pre>

6. Make an authenticated, encrypted curl request to your server using HTTP over TLS.

    <pre><code>
    <b>$ curl --cacert root.crt https://localhost:8443/hi</b>
    Hello, world!
    </code></pre>

*All Done!*

Check out the [Getting Started](./docs/GETTING_STARTED.md) guide for more examples
and best practices on running Step CA in production.

## Documentation

Documentation can be found in three places:

1. On the command line with `step ca help xxx` where `xxx` is the subcommand you are interested in. Ex: `step help ca provisioners list`

2. On the web at https://smallstep.com/docs/certificates

3. On your browser by running `step ca help --http :8080` and visiting http://localhost:8080

## The Future

We plan to build more tools that facilitate the use and management of zero trust
networks.

* Tell us what you like and don't like about managing your PKI - we're eager to
help solve problems in this space.
* Tell us what features you'd like to see - open issues or hit us on
[Twitter](https://twitter.com/smallsteplabs).

## Further Reading

Check out the [Getting Started](./docs/GETTING_STARTED.md) guide for more examples
and best practices on running Step CA in production.
