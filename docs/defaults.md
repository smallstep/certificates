# Default Algorithms and Attributes for Tokens, Keys, Certificates, etc.

The `step` ecosystem aims to be a "easy to use and hard to misuse" suite of PKI
tools. This means we need to select sane defaults for the myriad
configuration options that exist when using cryptographic primitives and higher
order abstractions (e.g. JWTs).

Below we document significant configuration options that we have selected as
defaults. These selections will change and evolve over time; security and
cryptography are constantly changing in response to real world pressures. We
intend for this document be an accurate representation of current best practices
in the industry, and to have these practices codified as defaults in the `step
certificates` code base. If you have questions, suggestions, or comments about
any of these decisions please let us know by opening an issue on this repo,
reaching out through [GitHub Discussions](https://github.com/smallstep/certificates/discussions).

## Tokens

We use JWTs (JSON Web Tokens) to prove authenticity and identity within the
Step ecosystem. JWTs have received negative attention because they are easy to
misuse and misconfigure. We agree! But lots of things are easy to misuse. We also
believe that when configured well JWTs are a great way to sign and encode data.
Our JWT's are, by default, short-lived (5 minute lifespan) and one time use
during the lifetime of the Step CA. We use a 1 minute clock drift leeway
because that was the recommended default in the reputable JWT package that we
chose. If using Step JWTs or your own JWTs in your code be sure to verify and
validate every single standard attribute of the JWT. JWTs, like all
cryptographic tools, are useless without proper attention to configuration and
guidelines.

## Keys

RSA keys don't scale very well. To get 128 bits of security, you need 3,072-bit
RSA keys, which are noticeably slower. ECDSA keys provide an alternative
that offers better security and better performance. At 256 bits, ECDSA keys
provide 128 bits of security. A small number of older clients don't support
ECDSA, but most modern clients do.

**Default Key Type**: ECDSA

**Default Curve Bits**: P-256

We've chosen the AES encryption algorithm (aka Rijndael) for writing private
keys to disk because it was the official choice of the Advanced
Encryption Standard contest. The three supported key sizes are 128, 192, and
256. Each of these is considered to be unbreakable for the forseeable future,
therefore we chose 128 bits as our default because the performance is
better (as compared to the greater key sizes) and because we agree, with
the designers of the algorithm, that 128 bits are quite sufficient for
most security needs.

**Default PEMCipher**: AES128

## X.509 Certificate Defaults

### Root Certificate

* Validity (10 year window)
  * **Not Before**: Now

  * **Not After**: Now + 10 years

    A 10 year window seems advisable until software and tools can be written
    for rotating the root certificate.

* **Basic Constraints**
  * **CA**: TRUE

    The root certificate is a Certificate Authority, it will be used to sign
    other Certificates.

  * **pathlen**: 1

    The path length constraint expresses the number of possible intermediate
    CA certificates in a path built from an end-entity certificate up to the
    CA certificate. An absent path length constraint means that there is no
    limitation to the number of intermediate certificates from end-entity to
    the CA certificate. The smallstep PKI has only one intermediate CA
    certificate between end-entity certificates and the root CA certificcate.

* **Key Usage** describes how the certificate can be used.
  * **Certificate Sign**

    Indicates that our root public key will be used to verify a signature on
    certificates.

  * **CRL Sign**

    Indicates that our root public key will be used to verify a signature on
    revocation information, such as CRL.

### Intermediate Certificate

* Validity (10 year window)
  * **Not Before**: Now
  * **Not After**: Now + 10 years

    A 10 year window seems advisable until software and tools can be written
    for rotating the root certificate.

* **Basic Constraints**
  * **CA**: TRUE

    The intermediate certificate is a Certificate Authority, used to sign
    end-entity (service, process, job, etc.) certificates.
  * **pathlen**: 0

    The path length constraint expresses the number of possible intermediate
    CA certificates in a path built from an end-entity certificate up to the
    CA certificate. An absent path length constraint means that there is no
    limitation to the number of intermediate certificates from end-entity to
    the CA certificate. There are no additional intermediary certificates in
    the path between the smallstep intermediate CA and end-entity certificates.

* **Key Usage**
  * **Certificate Signing**

    Indicates that our the intermediate private key can be used to sign
    certificate requests.

  * **CRL Sign**

    Indicates that this public key can be used to verify a signature on
    revocation information, such as CRL.

### Leaf Certificate - End Entity Certificate (certificates returned by the CA)

* Validity (24 hour window)
  * **Not Before**: Now
  * **Not After**: Now + 24 hours

    The default is a 24hr window. This value is somewhat arbitrary, however,
    our goal is to have seamless end-entity certificate rotation (we are
    getting close). Rotating certificates frequently is good security hygiene
    because it gives bad actors very little time to form an attack and limits
    the usefulness of any single private key in the system. We will continue
    to work towards decreasing this window because we believe it significantly
    reduces probability and effectiveness of any attack.

* **Key Usage**
  * **Key Encipherment**

    Indicates that a certificate will be used with a protocol that encrypts keys.

  * **Digital Signature**

    Indicates that this public key may be used as a digital signature to
    support security services that enable entity authentication and data
    origin authentication with integrity.

* **Extended Key Usage**
  * **TLS Web Server Authentication**

    Certificate can be used as the server side certificate in the TLS protocol.

  * **TLS Web Client Authentication**

    Certificate can be used as the client side certificate in the TLS protocol.

## Default TLS Configuration Options

* **Min TLS Version**: TLS 1.2
* **Max TLS Version**: TLS 1.2

  The PCI Security Standards Council required all payment processors
  and merchants to move to TLS 1.2 and above by June 30, 2018. By setting
  TLS 1.2 as the default for all tls protocol negotiation we encourage our
  users to adopt the same security conventions.

* **Default Cipher Suites**:

  ```
  [
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
  ]
  ```

  The default 'ciphersuites' are a list of two cipher combinations. For
  communication between services running step there is no need for cipher suite
  negotiation. The server can specify a single cipher suite which the client is
  already known to support.

  Reasons for selecting `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305`:
  * ECDHE key exchange algorithm has perfect forward secrecy
  * ECDSA has smaller keys and better performance (than RSA)
  * CHACHA20 with POLY1305 is the cipher mode used by google.
  * CHACHA20's performance is better than GCM and CBC.


  The http2 spec requires the `TLS_ECDHE_(RSA|ECDSA)_WITH_AES_128_GCM_SHA256`
  ciphersuite be accepted by the server, therefore it makes our list of
  default ciphersuites until we build the functionality to modify our defaults
  based on http version.

* **Approved Cipher Suites**:

  ```
  [
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
  ]
  ```

  Above is a list of step approved cipher suites. Not all communication
  can be mediated with step TLS functionality. For those connections the list of
  server supported cipher suites must have more options - in case older clients
  do not support our favored cipher suite.

  Reasons for selecting these cipher suites can be found in the following
  [ssllabs article](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices#23-use-secure-cipher-suites).

* **Renegotation**: Never

  TLS renegotiation significantly complicates the state machine and has been
  the source of numerous, subtle security issues. Therefore, by default we
  disable it.
