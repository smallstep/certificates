# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## TEMPLATE -- do not alter or remove

---

## [x.y.z] - aaaa-bb-cc

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security

---

## [Unreleased]

### Added

- Added configuration property `.crl.idpURL`  to be able to set a custom Issuing
  Distribution Point in the CRL.

## [v0.23.0] - 2022-11-11

### Added

- Added support for ACME device-attest-01 challenge on iOS, iPadOS, tvOS and
  YubiKey.
- Ability to disable ACME challenges and attestation formats.
- Added flags to change ACME challenge ports for testing purposes.
- Added name constraints evaluation and enforcement when issuing or renewing
  X.509 certificates.
- Added provisioner webhooks for augmenting template data and authorizing
  certificate requests before signing.
- Added automatic migration of provisioners when enabling remote management.
- Added experimental support for CRLs.
- Add certificate renewal support on RA mode. The `step ca renew` command must
  use the flag `--mtls=false` to use the token renewal flow.
- Added support for initializing remote management using `step ca init`.
- Added support for renewing X.509 certificates on RAs.
- Added support for using SCEP with keys in a KMS.
- Added client support to set the dialer's local address with the environment variable
  `STEP_CLIENT_ADDR`.

### Changed

- Remove the email requirement for issuing SSH certificates with an OIDC
  provisioner.
- Root files can contain more than one certificate.

### Fixed

- Fixed MySQL DSN parsing issues with an upgrade to
  [smallstep/nosql@v0.5.0](https://github.com/smallstep/nosql/releases/tag/v0.5.0).
- Fixed renewal of certificates with missing subject attributes.
- Fixed ACME support with [ejabberd](https://github.com/processone/ejabberd).

### Deprecated

- The CLIs `step-awskms-init`, `step-cloudkms-init`, `step-pkcs11-init`,
  `step-yubikey-init` are deprecated. Now you can use
  [`step-kms-plugin`](https://github.com/smallstep/step-kms-plugin) in
  combination with `step certificates create` to initialize your PKI.

## [0.22.1] - 2022-08-31

### Fixed

- Fixed signature algorithm on EC (root) + RSA (intermediate) PKIs.

## [0.22.0] - 2022-08-26

### Added

- Added automatic configuration of Linked RAs.
- Send provisioner configuration on Linked RAs.

### Changed

- Certificates signed by an issuer using an RSA key will be signed using the
  same algorithm used to sign the issuer certificate. The signature will no
  longer default to PKCS #1. For example, if the issuer certificate was signed
  using RSA-PSS with SHA-256, a new certificate will also be signed using
  RSA-PSS with SHA-256.
- Support two latest versions of Go (1.18, 1.19).
- Validate revocation serial number (either base 10 or prefixed with an
  appropriate base).
- Sanitize TLS options.

## [0.20.0] - 2022-05-26

### Added

- Added Kubernetes auth method for Vault RAs.
- Added support for reporting provisioners to linkedca.
- Added support for certificate policies on authority level.
- Added a Dockerfile with a step-ca build with HSM support.
- A few new WithXX methods for instantiating authorities

### Changed

- Context usage in HTTP APIs.
- Changed authentication for Vault RAs.
- Error message returned to client when authenticating with expired certificate.
- Strip padding from ACME CSRs.

### Deprecated

- HTTP API handler types.

### Fixed

- Fixed SSH revocation.
- CA client dial context for js/wasm target.
- Incomplete `extraNames` support in templates.
- SCEP GET request support.
- Large SCEP request handling.

## [0.19.0] - 2022-04-19

### Added

- Added support for certificate renewals after expiry using the claim `allowRenewalAfterExpiry`.
- Added support for `extraNames` in X.509 templates.
- Added `armv5` builds.
- Added RA support using a Vault instance as the CA.
- Added `WithX509SignerFunc` authority option.
- Added a new `/roots.pem` endpoint to download the CA roots in PEM format.
- Added support for Azure `Managed Identity` tokens.
- Added support for automatic configuration of linked RAs.
- Added support for the `--context` flag. It's now possible to start the
  CA with `step-ca --context=abc` to use the configuration from context `abc`.
  When a context has been configured and no configuration file is provided
  on startup, the configuration for the current context is used.
- Added startup info logging and option to skip it (`--quiet`).
- Added support for renaming the CA (Common Name).

### Changed

- Made SCEP CA URL paths dynamic.
- Support two latest versions of Go (1.17, 1.18).
- Upgrade go.step.sm/crypto to v0.16.1.
- Upgrade go.step.sm/linkedca to v0.15.0.

### Deprecated

- Go 1.16 support.

### Removed

### Fixed

- Fixed admin credentials on RAs.
- Fixed ACME HTTP-01 challenges for IPv6 identifiers.
- Various improvements under the hood.

### Security

## [0.18.2] - 2022-03-01

### Added

- Added `subscriptionIDs` and `objectIDs` filters to the Azure provisioner.
- [NoSQL](https://github.com/smallstep/nosql/pull/21) package allows filtering
  out database drivers using Go tags. For example, using the Go flag
  `--tags=nobadger,nobbolt,nomysql` will only compile `step-ca` with the pgx
  driver for PostgreSQL.

### Changed

- IPv6 addresses are normalized as IP addresses instead of hostnames.
- More descriptive JWK decryption error message.
- Make the X5C leaf certificate available to the templates using `{{ .AuthorizationCrt }}`.

### Fixed

- During provisioner add - validate provisioner configuration before storing to DB.

## [0.18.1] - 2022-02-03

### Added

- Support for ACME revocation.
- Replace hash function with an RSA SSH CA to "rsa-sha2-256".
- Support Nebula provisioners.
- Example Ansible configurations.
- Support PKCS#11 as a decrypter, as used by SCEP.

### Changed

- Automatically create database directory on `step ca init`.
- Slightly improve errors reported when a template has invalid content.
- Error reporting in logs and to clients.

### Fixed

- SCEP renewal using HTTPS on macOS.

## [0.18.0] - 2021-11-17

### Added

- Support for multiple certificate authority contexts.
- Support for generating extractable keys and certificates on a pkcs#11 module.

### Changed

- Support two latest versions of Go (1.16, 1.17)

### Deprecated

- go 1.15 support

## [0.17.6] - 2021-10-20

### Notes

- 0.17.5 failed in CI/CD

## [0.17.5] - 2021-10-20

### Added

- Support for Azure Key Vault as a KMS.
- Adapt `pki` package to support key managers.
- gocritic linter

### Fixed

- gocritic warnings

## [0.17.4] - 2021-09-28

### Fixed

- Support host-only or user-only SSH CA.

## [0.17.3] - 2021-09-24

### Added

- go 1.17 to github action test matrix
- Support for CloudKMS RSA-PSS signers without using templates.
- Add flags to support individual passwords for the intermediate and SSH keys.
- Global support for group admins in the OIDC provisioner.

### Changed

- Using go 1.17 for binaries

### Fixed

- Upgrade go-jose.v2 to fix a bug in the JWK fingerprint of Ed25519 keys.

### Security

- Use cosign to sign and upload signatures for multi-arch Docker container.
- Add debian checksum

## [0.17.2] - 2021-08-30

### Added

- Additional way to distinguish Azure IID and Azure OIDC tokens.

### Security

- Sign over all goreleaser github artifacts using cosign

## [0.17.1] - 2021-08-26

## [0.17.0] - 2021-08-25

### Added

- Add support for Linked CAs using protocol buffers and gRPC
- `step-ca init` adds support for
  - configuring a StepCAS RA
  - configuring a Linked CA
  - congifuring a `step-ca` using Helm

### Changed

- Update badger driver to use v2 by default
- Update TLS cipher suites to include 1.3

### Security

- Fix key version when SHA512WithRSA is used. There was a typo creating RSA keys with SHA256 digests instead of SHA512.
