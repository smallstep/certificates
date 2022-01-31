# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased - 0.18.1] - DATE
### Added
- Support for ACME revocation.
- Replace hash function with an RSA SSH CA to "rsa-sha2-256".
### Changed
### Deprecated
### Removed
### Fixed
### Security

## [0.18.0] - 2021-11-17
### Added
- Support for multiple certificate authority contexts.
- Support for generating extractable keys and certificates on a pkcs#11 module.
### Changed
- Support two latest versions of golang (1.16, 1.17)
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
