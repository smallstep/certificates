# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased - 0.17.3] - DATE
### Added
- go 1.17 to github action test matrix
- Support for CloudKMS RSA-PSS signers without using templates.
- Add flags to support individual passwords for the intermediate and SSH keys.
- Support for group admins in OIDC provisioners for X509 certificates.
### Changed
- Using go 1.17 for binaries
### Deprecated
### Removed
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

