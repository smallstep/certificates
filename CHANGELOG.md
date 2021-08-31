# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased - 0.17.3] - DATE
### Added
### Changed
### Deprecated
### Removed
### Fixed
### Security

## [0.17.2] - 08.30.2021
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

