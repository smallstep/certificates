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

### [x.y.z] - unreleased

### Changed

- Upgrade HSM-enabled Docker images from Debian Bookworm (12) to Debian Trixie
  (13) (smallstep/certificates#2493)
- Use JSON array format for Dockerfile's `CMD` instruction. This prevents shell
  interpolation of environment variables like `CONFIGPATH` and `PWDPATH`,
  ensuring consistent command execution. Commands can still be overridden via
  Kubernetes or Docker configuration when needed (smallstep/certificates#2493)

## [0.29.0] - 2025-12-03

### Added

- Add support for YubiKeys 5.7.4+ (smallstep/certificates#2370)
- Support managed device ID OID for step attestation format (smallstep/certificates#2382)
- Add support for remote configuration of GCP Organization-Id (smallstep/certificates#2408)
- Add additional DOCKER_STEPCA_INIT_* envs for docker/entrypoint.sh (smallstep/certificates#2461)
- Add sd_notify support (smallstep/certificates#2463)

### Changed

- Use errgroup to shutdown services concurrently (smallstep/certificates#2343)

### Deprecated

### Removed

### Fixed

- Fix process hanging after SIGTERM (smallstep/certificates#2338)
- Disable execute permission on a few policy/engine source files (smallstep/certificates#2435)
- Fix backdate support for ACME provisioner (smallstep/certificates#2444)

### Security


## [0.28.4] - 2025-07-13

### Added

- Add support for using key usage, extended key usage, and basic constraints
  from certificate requests in certificate templates (smallstep/crypto#767)
- Allow to specify audience when generating JWK provisioner tokens (smallstep/certificates#2326)
- Add SSH certificate type to exposed metrics (smallstep/certificates#2290)
- Enable dynamic validation of project ownership within a GCP organization
  when using the GCP Cloud Instance Identity provisioner (smallstep/certificates#2133)

### Changed

- Introduce poolhttp package for improved memory performance of Authority
  httpClients (smallstep/certificates#2325)


## [0.28.3] - 2025-03-17

- dependabot updates


## [0.28.2] - 2025-02-20

### Added

- Added support for imported keys on YubiKey (smallstep/certificates#2113)
- Enable storing ACME attestation payload (smallstep/certificates#2114)
- Add ACME attestation format field to ACME challenge (smallstep/certificates#2124)

### Changed

- Added internal httptransport package to replace cloning of http.DefaultTransport (smallstep/certificates#2098, smallstep/certificates#2103, smallstep/certificates#2104)
  - For example, replacing http.DefaultTransport clone in provisioner webhook business logic.


## [0.28.1] - 2024-11-19

### Added

- Support for using template data from SCEPCHALLENGE webhooks (smallstep/certificates#2065)
- New field to Webhook response that allows for propagation of human readable errors to the client (smallstep/certificates#2066, smallstep/certificates#2069)
- CICD for pushing DEB and RPM packages to packages.smallstep.com on releases (smallstep/certificates#2076)
- PKCS11 utilities in HSM container image (smallstep/certificates#2077)

### Changed

- Artifact names for RPM and DEB packages in conformance with standards (smallstep/certificates#2076)


## [0.28.0] - 2024-10-29

### Added

- Add options to GCP IID provisioner to enable or disable signing of SSH user and host certificates (smallstep/certificates#2045)

### Changed

- For IID provisioners with disableCustomSANs set to true, validate that the
  requested DNS names are a subset of the allowed DNS names (based on the IID token),
  rather than requiring an exact match to the entire list of allowed DNS names. (smallstep/certificates#2044)


## [0.27.5] - 2024-10-17

### Added

- Option to log real IP (x-forwarded-for) in logging middleware (smallstep/certificates#2002)

### Fixed

- Pulled in updates to smallstep/pkcs7 to fix failing Windows SCEP enrollment certificates (smallstep/certificates#1994)


## [0.27.4] - 2024-09-13

### Fixed

- Release worfklow

## [0.27.3] - 2024-09-13

### Added

- AWS auth method for Vault RA mode (smallstep/certificates#1976)
- API endpoints for retrieving Intermediate certificates (smallstep/certificates#1962)
- Enable use of OIDC provisioner with private identity providers and a certificate from step-ca (smallstep/certificates#1940)
- Support for verifying `cnf` and `x5rt#S256` claim when provided in token (smallstep/certificates#1660)
- Add Wire integration to ACME provisioner (smallstep/certificates#1666)

### Changed

- Clarified SSH certificate policy errors (smallstep/certificates#1951)

### Fixed

- Nebula ECDSA P-256 support (smallstep/certificates#1662)

## [0.27.2] - 2024-07-18

### Added

- `--console` option to default step-ssh config (smallstep/certificates#1931)


## [0.27.1] - 2024-07-12

### Changed

- Enable use of strict FQDN with a flag (smallstep/certificates#1926)
    - This reverses a change in 0.27.0 that required the use of strict FQDNs (smallstep/certificate#1910)


## [0.27.0] - 2024-07-11

### Added

- Support for validity windows in templates (smallstep/certificates#1903)
- Create identity certificate with host URI when using any provisioner (smallstep/certificates#1922)

### Changed

- Do strict DNS lookup on ACME (smallstep/certificates#1910)

### Fixed

- Handle bad attestation object in deviceAttest01 validation (smallstep/certificates#1913)


## [0.26.2] - 2024-06-13

### Added

- Add provisionerID to ACME accounts (smallstep/certificates#1830)
- Enable verifying ACME provisioner using provisionerID if available (smallstep/certificates#1844)
- Add methods to Authority to get intermediate certificates (smallstep/certificates#1848)
- Add GetX509Signer method (smallstep/certificates#1850)

### Changed

- Make ISErrNotFound more flexible (smallstep/certificates#1819)
- Log errors using slog.Logger (smallstep/certificates#1849)
- Update hardcoded AWS certificates (smallstep/certificates#1881)


## [0.26.1] - 2024-04-22

### Added

- Allow configuration of a custom SCEP key manager (smallstep/certificates#1797)

### Fixed

- id-scep-failInfoText OID (smallstep/certificates#1794)
- CA startup with Vault RA configuration (smallstep/certificates#1803)


## [0.26.0] - 2024-03-28

### Added

- [TPM KMS](https://github.com/smallstep/crypto/tree/master/kms/tpmkms) support for CA keys (smallstep/certificates#1772)
- Propagation of HTTP request identifier using X-Request-Id header (smallstep/certificates#1743, smallstep/certificates#1542)
- Expires header in CRL response (smallstep/certificates#1708)
- Support for providing TLS configuration programmatically (smallstep/certificates#1685)
- Support for providing external CAS implementation (smallstep/certificates#1684)
- AWS `ca-west-1` identity document root certificate (smallstep/certificates#1715)
- [COSE RS1](https://www.rfc-editor.org/rfc/rfc8812.html#section-2) as a supported algorithm with ACME `device-attest-01` challenge (smallstep/certificates#1663)

### Changed

- In an RA setup, let the CA decide the RA certificate lifetime (smallstep/certificates#1764)
- Use Debian Bookworm in Docker containers (smallstep/certificates#1615)
- Error message for CSR validation (smallstep/certificates#1665)
- Updated dependencies

### Fixed

- Stop CA when any of the required servers fails to start (smallstep/certificates#1751). Before the fix, the CA would continue running and only log the server failure when stopped.
- Configuration loading errors when not using context were not returned. Fixed in [cli-utils/109](https://github.com/smallstep/cli-utils/pull/109).
- HTTP_PROXY and HTTPS_PROXY support for ACME validation client (smallstep/certificates#1658).

### Security

- Upgrade to using cosign v2 for signing artifacts

## [0.25.1] - 2023-11-28

### Added

- Provisioner name in SCEP webhook request body in (smallstep/certificates#1617)
- Support for ASN1 boolean encoding in (smallstep/certificates#1590)

### Changed

- Generation of first provisioner name on `step ca init` in (smallstep/certificates#1566)
- Processing of SCEP Get PKIOperation requests in (smallstep/certificates#1570)
- Support for signing identity certificate during SSH sign by skipping URI validation in (smallstep/certificates#1572)
- Dependency on `micromdm/scep` and `go.mozilla.org/pkcs7` to use Smallstep forks in (smallstep/certificates#1600)
- Make the Common Name validator for JWK provisioners accept values from SANs too in (smallstep/certificates#1609)

### Fixed

- Registration Authority token creation relied on values from CSR. Fixed to rely on template in (smallstep/certificates#1608)
- Use same glibc version for running the CA when built using CGo in (smallstep/certificates#1616)

## [0.25.0] - 2023-09-26

### Added

- Added support for configuring SCEP decrypters in the provisioner (smallstep/certificates#1414)
- Added support for TPM KMS (smallstep/crypto#253)
- Added support for disableSmallstepExtensions provisioner claim
  (smallstep/certificates#1484)
- Added script to migrate a badger DB to MySQL or PostgreSQL
  (smallstep/certificates#1477)
- Added AWS public certificates for me-central-1 and ap-southeast-3
  (smallstep/certificates#1404)
- Added namespace field to VaultCAS JSON config (smallstep/certificates#1424)
- Added AWS public certificates for me-central-1 and ap-southeast-3
  (smallstep/certificates#1404)
- Added unversioned filenames to Github release assets
  (smallstep/certificates#1435)
- Send X5C leaf certificate to webhooks (smallstep/certificates#1485)
- Added support for disableSmallstepExtensions claim (smallstep/certificates#1484)
- Added all AWS Identity Document Certificates (smallstep/certificates#1404, smallstep/certificates#1510)
- Added Winget release automation (smallstep/certificates#1519)
- Added CSR to SCEPCHALLENGE webhook request body (smallstep/certificates#1523)
- Added SCEP issuance notification webhook (smallstep/certificates#1544)
- Added ability to disable color in the log text formatter
  (smallstep/certificates(#1559)

### Changed

- Changed the Makefile to produce cgo-enabled builds running
  `make build GO_ENVS="CGO_ENABLED=1"` (smallstep/certificates#1446)
- Return more detailed errors to ACME clients using device-attest-01
  (smallstep/certificates#1495)
- Change SCEP password type to string (smallstep/certificates#1555)

### Removed

- Removed OIDC user regexp check (smallstep/certificates#1481)
- Removed automatic initialization of $STEPPATH (smallstep/certificates#1493)
- Removed db datasource from error msg to prevent leaking of secrets to logs
  (smallstep/certificates#1528)

### Fixed

- Improved authentication for ACME requests using kid and provisioner name
  (smallstep/certificates#1386).
- Fixed indentation of KMS configuration in helm charts
  (smallstep/certificates#1405)
- Fixed simultaneous sign or decrypt operation on a YubiKey
  (smallstep/certificates#1476, smallstep/crypto#288)
- Fixed adding certificate templates with ASN.1 functions
  (smallstep/certificates#1500, smallstep/crypto#302)
- Fixed a problem when the ca.json is truncated if the encoding of the
  configuration fails (e.g., new provisioner with bad template data)
  (smallstep/cli#994, smallstep/certificates#1501)
- Fixed provisionerOptionsToLinkedCA missing template and templateData
  (smallstep/certificates#1520)
- Fix calculation of webhook signature (smallstep/certificates#1546)

## [v0.24.2] - 2023-05-11

### Added

- Log SSH certificates (smallstep/certificates#1374)
- CRL endpoints on the HTTP server (smallstep/certificates#1372)
- Dynamic SCEP challenge validation using webhooks (smallstep/certificates#1366)
- For Docker deployments, added DOCKER_STEPCA_INIT_PASSWORD_FILE. Useful for pointing to a Docker Secret in the container (smallstep/certificates#1384)

### Changed

- Depend on [smallstep/go-attestation](https://github.com/smallstep/go-attestation) instead of [google/go-attestation](https://github.com/google/go-attestation)
- Render CRLs into http.ResponseWriter instead of memory (smallstep/certificates#1373)
- Redaction of SCEP static challenge when listing provisioners (smallstep/certificates#1204)

### Fixed

- VaultCAS certificate lifetime (smallstep/certificates#1376)

## [v0.24.1] - 2023-04-14

### Fixed

- Docker image name for HSM support (smallstep/certificates#1348)

## [v0.24.0] - 2023-04-12

### Added

- Add ACME `device-attest-01` support with TPM 2.0
  (smallstep/certificates#1063).
- Add support for new Azure SDK, sovereign clouds, and HSM keys on Azure KMS
  (smallstep/crypto#192, smallstep/crypto#197, smallstep/crypto#198,
  smallstep/certificates#1323, smallstep/certificates#1309).
- Add support for ASN.1 functions on certificate templates
  (smallstep/crypto#208, smallstep/certificates#1345)
- Add `DOCKER_STEPCA_INIT_ADDRESS` to configure the address to use in a docker
  container (smallstep/certificates#1262).
- Make sure that the CSR used matches the attested key when using AME
  `device-attest-01` challenge (smallstep/certificates#1265).
- Add support for compacting the Badger DB (smallstep/certificates#1298).
- Build and release cleanups (smallstep/certificates#1322,
  smallstep/certificates#1329, smallstep/certificates#1340).

### Fixed

- Fix support for PKCS #7 RSA-OAEP decryption through
  [smallstep/pkcs7#4](https://github.com/smallstep/pkcs7/pull/4), as used in
  SCEP.
- Fix RA installation using `scripts/install-step-ra.sh`
  (smallstep/certificates#1255).
- Clarify error messages on policy errors (smallstep/certificates#1287,
  smallstep/certificates#1278).
- Clarify error message on OIDC email validation (smallstep/certificates#1290).
- Mark the IDP critical in the generated CRL data (smallstep/certificates#1293).
- Disable database if CA is initialized with the `--no-db` flag
  (smallstep/certificates#1294).

## [v0.23.2] - 2023-02-02

### Added

- Added [`step-kms-plugin`](https://github.com/smallstep/step-kms-plugin) to
  docker images, and a new image, `smallstep/step-ca-hsm`, compiled with cgo
  (smallstep/certificates#1243).
- Added [`scoop`](https://scoop.sh) packages back to the release
  (smallstep/certificates#1250).
- Added optional flag `--pidfile` which allows passing a filename where step-ca
  will write its process id (smallstep/certificates#1251).
- Added helpful message on CA startup when config can't be opened
  (smallstep/certificates#1252).
- Improved validation and error messages on `device-attest-01` orders
  (smallstep/certificates#1235).

### Removed

- The deprecated CLI utils `step-awskms-init`, `step-cloudkms-init`,
  `step-pkcs11-init`, `step-yubikey-init` have been removed.
  [`step`](https://github.com/smallstep/cli) and
  [`step-kms-plugin`](https://github.com/smallstep/step-kms-plugin) should be
  used instead (smallstep/certificates#1240).

### Fixed

- Fixed remote management flags in docker images (smallstep/certificates#1228).

## [v0.23.1] - 2023-01-10

### Added

- Added configuration property `.crl.idpURL`  to be able to set a custom Issuing
  Distribution Point in the CRL (smallstep/certificates#1178).
- Added WithContext methods to the CA client (smallstep/certificates#1211).
- Docker: Added environment variables for enabling Remote Management and ACME
  provisioner (smallstep/certificates#1201).
- Docker: The entrypoint script now generates and displays an initial JWK
  provisioner password by default when the CA is being initialized
  (smallstep/certificates#1223).

### Changed

- Ignore SSH principals validation when using an OIDC provisioner. The
  provisioner will ignore the principals passed and set the defaults or the ones
  including using WebHooks or templates (smallstep/certificates#1206).

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
