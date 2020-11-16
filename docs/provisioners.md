# Provisioners

> Note: The canonical documentation for `step-ca` provisioners now lives at
> https://smallstep.com/docs/step-ca/configuration#provisioners. Documentation
> found on this page may be out of date.

Provisioners are people or code that are registered with the CA and authorized
to issue "provisioning tokens". Provisioning tokens are single-use tokens that
can be used to authenticate with the CA and get a certificate.

See `step ca provisioner add --help` for documentation and examples on adding
provisioners.

> Attn: We strongly recommend using the `step ca provisioner add ...`
> utility to generate provisioners in your `ca.json` configuration. We often
> encode fields differently in the JSON than you might expect. And you can
> always come in and modify the configuration manually after using the utility.

## Claims

Each provisioner can define an optional `claims` attribute. The settings in this
attribute override any settings in the global `claims` attribute in the authority
configuration.

Example `claims`:

```
    ...
    "claims": {
        "minTLSCertDuration": "5m",
        "maxTLSCertDuration": "24h",
        "defaultTLSCertDuration": "24h",
        "disableRenewal": false,
        "minHostSSHCertDuration": "5m",
        "maxHostSSHCertDuration": "1680h",
        "defaultHostSSHCertDuration": "720h",
        "minUserSSHCertDuration": "5m",
        "maxUserSSHCertDuration": "24h",
        "defaultUserSSHCertDuration": "16h",
        "enableSSHCA": true
    },
    ...
```

* `claims` (optional): overwrites the default claims set in the authority.
  You can set one or more of the following claims:

  * `minTLSCertDuration`: do not allow certificates with a duration less than
    this value.

  * `maxTLSCertDuration`: do not allow certificates with a duration greater than
    this value.

  * `defaultTLSCertDuration`: if no certificate validity period is specified,
    use this value.

  * `disableIssuedAtCheck`: disable a check verifying that provisioning tokens
    must be issued after the CA has booted. This claim is one prevention against
    token reuse. The default value is `false`. Do not change this unless you
    know what you are doing.

  SSH CA properties

  * `minUserSSHCertDuration`: do not allow certificates with a duration less
  than this value.

  * `maxUserSSHCertDuration`: do not allow certificates with a duration
  greater than this value.

  * `defaultUserSSHCertDuration`: if no certificate validity period is specified,
  use this value.

  * `minHostSSHCertDuration`: do not allow certificates with a duration less
  than this value.

  * `maxHostSSHCertDuration`: do not allow certificates with a duration
  greater than this value.

  * `defaultHostSSHCertDuration`: if no certificate validity period is specified,
  use this value.

  * `enableSSHCA`: enable all provisioners to generate SSH Certificates.
  The deault value is `false`. You can enable this option per provisioner
  by setting it to `true` in the provisioner claims.

## Provisioner Types

Each provisioner has a different method of authentication with the CA.

  - A JWK provisioner uses a JWT signed by a JWK.
  - An OIDC provisioner uses a OIDC token signed by an Identity Provider e.g. Google, Okta, Azure.
  - An AWS provisioner uses an Instance Identity Document signed by AWS.
  - etc.

### Capabilities by Type

Provisioners are used to authenticate certificate signing requests, and every
provisioner has a slightly different scope of authorization. Below is a table
detailing the authorization capabilities of each provisioner.

Provisioner Capabilities| x509-sign | x509-renew | x509-revoke | ssh-user-cert-sign | ssh-host-cert-sign | ssh-user-cert-renew | ssh-host-cert-renew | ssh-revoke | ssh-rekey
----------- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-:
JWK    | ✔️  | ✔️  | ✔️  | ✔️  | ✔️  | 𝗫 | 𝗫 | ✔️  | 𝗫
OIDC   | ✔️  | ✔️  | ✔️  | ✔️  | ✔️ <sup id="a1">[1](#f1)</sup> | 𝗫 | 𝗫 | ✔️  | 𝗫
X5C    | ✔️  | ✔️  | ✔️  | ✔️  | ✔️  | 𝗫 | 𝗫 | 𝗫 | 𝗫
K8sSA  | ✔️  | ✔️  | ✔️  | ✔️  | ✔️  | 𝗫 | 𝗫 | 𝗫 | 𝗫
ACME   | ✔️  | ✔️  | 𝗫 | 𝗫 | 𝗫 | 𝗫 | 𝗫 | 𝗫 | 𝗫
SSHPOP | 𝗫 | 𝗫 | 𝗫 | 𝗫 | 𝗫 | 𝗫 | ✔️  | ✔️  | ✔️
AWS    | ✔️  | ✔️  | 𝗫 | 𝗫 | ✔️  | 𝗫 | 𝗫 | 𝗫 | 𝗫
Azure  | ✔️  | ✔️  | 𝗫 | 𝗫 | ✔️  | 𝗫 | 𝗫 | 𝗫 | 𝗫
GCP    | ✔️  | ✔️  | 𝗫 | 𝗫 | ✔️  | 𝗫 | 𝗫 | 𝗫 | 𝗫

<b id="f1">1</b> Admin OIDC users can generate Host SSH Certificates. Admins can be configured in the OIDC provisioner. [↩](#a1)

### JWK

JWK is the default provisioner type. It uses public-key cryptography to sign and
validate a JSON Web Token (JWT).

The [step](https://github.com/smallstep/cli) CLI tool will create a JWK
provisioner when `step ca init` is used, and it also contains commands to add
(`step ca provisioner add`) and remove (`step ca provisioner remove`) JWK
provisioners.

In the ca.json configuration file, a complete JWK provisioner example looks like:

```json
{
    "type": "JWK",
    "name": "you@smallstep.com",
    "key": {
        "use": "sig",
        "kty": "EC",
        "kid": "NPM_9Gz_omTqchS6Xx9Yfvs-EuxkYo6VAk4sL7gyyM4",
        "crv": "P-256",
        "alg": "ES256",
        "x": "bBI5AkO9lwvDuWGfOr0F6ttXC-ZRzJo8kKn5wTzRJXI",
        "y": "rcfaqE-EEZgs34Q9SSH3f9Ua5a8dKopXNfEzDD8KRlU"
    },
    "encryptedKey": "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJjdHkiOiJqd2sranNvbiIsImVuYyI6IkEyNTZHQ00iLCJwMmMiOjEwMDAwMCwicDJzIjoiTlV6MjlEb3hKMVdOaFI3dUNjaGdYZyJ9.YN7xhz6RAbz_9bcuXoymBOj8bOg23ETAdmSCRyHpxGekkV0q3STYYg.vo1oBnZsZjgRu5Ln.Xop8AvZ74h_im2jxeaq-hYYWnaK_eF7MGr4xcZGodMUxp-hGPqS85oWkyprkQLYt1-jXTURfpejtmPeB4-sxgj7OFxMYYus84BdkG9BZgSBmMN9SqZItOv4pqg_NwQA0bv9g9A_e-N6QUFanxuYQsEPX_-IwWBDbNKyN9bXbpEQa0FKNVsTvFahGzOxQngXipi265VADkh8MJLjYerplKIbNeOJJbLd9CbS9fceLvQUNr3ACGgAejSaWmeNUVqbho1lY4882iS8QVx1VzjluTXlAMdSUUDHArHEihz008kCyF0YfvNdGebyEDLvTmF6KkhqMpsWn3zASYBidc9k._ch9BtvRRhcLD838itIQlw",
    "claims": {
        "minTLSCertDuration": "5m",
        "maxTLSCertDuration": "24h",
        "defaultTLSCertDuration": "24h",
        "disableRenewal": false,
        "minHostSSHCertDuration": "5m",
        "maxHostSSHCertDuration": "1680h",
        "minUserSSHCertDuration": "5m",
        "maxUserSSHCertDuration": "24h",
        "enableSSHCA": true
    }
}
```

* `type` (mandatory): for a JWK provisioner it must be `JWK`, this field is case
  insensitive.

* `name` (mandatory): identifies the provisioner, a good practice is to
  use an email address or a descriptive string that allows the identification of
  the owner, but it can be any non-empty string.

* `key` (mandatory): is the JWK (JSON Web Key) representation of a public key
  used to validate a signed token.

* `encryptedKey` (recommended): is the encrypted private key used to sign a
  token. It's a JWE compact string containing the JWK representation of the
  private key.

  We can use [step](https://github.com/smallstep/cli) to see the private key
  encrypted with the password `asdf`:

  ```sh
  $ echo ey...lw | step crypto jwe decrypt  | jq
  Please enter the password to decrypt the content encryption key:
  {
    "use": "sig",
    "kty": "EC",
    "kid": "NPM_9Gz_omTqchS6Xx9Yfvs-EuxkYo6VAk4sL7gyyM4",
    "crv": "P-256",
    "alg": "ES256",
    "x": "bBI5AkO9lwvDuWGfOr0F6ttXC-ZRzJo8kKn5wTzRJXI",
    "y": "rcfaqE-EEZgs34Q9SSH3f9Ua5a8dKopXNfEzDD8KRlU",
    "d": "rsjCCM_2FQ-uk7nywBEQHl84oaPo4mTpYDgXAu63igE"
  }
  ```

  If the ca.json does not contain the encryptedKey, the private key must be
  provided using the `--key` flag of the `step ca token` to be able to sign the
  token.

### OIDC

An OIDC provisioner allows a user to get a certificate after authenticating
himself with an OAuth OpenID Connect identity provider. The ID token provided
will be used on the CA authentication, and by default, the certificate will only
have the user's email as a Subject Alternative Name (SAN) Extension.

One of the most common providers and the one we'll use in the following example
is G-Suite.

```json
{
    "type": "OIDC",
    "name": "Google",
    "clientID": "1087160488420-8qt7bavg3qesdhs6it824mhnfgcfe8il.apps.googleusercontent.com",
    "clientSecret": "udTrOT3gzrO7W9fDPgZQLfYJ",
    "configurationEndpoint": "https://accounts.google.com/.well-known/openid-configuration",
    "admins": ["you@smallstep.com"],
    "domains": ["smallstep.com"],
    "listenAddress": ":10000",
    "claims": {
        "maxTLSCertDuration": "8h",
        "defaultTLSCertDuration": "2h",
        "disableRenewal": true
    }
}
```

* `type` (mandatory): indicates the provisioner type and must be `OIDC`.

* `name` (mandatory): a string used to identify the provider when the CLI is
  used.

* `clientID` (mandatory): the client id provided by the identity provider used
  to initialize the authentication flow.

* `clientSecret` (mandatory): the client secret provided by the identity
  provider used to get the id token. Some identity providers might use an empty
  string as a secret.

* `configurationEndpoint` (mandatory): is the HTTP address used by the CA to get
  the OpenID Connect configuration and public keys used to validate the tokens.

* `admins` (optional): is the list of emails that will be able to get
  certificates with custom SANs. If a user is not an admin, it will only be able
  to get a certificate with its email in it.

* `domains` (optional): is the list of domains valid. If provided only the
  emails with the provided domains will be able to authenticate.

* `listenAddress` (optional): is the loopback address (`:port` or `host:port`)
  where the authorization server will redirect to complete the authorization
  flow. If it's not defined `step` will use `127.0.0.1` with a random port. This
  configuration is only required if the authorization server doesn't allow any
  port to be specified at the time of the request for loopback IP redirect URIs.

* `claims` (optional): overwrites the default claims set in the authority, see
  the [top](#provisioners) section for all the options.

### X5C

An X5C provisioner allows a client to get an x509 or SSH certificate using
an existing x509 certificate that is trusted by the X5C provisioner.

An X5C provisioner is configured with a root certificate, supplied by the user,
at the time the provisioner is created. The X5C provisioner can authenticate
X5C tokens.

An X5C token is a JWT, signed by the certificate private key, with an `x5c`
header that contains the chain.

If you would like any certificate signed by `step-ca` to become a provisioner,
you can configure the X5C provisioner using the root certificate used by
`step-ca`, like so:

```
step ca provisioner add x5c-smallstep --type X5C --x5c-root $(step path)/certs/root_ca.crt
```

Or you can configure the X5C provisioner with an outside root, giving provisioner
capabilities to a completely separate PKI.

Below is an example of an X5C provisioner in the `ca.json`:

```json
...
{
    "type": "X5C",
    "name": "x5c",
    "roots": "LS0tLS1 ... Q0FURS0tLS0tCg==",
    "claims": {
        "maxTLSCertDuration": "8h",
        "defaultTLSCertDuration": "2h",
        "disableRenewal": true
    }
}
```

* `type` (mandatory): indicates the provisioner type and must be `X5C`.

* `name` (mandatory): a string used to identify the provider when the CLI is
  used.

* `roots` (mandatory): a base64 encoded list of root certificates used for
  validating X5C tokens.

* `claims` (optional): overwrites the default claims set in the authority, see
  the [top](#provisioners) section for all the options.

### SSHPOP

An SSHPOP provisioner allows a client to renew, revoke, or rekey an SSH
certificate using that certificate for authentication with the CA.
The renew and rekey methods can only be used on SSH host certificates.

An SSHPOP provisioner is configured with the user and host root ssh certificates
from the `ca.json`. The SSHPOP provisioner can only authenticate SSHPOP tokens
generated using SSH certificates created by `step-ca`.

An SSHPOP token is a JWT, signed by the certificate private key, with an `sshpop`
header that contains the SSH certificate.

Below is an example of an SSHPOP provisioner in the `ca.json`:

```json
...
{
    "type": "SSHPOP",
    "name": "sshpop-smallstep",
    "claims": {
		"enableSSHCA": true
	}
}
```

* `type` (mandatory): indicates the provisioner type and must be `SSHPOP`.

* `name` (mandatory): a string used to identify the provider when the CLI is
  used.

* `claims` (optional): overwrites the default claims set in the authority, see
  the [top](#provisioners) section for all the options.

### ACME

An ACME provisioner allows a client to request a certificate from the server
using the [ACME Protocol](https://tools.ietf.org/html/rfc8555). The ACME
provisioner can only request X509 certificates. All authentication of the CSR
is managed by the ACME protocol.

Below is an example of an ACME provisioner in the `ca.json`:

```json
...
{
    "type": "ACME",
    "name": "my-acme-provisioner",
    "forceCN": true,
    "claims": {
        "maxTLSCertDuration": "8h",
        "defaultTLSCertDuration": "2h",
	}
}
```

* `type` (mandatory): indicates the provisioner type and must be `ACME`.

* `name` (mandatory): a string used to identify the provider when the CLI is
  used.

* `forceCN` (optional): force one of the SANs to become the Common Name, if a
  common name is not provided.

* `claims` (optional): overwrites the default claims set in the authority, see
  the [top](#provisioners) section for all the options.

See our [`step-ca` ACME tutorial](https://app.smallstep.com/docs/[product]/tutorials/acme-provisioners)
for more guidance on configuring and using the ACME protocol with `step-ca`.

### K8sSA - Kubernetes Service Account

A K8sSA provisioner allows a client to request a certificate from the server
using a Kubernetes Service Account Token.

As of the time when this provisioner was coded, the Kubernetes Service Account
API for retrieving the token from a running instance was still in beta. Therefore,
our K8sSA provisioner must be configured with the public key that will be used
to validate K8sSA tokens.

K8sSA tokens are very minimal. There is no place for SANs, or other details that
a user may want validated in a CSR. It is essentially a bearer token. Therefore,
at this time a K8sSA token can be used to sign a CSR with any SANs. Said
differently, the **K8sSA provisioner does little to no validation on the CSR
before signing it**. You should only configure and use this provisioner if you
know what you are doing. If a malicious user obtains the private key they will
be able to create certificates with any SANs and Subject.

Below is an example of a K8sSA provisioner in the `ca.json`:

```json
...
{
    "type": "K8sSA",
    "name": "my-kube-provisioner",
    "publicKeys": "LS0tLS1...LS0tCg==",
    "claims": {
        "maxTLSCertDuration": "8h",
        "defaultTLSCertDuration": "2h",
    }
}
```

* `type` (mandatory): indicates the provisioner type and must be `K8sSA`.

* `name` (mandatory): a string used to identify the provider when the CLI is
  used.

* `publicKeys` (mandatory): a base64 encoded list of public keys used to validate
  K8sSA tokens.

* `claims` (optional): overwrites the default claims set in the authority, see
  the [top](#provisioners) section for all the options.

### Provisioners for Cloud Identities

[Step certificates](https://github.com/smallstep/certificates) can grant
certificates to code running in a machine without any other authentication than
the one provided by the cloud. Usually, this is implemented with some kind of
signed document, but the information contained on them might not be enough to
generate a certificate. Due to this limitation, the cloud identities use by
default a trust model called Trust On First Use (TOFU).

The Trust On First Use model allows the use of more permissive CSRs that can
have custom SANs that cannot be validated. But it comes with the limitation that
you can only grant a certificate once. After this first grant, the same machine
will need to renew the certificate using mTLS, and the CA will block any other
attempt to grant a certificate to that instance.

#### AWS

The AWS provisioner allows granting a certificate to an Amazon EC2 instance
using the [Instance Identity Documents](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html)

The [step](https://github.com/smallstep/cli) CLI will generate a custom JWT
token containing the instance identity document and its signature and the CA
will grant a certificate after validating it.

In the ca.json, an AWS provisioner looks like:

```json
{
    "type": "AWS",
    "name": "Amazon Web Services",
    "accounts": ["1234567890"],
    "disableCustomSANs": false,
    "disableTrustOnFirstUse": false,
    "instanceAge": "1h",
    "iidRoots": "/path/to/aws.crt",
    "claims": {
        "maxTLSCertDuration": "2160h",
        "defaultTLSCertDuration": "2160h"
    }
}
```

* `type` (mandatory): indicates the provisioner type and must be `AWS`.

* `name` (mandatory): a string used to identify the provider when the CLI is
  used.

* `accounts` (optional): the list of AWS account numbers that are allowed to use
  this provisioner. If none is specified, all AWS accounts will be valid.

* `disableCustomSANs` (optional): by default custom SANs are valid, but if this
  option is set to true only the SANs available in the instance identity
  document will be valid, these are the private IP and the DNS
  `ip-<private-ip>.<region>.compute.internal`.

* `disableTrustOnFirstUse` (optional): by default only one certificate will be
  granted per instance, but if the option is set to true this limit is not set
  and different tokens can be used to get different certificates.

* `instanceAge` (optional): the maximum age of an instance to grant a
  certificate. The instance age is a string using the duration format.

* `iidRoots` (optional): the path to one or more public certificates in PEM
  format used to validate the signature of the instance identity document.

* `claims` (optional): overwrites the default claims set in the authority, see
  the [top](#provisioners) section for all the options.

#### GCP

The GCP provisioner grants certificates to Google Compute Engine instance using
its [identity](https://cloud.google.com/compute/docs/instances/verifying-instance-identity)
token. The CA will validate the JWT and grant a certificate.

In the ca.json, a GCP provisioner looks like:

```json
{
    "type": "GCP",
    "name": "Google Cloud",
    "serviceAccounts": ["1234567890"],
    "projectIDs": ["project-id"],
    "disableCustomSANs": false,
    "disableTrustOnFirstUse": false,
    "instanceAge": "1h",
    "claims": {
        "maxTLSCertDuration": "2160h",
        "defaultTLSCertDuration": "2160h"
    }
}
```

* `type` (mandatory): indicates the provisioner type and must be `GCP`.

* `name` (mandatory): a string used to identify the provider when the CLI is
  used.

* `serviceAccounts` (optional): the list of service account numbers that are
  allowed to use this provisioner. If none is specified, all service accounts
  will be valid.

* `projectIDs` (optional): the list of project identifiers that are allowed to
  use this provisioner. If non is specified all project will be valid.

* `disableCustomSANs` (optional): by default custom SANs are valid, but if this
  option is set to true only the SANs available in the instance identity
  document will be valid, these are the DNS
  `<instance-name>.c.<project-id>.internal` and
  `<instance-name>.<zone>.c.<project-id>.internal`

* `disableTrustOnFirstUse` (optional): by default only one certificate will be
  granted per instance, but if the option is set to true this limit is not set
  and different tokens can be used to get different certificates.

* `instanceAge` (optional): the maximum age of an instance to grant a
  certificate. The instance age is a string using the duration format.

* `claims` (optional): overwrites the default claims set in the authority, see
  the [top](#provisioners) section for all the options.

#### Azure

The Azure provisioner grants certificates to Microsoft Azure instances using
the [managed identities tokens](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/how-to-use-vm-token).
The CA will validate the JWT and grant a certificate.

In the ca.json, an Azure provisioner looks like:

```json
{
    "type": "Azure",
    "name": "Microsoft Azure",
    "tenantId": "b17c217c-84db-43f0-babd-e06a71083cda",
    "resourceGroups": ["backend", "accounting"],
    "audience": "https://management.azure.com/",
    "disableCustomSANs": false,
    "disableTrustOnFirstUse": false,
    "claims": {
        "maxTLSCertDuration": "2160h",
        "defaultTLSCertDuration": "2160h"
    }
}
```

* `type` (mandatory): indicates the provisioner type and must be `Azure`.

* `name` (mandatory): a string used to identify the provider when the CLI is
  used.

* `tenantId` (mandatory): the Azure account tenant id for this provisioner. This
  id is the Directory ID available in the Azure Active Directory properties.

* `audience` (optional): defaults to `https://management.azure.com/` but it can
  be changed if necessary.

* `resourceGroups` (optional): the list of resource group names that are allowed
  to use this provisioner. If none is specified, all resource groups will be
  valid.

* `disableCustomSANs` (optional): by default custom SANs are valid, but if this
  option is set to true only the SANs available in the token will be valid, in
  Azure only the virtual machine name is available.

* `disableTrustOnFirstUse` (optional): by default only one certificate will be
  granted per instance, but if the option is set to true this limit is not set
  and different tokens can be used to get different certificates.

* `claims` (optional): overwrites the default claims set in the authority, see
  the [top](#provisioners) section for all the options.
