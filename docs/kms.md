# Key Management Services

This document describes how to use a key management service or KMS to store the
private keys and sign certificates.

Support for multiple KMS are planned, but currently the only Google's Cloud KMS,
and Amazon's AWS KMS are supported. A still experimental version for YubiKeys is
also available if you compile [step-ca](https://github.com/smallstep/certificates) 
yourself.

## Google's Cloud KMS

[Cloud KMS](https://cloud.google.com/kms) is the Google's cloud-hosted KMS that
allows you to store the cryptographic keys, and sign certificates using their
infrastructure. Cloud KMS supports two different protection levels, SOFTWARE and
HSM.

To configure Cloud KMS in your CA you need add the `"kms"` property to you
`ca.json`, and replace the property`"key"` with the Cloud KMS key name of your
intermediate key:

```json
{
    ...
    "key": "projects/<project-id>/locations/global/keyRings/<ring-id>/cryptoKeys/<key-id>/cryptoKeyVersions/<version-number>",
    ...
    "kms": {
        "type": "cloudkms",
        "credentialsFile": "path/to/credentials.json"
    }
}
```

In a similar way, for SSH certificate, the SSH keys must be Cloud KMS names:

```json
{
    ...
    "ssh": {
        "hostKey": "projects/<project-id>/locations/global/keyRings/<ring-id>/cryptoKeys/<key-id>/cryptoKeyVersions/<version-number>",
        "userKey": "projects/<project-id>/locations/global/keyRings/<ring-id>/cryptoKeys/<key-id>/cryptoKeyVersions/<version-number>"
    },
}
```

Currently [step](https://github.com/smallstep/cli) does not provide an automatic
way to initialize the public key infrastructure (PKI) using Cloud KMS, but an
experimental tool named `step-cloudkms-init` is available for this use case. At
some point this tool will be integrated into `step` and it will be deleted.

To use `step-cloudkms-init` just enable Cloud KMS in your project and run:

```sh
$ export GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json
$ step-cloudkms-init --project your-project-id --ssh
Creating PKI ...
✔ Root Key: projects/your-project-id/locations/global/keyRings/pki/cryptoKeys/root/cryptoKeyVersions/1
✔ Root Certificate: root_ca.crt
✔ Intermediate Key: projects/your-project-id/locations/global/keyRings/pki/cryptoKeys/intermediate/cryptoKeyVersions/1
✔ Intermediate Certificate: intermediate_ca.crt

Creating SSH Keys ...
✔ SSH User Public Key: ssh_user_ca_key.pub
✔ SSH User Private Key: projects/your-project-id/locations/global/keyRings/pki/cryptoKeys/ssh-user-key/cryptoKeyVersions/1
✔ SSH Host Public Key: ssh_host_ca_key.pub
✔ SSH Host Private Key: projects/your-project-id/locations/global/keyRings/pki/cryptoKeys/ssh-host-key/cryptoKeyVersions/1
```

See `step-cloudkms-init --help` for more options.

## AWS KMS

[AWS KMS](https://docs.aws.amazon.com/kms/index.html) is the Amazon's managed
encryption and key management service. It creates and store the cryptographic
keys, and use their infrastructure for signing operations. Amazon KMS operations
are always backed by hardware security modules (HSMs).

To configure AWS KMS in your CA you need add the `"kms"` property to you
`ca.json`, and replace the property`"key"` with the AWS KMS key name of your
intermediate key:

```json
{
    ...
    "key": "awskms:key-id=f879f239-feb6-4596-9ed2-b1606277c7fe",
    ...
    "kms": {
        "type": "awskms",
        "region": "us-east-1"
    }
}
```

By default it uses the credentials in `~/.aws/credentials`, but this can be
overridden using the `credentialsFile` option, `region` and `profile` can also
be configured as options. These can also be configured using environment
variables as described by their [session
docs](https://docs.aws.amazon.com/sdk-for-go/api/aws/session/).

To configure SSH certificate signing we do something similar, and replace the
ssh keys with the ones in the KMS:

```json
{
    ...
    "ssh": {
        "hostKey": "awskms:key-id=d48e502a-09bc-4bf7-9af8-ae1bccedc931",
        "userKey": "awskms:key-id=cf28e942-1e10-4a08-b84c-5359af1b5f12"
    },
}
```

The keys can also be just the Amazon's Key ID or the ARN, but using the format
based on the [RFC7512](https://tools.ietf.org/html/rfc7512) will allow more
flexibility for future releases of `step`.

Currently [step](https://github.com/smallstep/cli) does not provide an automatic
way to initialize the public key infrastructure (PKI) using AWS KMS, but an
experimental tool named `step-awskms-init` is available for this use case. At
some point this tool will be integrated into `step` and it will be deleted.

To use `step-awskms-init` make sure to have to have your [environment
configured](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)
running `aws configure` and then just run:

```sh
$ bin/step-awskms-init --ssh --region us-east-1
Creating PKI ...
✔ Root Key: awskms:key-id=f53fb767-4029-40ff-b650-0dd35fb661df
✔ Root Certificate: root_ca.crt
✔ Intermediate Key: awskms:key-id=f879f239-feb6-4596-9ed2-b1606277c7fe
✔ Intermediate Certificate: intermediate_ca.crt

Creating SSH Keys ...
✔ SSH User Public Key: ssh_user_ca_key.pub
✔ SSH User Private Key: awskms:key-id=cf28e942-1e10-4a08-b84c-5359af1b5f12
✔ SSH Host Public Key: ssh_host_ca_key.pub
✔ SSH Host Private Key: awskms:key-id=cf28e942-1e10-4a08-b84c-5359af1b5f12
```

The `--region` parameter is only required if your aws configuration does not
define a region. See `step-awskms-init --help` for more options.

## YubiKey

And incomplete and experimental support for [YubiKeys](https://www.yubico.com)
is also available. Support for YubiKeys is not enabled by default and only TLS
signing can be configured.

The YubiKey implementation requires cgo, and our build system does not produce
binaries with it. To enable YubiKey download the source code and run:

```sh
make build GOFLAGS=""
```

The implementation uses [piv-go](https://github.com/go-piv/piv-go), and it
requires PCSC support, this is available by default on macOS and Windows
operating systems, but on Linux piv-go requires PCSC lite.

To install on Debian-based distributions, run:

```sh
sudo apt-get install libpcsclite-dev
```

On Fedora:

```sh
sudo yum install pcsc-lite-devel
```

On CentOS:

```sh
sudo yum install 'dnf-command(config-manager)'
sudo yum config-manager --set-enabled PowerTools
sudo yum install pcsc-lite-devel
```

The initialization of the public key infrastructure (PKI) for YubiKeys, is not
currently integrated into [step](https://github.com/smallstep/cli), but an
experimental tool named `step-yubikey-init` is available for this use case. At
some point this tool will be integrated into `step` and it will be deleted.

To configure your YubiKey just run:

```sh
$ bin/step-yubikey-init
What is the YubiKey PIN?:
Creating PKI ...
✔ Root Key: yubikey:slot-id=9a
✔ Root Certificate: root_ca.crt
✔ Intermediate Key: yubikey:slot-id=9c
✔ Intermediate Certificate: intermediate_ca.crt
```

See `step-yubikey-init --help` for more options.

Finally to enable it in the ca.json, point the `root` and `crt` to the generated
certificates, set the `key` with the yubikey URI generated in the previous step
and configure the `kms` property with the `type` and your `pin` in it.

```json
{
    "root": "/path/to/root_ca.crt",
    "crt": "/path/to/intermediate_ca.crt",
    "key": "yubikey:slot-id=9c",
    "kms": {
        "type": "yubikey",
        "pin": "123456"
    },
    ...
}
```

## SSHAgentKMS

SSHAgentKMS is a KMS that wrapps a ssh-agent which has access to the keys to
sign ssh certificates. This was primarly written to be able to use gpg-agent
to provide the keys stored in a YubiKeys openpgp interface.

```json
{
    "kms": {
        "type": "sshagentkms"
    },
    "ssh": {
        "hostKey": "sshagentkms:cardno:000123456789",
        "userKey": "sshagentkms:cardno:000123456789",
    },
    ...
}
```

This KMS requires that "root", "crt" and "key" are stored in plain files as for
SoftKMS.
