# Frequently Asked Questions

These are some commonly asked questions on the topics of PKI, TLS, X509,
cryptography, threshold-cryptography, etc.
Hopefully we will reduce the amount of hand-waving in these responses as we add
more features to the Step toolkit over time.

> We encourage you to read
> [our blog post on everything relating to PKI](https://smallstep.com/blog/everything-pki.html)
> as we believe it to be a solid resource that answers many of of the questions
> listed below.

## What are TLS & PKI?

TLS stands for *transport layer security*. It used to be called *secure sockets
layer* (or SSL), but technically SSL refers to an older version of the protocol.
Normal TCP connections communicate in plain text, allowing attackers to
eavesdrop and spoof messages. If used properly, TLS provides *confidentiality*
and *integrity* for TCP traffic, ensuring that messages can only be seen by their
intended recipient, and cannot be modified in transit.

TLS is a complicated protocol with lots of options, but the most common mode of
operation establishes a secure channel using *asymmetric cryptography* with
*digital certificates* (or just certificates for short).

First, some quick definitions:
* *Asymmetric cryptography* (a.k.a., public key cryptography) is an underappreciated
gift from mathematics to computer science. It uses a *key pair*: a private key
known only to the recipient of the message, and a public key that can be broadly
distributed, even to adversaries, without compromising security.
* *Digital certificates* are data structures that map a public key to the
well-known name of the owner of the corresponding private key (e.g., a DNS host name).
They *bind* a name to the public key so you can address recipients by name instead of
using public keys directly (which are big random numbers).

Briefly, there are two functions that can be achieved using asymmetric cryptography:
* Messages can be *encrypted* using the public key to ensure that only the
private key holder can *decrypt* them, and
* Messages can be *signed* using the private key so that anyone with the *public
key* knows the message came from the private key holder.
With digital certificates, you can replace "private key holder" with "named entity,"
which makes things a whole lot more useful. It lets you use names, instead of
public keys, to address messages.

PKI stands for *public key infrastructure*. Abstractly, it's a set of policies
and procedures for managing digital certificates (i.e., managing the bindings
between names and public keys). Without proper secure PKI, an attacker can fake
a binding and undermine security.

## What's a certificate authority?

A certificate authority (CA) stores, issues, and signs digital certificates. CAs
have their own key pair, with the private key carefully secured (often offline).
The CA binds its name to its public key by signing a digital certificate using
its own private key (called *self signing*). The CA's self-signed certificate,
or *root certificate*, is distributed to all principals in the system (e.g., all
of the clients and servers in your infrastructure).

So, the CA is tasked with securely binding names to public keys. Here's how that process works.
1. When a named principal wants a certificate, it generates its own key pair.
Nobody else ever needs to know the private key, not even the CA.
2. The principal creates a certificate signing request (CSR), containing its
name and public key (and some other stuff), and submits it to the CA. The CSR is
self-signed, like the root certificate, so the CA knows that the requestor has
the corresponding private key.
3. The CA performs some form of *identity proofing*, certifying that the request
is coming from the principal named in the CSR.
4. Once satisfied, the CA issues a certificate by using its own private key to
sign a certificate binding the name and public key from the CSR.

Certificates signed by the CA are used to securely introduce principals that
don't already know one anothers' public keys. Assuming both principals agree on
a trusted CA, they can exchange digital certificates and authenticate the
signatures to gain some assurance that they are communicating with the named entity.

Technically, smallstep's certificate authority is more than just a certificate
authority. It combines several PKI roles into one simple, flexible package. It
acts as a *registration authority*, accepting requests for digital certificates
and verifying the identity of the requesting entities before establishing bindings.
It also acts as a *central directory* and more generally as a *certificate
management system*, a secure location for storing and distributing key material.

## Why not just use Verisign, Entrust, Let's Encrypt, etc?

The web's *open public key infrastructure* (web PKI), while far from perfect,
is an important foundation for securing the web. So why not use it for securing
communication for your own internal infrastructure? There are several reasons:
* It's expensive to provision certificates from a public CA for all of your services
* Public CAs can't handle client certificates (mutual TLS)
* It's much harder (and more expensive) to revoke or roll certificates from public CAs
* It relies on a third party that can subvert your security

More broadly, the answer is that web PKI was designed for the web. A lot of the
web PKI design decisions aren't appropriate for internal systems.

## How does identity proofing work?

In general, trust will always flow back out to you, the operator of your system.
With that in mind, the simplest form of identity proofing is manual: [describe
token-based manual mechanism here]. As your system grows, this process can become
onerous. Automated identity proofing requires careful coordination between
different parts of your system. Smallstep provides additional tooling, and vetted
designs, to help with this. If you integrate with our other tools its easy to
start with a manual identity proofing mechanism and move to a more sophisticated
automated method as your system grows.

## I already have PKI in place. Can I use this with my own root certificate?

Yes. There's a easy way, and a longer but more secure way to do this.

### Option 1: The easy way

If you have your root CA signing key available, you can run:

```bash
step ca init --root=[ROOT_CERT_FILE] --key=[ROOT_PRIVATE_KEY_FILE]
```

The root certificate can be in PEM or DER format, and the signing key can be a PEM file containing a PKCS#1, PKCS#8, or RFC5915 (for EC) key.

### Option 2: More secure

That said, CAs are usually pretty locked down and it's bad practice to move the private key around. So I'm gonna assume that's not an option and give you the more complex instructions to do this "the right way", by generating a CSR for `step-ca`, getting it signed by your existing root, and configuring `step-ca` to use it.

When you run `step ca init` we create a couple artifacts under `~/.step/`. The important ones for us are:

- `~/.step/certs/root_ca.crt` is your root CA certificate
- `~/.step/secrets/root_ca_key` is your root CA signing key
- `~/.step/certs/intermediate_ca.crt` is your intermediate CA cert
- `~/.step/secrets/intermediate_ca_key` is the intermediate signing key used by `step-ca`

The easiest thing to do is to run `step ca init` to get  this scaffolding configuration in place, then remove/replace these  artifacts with new ones that are tied to your existing root CA.

First, `step-ca` does not actually need the root CA signing key. So you can simply remove that file:

```bash
rm ~/.step/secrets/root_ca_key
```

Next, replace `step-ca`'s root CA cert with your existing root certificate:

```bash
mv /path/to/your/existing/root.crt ~/.step/certs/root_ca.crt
```

Now you need to generate a new signing key and intermediate certificate, signed by your existing root CA. To do that we can use the `step certificate create` subcommand to generate a certificate signing request (CSR) that we'll have your existing root CA sign, producing an intermediate certificate.

To generate those artifacts run:

```bash
step certificate create "Intermediate CA Name" intermediate.csr intermediate_ca_key --csr
```

Next, you'll need to transfer the CSR file (`intermediate.csr`) to your existing root CA and get it signed.

Now you need to get the CSR executed by your existing root CA.

**Active Directory Certificate Services**

```bash
certreq -submit -attrib "CertificateTemplate:SubCA" intermediate.csr intermediate.crt
```

**AWS Certificate Manager Private CA**

Here's a Python script that uses [issue-certificate](https://docs.aws.amazon.com/acm-pca/latest/userguide/PcaIssueCert.html) to process the CSR:

```python
import boto3
import sys

AWS_CA_ARN = '[YOUR_PRIVATE_CA_ARN]'

csr = ''.join(sys.stdin.readlines())

client = boto3.client('acm-pca')
response = client.issue_certificate(
    CertificateAuthorityArn=AWS_CA_ARN,
    Csr=csr,
    SigningAlgorithm='SHA256WITHRSA',
    TemplateArn='arn:aws:acm-pca:::template/SubordinateCACertificate_PathLen1/V1',
    Validity={
        'Value': 5,
        'Type': 'YEARS'
    }
)
print(f"Creating certificate with ARN {response['CertificateArn']}...", file=sys.stderr, end='')
waiter = client.get_waiter('certificate_issued')
waiter.wait(
    CertificateAuthorityArn=AWS_CA_ARN,
    CertificateArn=response['CertificateArn']
)
print('done.', file=sys.stderr)
response = client.get_certificate(
   CertificateArn=response['CertificateArn'],
   CertificateAuthorityArn=AWS_CA_ARN
)
print(response['Certificate'])
```

To run it, fill in the ARN of your CA and run:

```bash
python issue_certificate.py < intermediate.csr > intermediate.crt
```

**OpenSSL**

```bash
openssl ca -config [ROOT_CA_CONFIG_FILE] \
  -extensions v3_intermediate_ca \
  -days 3650 -notext -md sha512 \
  -in intermediate.csr \
  -out intermediate.crt
```

**CFSSL**

For CFSSL you'll need a signing profile that specifies a 10-year expiry:

```bash
cat > ca-smallstep-config.json <<EOF
{
  "signing": {
    "profiles": {
      "smallstep": {
        "expiry": "87660h",
        "usages": ["signing"]
      }
    }
  }
}
EOF
```

Now use that config to sign the intermediate certificate:

```bash
cfssl sign -ca ca.pem \
    -ca-key ca-key.pem \
    -config ca-smallstep-config.json \
    -profile smallstep
    -csr intermediate.csr | cfssljson -bare
```

This process will yield a signed `intermediate.crt` certificate (or `cert.pem` for CFSSL). Transfer this file back to the machine running `step-ca`.

Finally, replace the intermediate .crt and signing key produced by `step ca init` with the new ones we just created:

```bash
mv intermediate.crt ~/.step/certs/intermediate_ca.crt
mv intermediate_ca_key ~/.step/secrets/intermediate_ca_key
```

That should be it! You should be able to start `step-ca` and the certificates should be trusted by anything that trusts your existing root CA.

## Further Reading

* [Use TLS Everywhere](https://smallstep.com/blog/use-tls.html)
* [Everything you should know about certificates and PKI but are too afraid to ask](https://smallstep.com/blog/everything-pki.html)
