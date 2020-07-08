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

## What are the security risks of exposing the OAuth Client Secret in the output of `step ca provisioner list`?

It would be nice if we could have the CA operate as an OAuth confidential
client, keeping the client secret private and redirecting back to the CA
instead of to loopback. But, to be clear, this is not an abuse of the OAuth
spec. The way this was implemented in step, as an OAuth native application
using a public client, is standard, was intentional, (mostly) conforms to best
current practices, and the flow we're using is widely used in practice. A
confidential client is (strictly?) more secure. But a public client that
redirects to loopback isn’t a significant security risk under a normal threat
model.

### The current flow
The advantage of the current flow is that it’s more general purpose. For
example, `step oauth` works without any additional infrastructure. An issued
access token can be used from the command line, and OIDC identity tokens can be
safely used to authenticate to remote services (including remote services that
        don’t speak OAuth OIDC, or don’t even speak HTTP, but can validate a
        JWT). `step-ca` is one example of a remote service that can authenticate
step users via OIDC identity token. You can also use `step crypto jwt verify` to
authenticate using OIDC at the command line.

The particular details of the OAuth flow we selected has pros & cons, as does
any flow. The relevant security risks are:

1. Since the OAuth access token isn’t issued directly to a remote server (e.g.,
        `step-ca`), remote servers can’t safely use the issued access tokens
without significant care. If they did, an attacker might be able to maliciously
trick the remote server into using an access token that was issued to a
different client.

2. The redirect back from the OAuth authorization server to the
client can be intercepted by another process running on the local machine. This
isn’t really necessary though, because...

3. The `client_secret` is public, so anyone can initiate (and complete) an OAuth
flow using our client (but it will always redirect back to 127.0.0.1).

The first threat is moot since we don't actually use the access token for
anything when we're connecting to `step-ca`. Unfortunately there's no way to not
get an access token. So we just ignore it.

Note that it *is* safe to use the access token from the command line to access
resources at a remote API. For example, it’s safe to user `step oauth` to obtain
an OAuth access token from Google and use it to access Google’s APIs in a bash
script.

More generally, access tokens are for accessing resources (authorization) and
are not useful for authenticating a user since they're not audience-addressed.
If you and I both have a Google OAuth client, I could get Alice to OAuth into
my app and use the issued access token to masquerade as Alice to you. But OIDC
identity tokens are audience-addressed. An identity token is a JWT with the
`client_id` baked in as the `aud` (audience) parameter. As long as clients check
this parameter (which `step-ca` does) they're not susceptible to this attack. In
fact, OIDC identity tokens were designed and developed precisely to solve this
problem.

So it's completely safe for one entity to obtain an *identity token* from an IdP
on behalf of a user and use it to authenticate to another entity (like `step`
        does). That's exactly the use case OIDC was designed to support.

The second and third threats are related. They involve a malicious attempt to
initiate an OAuth OIDC flow using our client credentials. There's a lot of
analysis we could do here comparing this situation to a non-native (e.g., *web*)
client and to other flows (e.g., the *implicit flow*, which also makes the
client secret public). Skipping that detail, we know two things for sure:

1. OAuth flows generally require user consent to complete (e.g., a user has to
"approve" an application's authentication / authorization request)

2. An OAuth flow initiated using our client will always redirect back to 127.0.0.1

So a malicious attacker trying to obtain an *identity token* needs two things:

1. They need to get user consent to complete an OAuth flow
2. They need to have local access to the user's machine

This is already a pretty high bar. It’s worth noting, however, that the first
part is *much* easier if the user is already logged in and the identity provider
is configured to not require consent (i.e., the OAuth flow is automatically
        completed without the user having to click any buttons). Okta seems to
do this for some applications by default.

It's also worth noting that a process with local access could probably obtain
an access/identity token for a *confidential client* without knowing the client
secret. That's the main reason I don't think the flow we're using has a
meaningful security impact under most threat models. The biggest difference is
that attacking a confidential client would probably require privileged (root)
    access, whereas our flow could be attacked by an unprivileged process. But
    the fruit of our OAuth flow — the SSH certificate — is also available for
    use by an unprivileged process running locally via the `ssh-agent`. So the
    only thing possibly gained is the ability to exfiltrate.

### Stuff we should consider doing
There are at least three OAuth features that are relevant to this discussion.
Two have already been mentioned:

1. OAuth *public clients* for *native applications* can be (er, are *supposed*
to be) created without a client secret

2. Proof Key for Code Exchange (PKCE) helps ensure that the process requesting the access token / identity token is the same process that initiated the flow

The first feature, clients without secrets, is mostly cosmetic. There's no real
difference between a public secret and no secret, except that it's confusing to
have something called a "secret" that's not actually secret. (Caveat: IdPs that
support "native applications" without secrets typically enforce other rules for
these clients — they often require PKCE and might not issue a renew token, for
example. But these features can often be turned on/of for other client types,
too.)

The reason we don't assume a *public client* without a secret is that,
unfortunately, not all IdPs support them. Significantly, Google does not. In
fact, gcloud (Google Cloud's CLI tool) uses OAuth OIDC and uses the exact same
technique we're using. If you look at the source you'll find their
"NOTSOSECRET" All of that said, we should support "native clients" without
secrets at some point.

We should also implement Proof Key for Code Exchange (PKCE). This has been on
our backlog for a while, and it's actually really simple and useful. It's
definitely low-hanging fruit. Before initiating the OAuth flow your client
generates a random number. It hashes that number and passes the hash to the IdP
as part of the authorization request (the URL that users are sent to for
        login). After authenticating and consenting, when the user is
redirected back to the client, the client makes a request to the IdP to get an
access token & identity token. In *that* request the client must include the
*unhashed* random number. The IdP re-hashes it and compares it to the value it
received in the authorization request. If they match, the IdP can be certain
that the entity making the access token request is the same entity that
initiated the flow. In other words, the request has not been intercepted by
some malicious intermediary.

The last hardening mechanism to be aware of are the `acr` and `amr` parameters.
Basically, when the OAuth flow is initiated the client can request that the IdP
require consent, do 2FA, and a bunch of other stuff. The issued identity token
includes parameters to indicate that these processes did, indeed, occur.
Leveraging this mechanism one could configure `step-ca` to check these parameters
and be sure that users have consented and undergone a 2FA presence check (e.g.,
        tapped a security token). Unfortunately, like a bunch of other optional
OAuth features, many IdPs (*cough* Google *cough*) don't support this stuff.

### Summary

Implementing PKCE should be our highest priority item. Support for "native"
clients without secrets would also be nice. Forcing 2FA & consent via `acr` & `amr`
is also a good idea. Support for non-native clients that redirect back to the
CA, and where the secret is *actually* secret, would also be nice. But it's a
bigger architectural change and the security implications aren't actually that
severe.

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
