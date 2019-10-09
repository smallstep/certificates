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

Absolutely. [Details here].

## Further Reading

* [Use TLS Everywhere](https://smallstep.com/blog/use-tls.html)
* [Everything you should know about certificates and PKI but are too afraid to ask](https://smallstep.com/blog/everything-pki.html)
