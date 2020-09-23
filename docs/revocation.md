# Revocation

**Active Revocation**: A certificate is no longer valid from the moment it has
been actively revoked. Clients are required to check against centralized
sources of certificate validity information (e.g. by using CRLs (Certificate
Revocation Lists) or OCSP (Online Certificate Status Protocol)) to
verify that certificates have not been revoked. Active Revocation requires
clients to take an active role in certificate validation for the benefit of
real time revocation.

**Passive Revocation**: A certificate that has been passively revoked can no
longer be renewed. It will still be valid for the remainder of it's validity period,
but cannot be prolonged. The benefit of passive revocation is that clients
can verify certificates in a simple, decentralized manner without relying on
centralized 3rd parties. Passive revocation works best with short
certificate lifetimes.

`step certificates` currently only supports passive revocation. Active revocation
is on our roadmap.

Run `step help ca revoke` from the command line for full documentation, list of
command line flags, and examples.

## How It Works

Certificates can be created and revoked through the `step cli`. Let's walk
through an example.

### Requirements

* `step` (>=v0.10.0) ([install instructions](../README.md#installation-guide))

### Let's Get To It

1. Bootstrap your PKI.

   > If you've already done this before and you have a `$STEPPATH` with certs,
   > secrets, and configuration files then you can move on to step 2.

   Run `step ca init`.

   <pre><code>
   <b>$ step ca init --name "Local CA" --provisioner admin --dns localhost --address ":443"</b>
   </code></pre>

   Move on to step 3.

2. Configure a persistence layer in your `ca.json`.

   > If you did step 1 with `step` v0.10.0 or greater then your db will
   > have been configured in the previous step.

   Get your full step path by running `echo $(step path)`. Now edit
   your `ca.json` by adding the following stanza as a top-level attribute:
   > Your `ca.json` should be in `$(step path)/config/ca.json`.

   ```
     ...
     "db": {
       "type": "badger",
       "dataSource": "<full step path>/db"
     },
     ...
   ```

   Check out our [database documentation](./database.md) to see all available
   database backends and adapters.

3. Run the CA

   <pre><code>
   <b>$ step-ca $(step path)/config/ca.json</b>
   </code></pre>

4. Create a certificate for localhost

   <pre><code>
   <b>$ step ca certificate localhost localhost.crt localhost.key</b>
   ✔ Key ID: n2kqNhicCCqVxJidspCQrjXWBtGwsa9zk3eBObrViy8 (sebastian@smallstep.com)
   ✔ Please enter the password to decrypt the provisioner key:
   ✔ CA: https://ca.smallstep.com
   ✔ Certificate: localhost.crt
   ✔ Private Key: localhost.key

   <b>$ step certificate inspect --short localhost.crt</b>
   X.509v3 TLS Certificate (ECDSA P-256) [Serial: 2400...2409]
     Subject:     localhost
     Issuer:      Smallstep Intermediate CA
     Provisioner: sebastian@smallstep.com [ID: n2kq...Viy8]
     Valid from:  2019-04-23T22:55:54Z
             to:  2019-04-24T22:55:54Z
   </code></pre>

5. Renew the certificate (just to prove we can!)

   <pre><code>
   <b>$ step ca renew localhost.crt localhost.key</b>
   ✔ Would you like to overwrite localhost.crt [y/n]: y
   Your certificate has been saved in localhost.crt.

   # Make sure the from timestamp is "newer"
   <b>$ step certificate inspect --short localhost.crt</b>
   X.509v3 TLS Certificate (ECDSA P-256) [Serial: 5963...8406]
     Subject:     localhost
     Issuer:      Smallstep Intermediate CA
     Provisioner: sebastian@smallstep.com [ID: n2kq...Viy8]
     Valid from:  2019-04-23T22:57:50Z
             to:  2019-04-24T22:57:50Z
   </pre></code>

6. Now let's revoke the certificate

   <pre><code>
   <b>$ step certificate inspect --format=json localhost.crt | jq .serial_number</b>
   "59636004850364466675608080466579278406"
   # the serial number is unique

   <b>$ step ca revoke 59636004850364466675608080466579278406</b>
   ✔ Key ID: n2kqNhicCCqVxJidspCQrjXWBtGwsa9zk3eBObrViy8 (sebastian@smallstep.com)
   ✔ Please enter the password to decrypt the provisioner key:
   ✔ CA: https://ca.smallstep.com
   Certificate with Serial Number 59636004850364466675608080466579278406 has been revoked.
   </pre></code>

7. Awesome! But did it work?

   <pre><code>
   <b>$ step ca renew localhost.crt localhost.key</b>
   error renewing certificate: Unauthorized

   # log trace from CA:
   [...]
   WARN[0569] duration="82.782µs" duration-ns=82782
     error="renew: certificate has been revoked"
     fields.time="2019-04-23T16:03:01-07:00" method=POST
     name=ca path=/renew protocol=HTTP/1.1 referer=
     remote-address=127.0.0.1 request-id=bivpj9a3q563rpjheh5g
     size=40 status=401 user-agent=Go-http-client/1.1 user-id=
   [...]
   </pre></code>

8. Other ways to revoke a Certificate

   Use the certificate and key. This method does not require a provisioner
   because it uses the certificate and key to authenticate the request.

   <pre><code>
   <b>$ step ca revoke --cert localhost.crt --key localhost.key</b>
   Certificate with Serial Number 59636004850364466675608080466579278406 has been revoked.
   </pre></code>

   Or, revoke a certificate in two steps by first creating a revocation token and
   then exchanging that token in a revocation request.

   <pre><code>
   <b>$ TOKEN=$(step ca token --revoke 59636004850364466675608080466579278406)</b>
   ✔ Key ID: n2kqNhicCCqVxJidspCQrjXWBtGwsa9zk3eBObrViy8 (sebastian@smallstep.com)
   ✔ Please enter the password to decrypt the provisioner key:

   <b>$ echo $TOKEN | step crypto jwt inspect --insecure</b>
   {
     "header": {
       "alg": "ES256",
       "kid": "uxEunU9UhUo96lRvKgpEtRevkzbN5Yq88AFFtb1nSGg",
       "typ": "JWT"
     },
     "payload": {
       "aud": "https://localhost:443/1.0/revoke",
       "exp": 1556395590,
       "iat": 1556395290,
       "iss": "sebastian@smallstep.com",
       "jti": "1f222fc1a22530b7bcd2a40d7308c566c8e49f90413bc350e07bfabc8002b79b",
       "nbf": 1556395290,
       "sha": "fef4c75a050e1f3a31175ca4f4fdb711cbef1efcd374fcae4700596604eb8e5a",
       "sub": "59636004850364466675608080466579278406"
     },
     "signature": "M1wX0ea3VXwS5rIim0TgtcCXHDtvP1GWD15cJSvVkrHNO6XMYl6m3ZmnWdwMi976msv-n2GTG3h6dJ3j2ImdfQ"
   }

   <b>$ step ca revoke --token $TOKEN 59636004850364466675608080466579278406</b>
   Certificate with Serial Number 59636004850364466675608080466579278406 has been revoked.
   </pre></code>

   Or, revoke a certificate in offline mode:

   <pre><code>
   <b>$ step ca revoke --offline 59636004850364466675608080466579278406</b>
   Certificate with Serial Number 59636004850364466675608080466579278406 has been revoked.

   <b>$ step ca revoke --offline --cert localhost.crt --key localhost.key</b>
   Certificate with Serial Number 59636004850364466675608080466579278406 has been revoked.
   </pre></code>

   > NOTE: you can only revoke a certificate once. Any repeated attempts to revoke
   > the same serial number will fail.

   Run `step help ca revoke` from the command line for full documentation, list of
   command line flags, and examples.

## What's next?

[Use TLS Everywhere](https://smallstep.com/blog/use-tls.html) and let us know
what you think of our tools. Get in touch over
[Twitter](twitter.com/smallsteplabs) or through our
[GitHub Discussions](https://github.com/smallstep/certificates/discussions) to chat with us in real time.

## Further Reading

* [Use TLS Everywhere](https://smallstep.com/blog/use-tls.html)
* [Everything you should know about certificates and PKI but are too afraid to ask](https://smallstep.com/blog/everything-pki.html)
