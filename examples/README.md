# Example

# Client & Server requests

On this example we are going to see the Certificate Authority running, as well
as a simple Server using TLS and a simple client doing TLS requests to the
server.

The examples directory already contains a sample pki configuration with the
password `password` hardcoded, but you can create your own using `step ca init`.

First we will start the certificate authority:
```
certificates $ bin/step-ca examples/pki/config/ca.json
2018/11/02 18:29:25 Serving HTTPS on :9000 ...
```

We will start the server and we will type `password` when step asks for the
provisioner password:
```
certificates $ export STEPPATH=examples/pki 
certificates $ export STEP_CA_URL=https://localhost:9000
certificates $ go run examples/server.go $(step ca new-token localhost))
✔ Key ID: DmAtZt2EhmZr_iTJJ387fr4Md2NbzMXGdXQNW1UWPXk (mariano@smallstep.com)
Please enter the password to decrypt the provisioner key:
Listening on :8443 ...
```

We try that using cURL with the system certificates it will return an error:
```
certificates $ curl https://localhost:8443
curl: (60) SSL certificate problem: unable to get local issuer certificate
More details here: https://curl.haxx.se/docs/sslcerts.html

curl performs SSL certificate verification by default, using a "bundle"
 of Certificate Authority (CA) public keys (CA certs). If the default
 bundle file isn't adequate, you can specify an alternate file
 using the --cacert option.
If this HTTPS server uses a certificate signed by a CA represented in
 the bundle, the certificate verification probably failed due to a
 problem with the certificate (it might be expired, or the name might
 not match the domain name in the URL).
If you'd like to turn off curl's verification of the certificate, use
 the -k (or --insecure) option.
HTTPS-proxy has similar options --proxy-cacert and --proxy-insecure.
```

But if we use the root certificate it will properly work:
```
certificates $ curl --cacert examples/pki/secrets/root_ca.crt https://localhost:8443
Hello nobody at 2018-11-03 01:49:25.66912 +0000 UTC!!!
```

Notice that in the response we see `nobody`, this is because the server didn't
detected a TLS client configuration.

But if we the client with the certificate name Mike we'll see:
```
certificates $ export STEPPATH=examples/pki 
certificates $ export STEP_CA_URL=https://localhost:9000
certificates $ go run examples/client.go $(step ca new-token Mike)
✔ Key ID: DmAtZt2EhmZr_iTJJ387fr4Md2NbzMXGdXQNW1UWPXk (mariano@smallstep.com)
Please enter the password to decrypt the provisioner key:
Server responded: Hello Mike at 2018-11-03 01:52:52.678215 +0000 UTC!!!
Server responded: Hello Mike at 2018-11-03 01:52:53.681563 +0000 UTC!!!
Server responded: Hello Mike at 2018-11-03 01:52:54.682787 +0000 UTC!!!
...
```