# Getting started with docker

This guide shows how to set up [step certificates](https://github.com/smallstep/certificates) using docker.

For short, we will use **step-ca** to refer to [step certificates](https://github.com/smallstep/certificates).

## Requirements

To be able to follow this guide you need to install [step
cli](https://github.com/smallstep/cli). Follow the installation instructions to
install it in your environment.

## Getting the image

The first thing that we need to run step-ca is pull the image from docker. Get
the latest version from the [step-ca docker
hub](https://hub.docker.com/r/smallstep/step-ca) and run:

```sh
docker pull smallstep/step-ca
```

## Volumes

To be able to run step-ca we need to create a volume in docker where we will
store our PKI as well as the step-ca configuration file.

To create a volume just run:

```sh 
docker volume create step
```

## Initializing the PKI

The simpler way to do this is to run an interactive terminal and initialize it:

```
$ docker run -it -v step:/home/step smallstep/step-ca sh
~ $ step ca init
✔ What would you like to name your new PKI? (e.g. Smallstep): Smallstep
✔ What DNS names or IP addresses would you like to add to your new CA? (e.g. ca.smallstep.com[,1.1.1.1,etc.]): localhost
✔ What address will your new CA listen at? (e.g. :443): :9000
✔ What would you like to name the first provisioner for your new CA? (e.g. you@smallstep.com): admin
✔ What do you want your password to be? [leave empty and we'll generate one]: <your password here>

Generating root certificate...
all done!

Generating intermediate certificate...
all done!

✔ Root certificate: /home/step/certs/root_ca.crt
✔ Root private key: /home/step/secrets/root_ca_key
✔ Root fingerprint: f9e45ae9ec5d42d702ce39fd9f3125372ce54d0b29a5ff3016b31d9b887a61a4
✔ Intermediate certificate: /home/step/certs/intermediate_ca.crt
✔ Intermediate private key: /home/step/secrets/intermediate_ca_key
✔ Default configuration: /home/step/config/defaults.json
✔ Certificate Authority configuration: /home/step/config/ca.json

Your PKI is ready to go. To generate certificates for individual services see 'step help ca'.
```

Our image is expecting the password to be placed in /home/step/secrets/password
you can simple go in to the terminal again and write that file:

```sh
$ docker run -it -v step:/home/step smallstep/step-ca sh
~ $ echo <your password here> > /home/step/secrets/password
```

At this time everything is ready to run step-ca.

## Running step certificates

Now that we have the volume and we have initialized the PKI we can run step-ca
and expose locally the server address with:

```sh
docker run -d -p 127.0.0.1:9000:9000 -v step:/home/step smallstep/step-ca
```

You can verify with curl that the service is running:

```sh
$ curl https://localhost:9000/health
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

It's working but curl complains because the certificate is not signed by an
accepted certificate authority.

## Dev environment bootstrap

To initialize the development environment we need to go back to [Initializing
the PKI](#initializing-the-pki) and grab the Root fingerprint. In our case
`f9e45ae9ec5d42d702ce39fd9f3125372ce54d0b29a5ff3016b31d9b887a61a4`. With the
fingerprint we can bootstrap our dev environment.

```sh
$ step ca bootstrap --ca-url https://localhost:9000 --fingerprint f9e45ae9ec5d42d702ce39fd9f3125372ce54d0b29a5ff3016b31d9b887a61a4
The root certificate has been saved in ~/.step/certs/root_ca.crt.
Your configuration has been saved in ~/.step/config/defaults.json.
```

From this moment forward [step cli](https://github.com/smallstep/cli) is
configured properly to use step certificates.

But curl and the rest of your environment won't accept the root certificate, we
can install the root certificate and everything would be ready.

```sh
$ step certificate install ~/.step/certs/root_ca.crt
Password: 
Certificate ~/.step/certs/root_ca.crt has been installed.
```

We can skip this last step if we go back to the bootstrap and run it with the
`--install` flag:

```sh
$ step ca bootstrap --ca-url https://localhost:9000 --fingerprint f9e45ae9ec5d42d702ce39fd9f3125372ce54d0b29a5ff3016b31d9b887a61a4 --install
The root certificate has been saved in ~/.step/certs/root_ca.crt.
Your configuration has been saved in ~/.step/config/defaults.json.
Installing the root certificate in the system truststore... done.
```

Now curl will not complain:

```sh
$ curl https://localhost:9000/health
{"status":"ok"}
```

And you will be able to run web services using TLS (and mTLS):

```sh
$ $ step ca certificate localhost localhost.crt localhost.key
✔ Key ID: aTPGWP0qbuQdflR5VxtNouDIOXyNMH1H9KAZKP-UcHo (admin)
✔ Please enter the password to decrypt the provisioner key:
✔ CA: https://localhost:9000/1.0/sign
✔ Certificate: localhost.crt
✔ Private Key: localhost.key
$ step ca root root_ca.crt
The root certificate has been saved in root_ca.crt.
$ python <<EOF
import BaseHTTPServer, ssl
class H(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header('content-type', 'text/html; charset=utf-8'); self.end_headers()
        self.wfile.write(b'\n\xf0\x9f\x91\x8b Hello! Welcome to TLS \xf0\x9f\x94\x92\xe2\x9c\x85\n\n')
httpd = BaseHTTPServer.HTTPServer(('', 8443), H)
httpd.socket = ssl.wrap_socket (httpd.socket, server_side=True, keyfile="localhost.key", certfile="localhost.crt", ca_certs="root_ca.crt")
httpd.serve_forever()
EOF
```

And in another terminal or in your browser:
```sh
$ curl https://localhost:8443

👋 Hello! Welcome to TLS 🔒✅
```
