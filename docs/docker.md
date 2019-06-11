# Getting started with docker

This guide shows how to set up [step certificates](https://github.com/smallstep/certificates) using docker.

For short, we will use **step-ca** to refer to [step certificates](https://github.com/smallstep/certificates).

## Requirements

1. To follow this guide you will need to [install step
cli](https://github.com/smallstep/cli#installation-guide).

2. Get the docker image.

    Get the latest version of **step-ca** from the [step-ca docker
    hub](https://hub.docker.com/r/smallstep/step-ca):

    ```sh
    $ docker pull smallstep/step-ca
    ```

3. Create the required volumes.

    We need to create a volume in docker where we will store our PKI as well as
    the step-ca configuration file.

    ```sh
    $ docker volume create step
    ```

4. Initialize the PKI.

    The simple way to do this is to run an interactive terminal:

    ```sh
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

5. Place the PKI root password in a known location.

    Our image is expecting the password to be placed in `/home/step/secrets/password`
    you can simply go in to the terminal again and write that file:

    ```sh
    $ docker run -it -v step:/home/step smallstep/step-ca sh
    ~ $ echo <your password here> > /home/step/secrets/password
    ```

At this time everything is ready to run step-ca!

## Running step certificates

Now that we have configured our environment we are ready to run step-ca.

Expose the server address locally and run the step-ca with:
```sh
$ docker run -d -p 127.0.0.1:9000:9000 -v step:/home/step smallstep/step-ca
```

Let's verify that the service is running with curl:
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

To initialize the development environment we need to grab the Root fingerprint
from the [Initializing the PKI](#initializing-the-pki) step earlier. In the
case of this example:
`f9e45ae9ec5d42d702ce39fd9f3125372ce54d0b29a5ff3016b31d9b887a61a4`. With the
fingerprint we can bootstrap our dev environment.

```sh
$ step ca bootstrap --ca-url https://localhost:9000 --fingerprint f9e45ae9ec5d42d702ce39fd9f3125372ce54d0b29a5ff3016b31d9b887a61a4 --install
The root certificate has been saved in ~/.step/certs/root_ca.crt.
Your configuration has been saved in ~/.step/config/defaults.json.
Installing the root certificate in the system truststore... done.
```

Now [step cli](https://github.com/smallstep/cli) is configured to use step-ca
and our new root certificate is trusted by our local environment.
```sh
$ curl https://localhost:9000/health
{"status":"ok"}
```

And we are able to run web services configured with TLS (and mTLS):
```sh
~ $ step ca certificate localhost localhost.crt localhost.key
✔ Key ID: aTPGWP0qbuQdflR5VxtNouDIOXyNMH1H9KAZKP-UcHo (admin)
✔ Please enter the password to decrypt the provisioner key:
✔ CA: https://localhost:9000/1.0/sign
✔ Certificate: localhost.crt
✔ Private Key: localhost.key
~ $ step ca root root_ca.crt
The root certificate has been saved in root_ca.crt.
~ $ python <<EOF
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

Test from another terminal:
```sh
$ curl https://localhost:8443

👋 Hello! Welcome to TLS 🔒✅
```

Or visit `https://localhost:8443` from your browser.
