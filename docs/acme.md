# Using ACME with `step-ca `

Let’s assume you’ve [installed
`step-ca`](https://smallstep.com/docs/getting-started/#1-installing-step-and-step-ca)
(e.g., using `brew install step`), have it running at `https://ca.internal`,
and you’ve [bootstrapped your ACME client
system(s)](https://smallstep.com/docs/getting-started/#bootstrapping) (or at
least [installed your root
certificate](https://smallstep.com/docs/cli/ca/root/) at
`~/.step/certs/root_ca.crt`).

## Enabling ACME

To enable ACME, simply [add an ACME provisioner](https://smallstep.com/docs/cli/ca/provisioner/add/) to your `step-ca` configuration
by running:

```
$ step ca provisioner add my-acme-provisioner --type ACME
```

> NOTE: The above command will add a new provisioner of type `ACME` and name
> `my-acme-provisioner`. The name is used to identify the provisioner
> (e.g. you cannot have two `ACME` provisioners with the same name).

Now restart or SIGHUP `step-ca` to pick up the new configuration.

That’s it.

## Configuring Clients

To configure an ACME client to connect to `step-ca` you need to:

1. Point the client at the right ACME directory URL
2. Tell the client to trust your CA’s root certificate

Once certificates are issued, you’ll also need to ensure they’re renewed before
they expire.

### Pointing Clients at the right ACME Directory URL

Most ACME clients connect to Let’s Encrypt by default. To connect to `step-ca`
you need to point the client at the right [ACME directory
URL](https://tools.ietf.org/html/rfc8555#section-7.1.1).

A single instance of `step-ca` can have multiple ACME provisioners, each with
their own ACME directory URL that looks like:

```
https://{ca-host}/acme/{provisioner-name}/directory
```

We just added an ACME provisioner named “acme”. Its ACME directory URL is:

```
https://ca.internal/acme/acme/directory
```

### Telling clients to trust your CA’s root certificate

Communication between an ACME client and server [always uses
HTTPS](https://tools.ietf.org/html/rfc8555#section-6.1). By default, client’s
will validate the server’s HTTPS certificate using the public root certificates
in your system’s [default
trust](https://smallstep.com/blog/everything-pki.html#trust-stores) store.
That’s fine when you’re connecting to Let’s Encrypt: it’s a public CA and its
root certificate is in your system’s default trust store already. Your internal
root certificate isn’t, so HTTPS connections from ACME clients to `step-ca` will
fail.

There are two ways to address this problem:

1. Explicitly configure your ACME client to trust `step-ca`'s root certificate, or
2. Add `step-ca`'s root certificate to your system’s default trust store (e.g.,
   using [`step certificate
   install`](https://smallstep.com/docs/cli/certificate/install/))

If you’re using your CA for TLS in production, explicitly configuring your ACME
client to only trust your root certificate is a better option. We’ll
demonstrate this method with several clients below.

If you’re simulating Let’s Encrypt in pre-production, installing your root
certificate is a more faithful simulation of production. Once your root
certificate is installed, no additional client configuration is necessary.

> Caution: adding a root certificate to your system’s trust store is a global
> operation. Certificates issued by your CA will be trusted everywhere,
> including in web browsers.

### Example using [`certbot`](https://certbot.eff.org/)

[`certbot`](https://certbot.eff.org/) is the grandaddy of ACME clients. Built
and supported by [the EFF](https://www.eff.org/), it’s the standard-bearer for
production-grade command-line ACME.

To get a certificate from `step-ca` using `certbot` you need to:

1. Point `certbot` at your ACME directory URL using the `--`server flag.
2. Tell `certbot` to trust your root certificate using the `REQUESTS_CA_BUNDLE` environment variable.

For example:

```
$ sudo REQUESTS_CA_BUNDLE=$(step path)/certs/root_ca.crt \
  certbot certonly -n --standalone -d foo.internal \
    --server https://ca.internal/acme/acme/directory
```

`sudo` is required in `certbot`'s [*standalone*
mode](https://certbot.eff.org/docs/using.html#standalone) so it can listen on
port 80 to complete the `http-01` challenge. If you already have a webserver
running you can use [*webroot*
mode](https://certbot.eff.org/docs/using.html#webroot) instead. With the
[appropriate plugin](https://certbot.eff.org/docs/using.html#dns-plugins)
`certbot` also supports the `dns-01` challenge for most popular DNS providers.
Deeper integrations with [nginx](https://certbot.eff.org/docs/using.html#nginx)
and [apache](https://certbot.eff.org/docs/using.html#apache) can even configure
your server to use HTTPS automatically (we'll set this up ourselves later). All
of this works with `step-ca`.

You can renew all of the certificates you've installed using `cerbot` by running:

```
$ sudo REQUESTS_CA_BUNDLE=$(step path)/certs/root_ca.crt certbot renew
```

You can automate renewal with a simple `cron` entry:

```
*/15 * * * * root REQUESTS_CA_BUNDLE=$(step path)/certs/root_ca.crt certbot -q renew
```

The `certbot` packages for some Linux distributions will create a `cron` entry
or [systemd
timer](https://stevenwestmoreland.com/2017/11/renewing-certbot-certificates-using-a-systemd-timer.html)
like this for you. This entry won't work with `step-ca` because it [doesn't set
the `REQUESTS_CA_BUNDLE` environment
variable](https://github.com/certbot/certbot/issues/7170). You'll need to
manually tweak it to do so.

More subtly, `certbot`'s default renewal job is tuned for Let's Encrypt's 90
day certificate lifetimes: it's run every 12 hours, with actual renewals
occurring for certificates within 30 days of expiry. By default, `step-ca`
issues certificates with *much shorter* 24 hour lifetimes. The `cron` entry
above accounts for this by running `certbot renew` every 15 minutes. You'll
also want to configure your domain to only renew certificates when they're
within a few hours of expiry by adding a line like:

```
renew_before_expiry = 8 hours
```

to the top of your renewal configuration (e.g., in `/etc/letsencrypt/renewal/foo.internal.conf`).

## Feedback

`step-ca` should work with any ACMEv2
([RFC8555](https://tools.ietf.org/html/rfc8555)) compliant client that supports
the http-01 or dns-01 challenge.

Post feedback on [our GitHub Discussions tab](https://github.com/smallstep/certificates/discussions),
or [create a bug report issue](https://github.com/smallstep/certificates/issues/new?template=bug_report.md).
