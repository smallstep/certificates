# Registration Authorities

This document describes how to use an external registration authority (RA), aka
certificate authority service (CAS) to sign X.509 certificates requests.

A CAS is a system that implements an API to sign certificate requests, the
difference between CAS and KMS is that the latter can sign any data, while CAS
is intended to sign only X.509 certificates.

`step-ca` defines an interface that can be implemented to support other
registration authorities, currently only CloudCAS and the default SoftCAS are
implemented.

The `CertificateAuthorityService` is defined in the package
`github.com/smallstep/certificates/cas/apiv1` and it is:

```go
type CertificateAuthorityService interface {
    CreateCertificate(req *CreateCertificateRequest) (*CreateCertificateResponse, error)
    RenewCertificate(req *RenewCertificateRequest) (*RenewCertificateResponse, error)
    RevokeCertificate(req *RevokeCertificateRequest) (*RevokeCertificateResponse, error)
}
```

The same package defines another interface that is used to get the root
certificates from the CAS:

```go
type CertificateAuthorityGetter interface {
    GetCertificateAuthority(req *GetCertificateAuthorityRequest) (*GetCertificateAuthorityResponse, error)
}
```

## SoftCAS

SoftCAS is the default implementation supported by `step-ca`. No special
configurations are required to enable it.

SoftCAS generally uses certificates and keys in the filesystem, but a KMS can
also be used instead of a key file for signing certificates. See [KMS](kms.md)
for more information.

## CloudCAS

CloudCAS is the implementation of the `CertificateAuthorityService` and
`CertificateAuthorityGetter` interfaces using [Google's Certificate Authority
Service](https://cloud.google.com/certificate-authority-service/).

Before enabling CloudCAS in `step-ca` you do some steps in Google Cloud Console
or using `gcloud` CLI:

1. Create or define a project to use. Let's say the name is `smallstep-cas-test`.
2. Create the KMS keyring and keys for root and intermediate certificates:

   ```sh
   # Create key ring
   gcloud kms keyrings create kr1 --location us-west1
   # Create key for Root certificate
   gcloud kms keys create k1 \
       --location us-west1 \
       --keyring kr1 \
       --purpose asymmetric-signing \
       --default-algorithm ec-sign-p256-sha256 \
       --protection-level software
   # Create key for Intermediate certicate
   gcloud kms keys create k2 \
       --location us-west1 \
       --keyring kr1 \
       --purpose asymmetric-signing \
       --default-algorithm ec-sign-p256-sha256 \
       --protection-level software

   # Put the resource name for version 1 of the new KMS keys into a shell variable.
   # This will be used in the other instructions below.
   KMS_ROOT_KEY_VERSION=$(gcloud kms keys versions describe 1 --key k1 --keyring kr1 --location us-west1 --format "value(name)")
   KMS_INTERMEDIATE_KEY_VERSION=$(gcloud kms keys versions describe 1 --key k2 --keyring kr1 --location us-west1 --format "value(name)")
   ```

3. Enable the CA service API. You can do it on the console or running:

   ```sh
   gcloud services enable privateca.googleapis.com
   ```

4. Configure IAM. Create a service account using Google Console or running:

   ```sh
   # Create service account
   gcloud iam service-accounts create step-ca-sa \
       --project smallstep-cas-test \
       --description "Step-CA Service Account" \
       --display-name "Step-CA Service Account"
   # Add permissions to use the privateca API
   gcloud projects add-iam-policy-binding smallstep-cas-test \
       --member=serviceAccount:step-ca-sa@smallstep-cas-test.iam.gserviceaccount.com \
       --role=roles/privateca.caManager
   gcloud projects add-iam-policy-binding smallstep-cas-test \
       --member=serviceAccount:step-ca-sa@smallstep-cas-test.iam.gserviceaccount.com \
       --role=roles/privateca.certificateRequester
   # Download the credentials.file
   gcloud iam service-accounts keys create credentials.json \
      --iam-account step-ca-sa@smallstep-cas-test.iam.gserviceaccount.com
   ```

5. Create a Root CA. You can do this on the console or running:

   ```sh
   gcloud beta privateca roots create prod-root-ca \
       --location us-west1 \
       --kms-key-version "$KMS_ROOT_KEY_VERSION" \
       --subject "CN=Example Root CA, O=Example LLC" \
       --max-chain-length 2
   ```

6. Create an Intermediate CA. You can do this on the console or running:

   ```sh
   gcloud beta privateca subordinates create prod-intermediate-ca \
       --location us-west1 \
       --issuer prod-root-ca \
       --issuer-location us-west1 \
       --kms-key-version "$KMS_INTERMEDIATE_KEY_VERSION" \
       --subject "CN=Example Intermediate CA, O=Example LLC" \
       --reusable-config "subordinate-server-tls-pathlen-0"
   ```

Now it's time to enable it in `step-ca` by adding some new files in the
`"authority"` section of the `ca.json`.

```json
{
    "authority": {
        "type": "cloudCAS",
        "credentialsFile": "/path/to/credentials.json",
        "certificateAuthority": "projects/<name>/locations/<loc>/certificateAuthorities/<ca-name>",
    }
}
```

* **type** defines the name of the CAS to use, _cloudCAS_ must be used to enable it.
* **credentialsFile** defines the path to a Google Cloud credential file with
  access to Google's Certificate AuthorityService. We created this file before
  in step 4. Instead of setting this property, the environment variable
  `GOOGLE_APPLICATION_CREDENTIALS` can be pointed to the file to use. Or if the
  `step-ca` is running in Google Cloud, the default service account in the
  machine can also be used.
* **certificateAuthority** defines the Google Cloud resource to the intermediate
  (or subordinated) certificate to use. We created this resource in step 6.

As we said before, the CloudCAS implementation in `step-ca` also defines the
interface `CertificateAuthorityGetter`, this allows `step-ca` to automatically
download the root certificate from Cloud CAS. In the `ca.json` now you don't
need to configure `"root"`, and because the intermediate is in Google Cloud,
`"crt"` and `"key"` are no needed. A full `ca.json` can look like:

```json
{
   "address": ":443",
   "dnsNames": ["ca.example.com"],
   "logger": {"format": "text"},
   "db": {
      "type": "badger",
      "dataSource": "/home/jane/.step/db",
   },
   "authority": {
      "type": "cloudCAS",
      "credentialsFile": "/home/jane/.step/credentials.json",
      "certificateAuthority": "projects/smallstep-cas-test/locations/us-west1/certificateAuthorities/prod-intermediate-ca",
      "provisioners": [
         {
            "type": "JWK",
            "name": "jane@example.com",
            "key": {
               "use": "sig",
               "kty": "EC",
               "kid": "ehFT9BkVOY5k_eIiMax0ZxVZCe2hlDVkMwZ2Y78av4s",
               "crv": "P-256",
               "alg": "ES256",
               "x": "GtEftN0_ED1lNc2SEUJDXV9EMi7JY-kqINPIEQJIkjM",
               "y": "8HYFdNe1MbWcbclF-hU1L80SCmMcZQI6vZfTOXfPOjg"
            },
            "encryptedKey": "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJjdHkiOiJqd2sranNvbiIsImVuYyI6IkEyNTZHQ00iLCJwMmMiOjEwMDAwMCwicDJzIjoiSjBSWnY5UFZrM3JKRUJkem5RbExzZyJ9.Fiwvo-RIKU5G6v5udeCT1nlX87ElxrocP2FcgNs3AqEz5OH9H4suew.NmzUJR_9xv8ynQC8.dqOveA_G5kn5lxjxnEZoJCystnJMVYLkZ_8CVzfJQhYchbZfNk_-FKdIuQxeWWBzvmomsILFNtLOIUoqSt30qk83lFyGQWN8Ke2bK5DhuwojF7RI_UqkMyiKP0F28Z4ZFhfQP5D2ZT_stoFaMlU8eak0-T8MOiBIfdAJTWM9x2DN-68mtUBuL5z5eU8bqsxELnjGauD_GHTdnduOosmYsw8vp_PmffTTwqUzDFH1RhkeSmRFRZntAizZMGYkxLamquHI3Jvuqiv4eeJ3yLqh3Ppyo_mVQKnxM7P9TyTxcvLkb2dB3K-cItl1fpsz92cy8euKsKG8n5-hKFRyPfY.j7jBN7nUwatoSsIZuNIwHA"
         }
      ]
   },
   "tls": {
      "cipherSuites": [
         "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
         "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
      ],
      "minVersion": 1.2,
      "maxVersion": 1.3,
      "renegotiation": false
   }
}
```

The we only need to run `step-ca` as usual, but this time, the CA will print the
root fingerprint too:

```sh
$ step-ca /home/jane/.step/config/ca.json
2020/09/22 13:17:15 Using root fingerprint '3ef16343cf0952eedbe2b843066bb798fa7a7bceb16aa285e8b0399f661b28b7'
2020/09/22 13:17:15 Serving HTTPS on :9000 ...
```

We will need to bootstrap once our environment using the printed fingerprint:

```sh
step ca bootstrap --ca-url https://ca.example.com --fingerprint 3ef16343cf0952eedbe2b843066bb798fa7a7bceb16aa285e8b0399f661b28b7
```

And now we can sign sign a certificate as always:

```sh
step ca certificate test.example.com test.crt test.key
```
