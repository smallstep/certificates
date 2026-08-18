# Kubernetes ServiceAccount TokenReview

The K8sSA provisioner can authenticate Kubernetes ServiceAccount tokens with
the Kubernetes TokenReview API. This mode is enabled when the provisioner does
not configure `publicKeys`:

```json
{
  "type": "K8sSA",
  "name": "k8sSA-default"
}
```

TokenReview mode expects `step-ca` to run inside the same Kubernetes cluster as
the ServiceAccounts it authenticates. It uses the standard in-cluster API
server environment variables, CA bundle, and mounted ServiceAccount token. The
reviewer token is read for every request so kubelet token rotation is picked up
without restarting `step-ca`.

## Grant TokenReview access

Apply [`rbac.yaml`](./rbac.yaml) and configure the `step-ca` Pod to use the
`step-ca` ServiceAccount. The only cluster-scoped permission is `create` on the
`tokenreviews` resource:

```sh
kubectl apply -f examples/kubernetes-tokenreview/rbac.yaml
```

## Mount a short-lived client token

Use a projected ServiceAccount token with an audience accepted by the `step-ca`
sign endpoint. The audience is normally the configured CA URL plus `/1.0/sign`.
For example, if the CA URL is `https://ca.example.com`, add this volume to the
client Pod:

```yaml
volumes:
  - name: step-ca-token
    projected:
      sources:
        - serviceAccountToken:
            path: token
            audience: https://ca.example.com/1.0/sign
            expirationSeconds: 600

containers:
  - name: client
    volumeMounts:
      - name: step-ca-token
        mountPath: /var/run/secrets/step-ca
        readOnly: true
```

The Kubernetes API server verifies the token's signature, lifetime, audience,
bound object, and ServiceAccount existence. `step-ca` additionally requires the
authenticated username returned by TokenReview to have the standard
`system:serviceaccount:<namespace>:<name>` form.

Use the projected token with the Smallstep CLI:

```sh
step ca certificate service.example.com service.crt service.key \
  --ca-url https://ca.example.com \
  --root /path/to/root_ca.crt \
  --k8ssa-token-path /var/run/secrets/step-ca/token
```

The K8sSA provisioner does not restrict the certificate Common Name or Subject
Alternative Names by itself. Use certificate name policy, templates, or
webhooks when certificate identities must be derived from the authenticated
namespace and ServiceAccount.

To keep the existing offline public-key validation mode, continue to configure
`publicKeys`. There is no fallback from TokenReview to public-key validation if
the Kubernetes API is unavailable.
