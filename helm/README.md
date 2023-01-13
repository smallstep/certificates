# Step Certificates

An online certificate authority and related tools for secure automated
certificate management, so you can use TLS everywhere.

To learn more, visit <https://github.com/smallstep/certificates>.

## TL;DR

```console
helm repo add smallstep https://smallstep.github.io/helm-charts/
step ca init --helm > values.yaml
echo "password" | base64 > password.txt
helm install -f values.yaml \
     --set inject.secrets.ca_password=$(cat password.txt) \
     --set inject.secrets.provisioner_password=$(cat password.txt) \
     --set service.targetPort=9000 \
     step-certificates smallstep/step-certificates
```

## Prerequisites

- Kubernetes 1.10+

## Installing the Chart

To install the chart with the release name `my-release`:

```console
helm install my-release smallstep/step-certificates
```

The command deploys Step certificates on the Kubernetes cluster in the default
configuration. The [configuration](#configuration) section lists the parameters
that can be configured during installation.

> **Tip**: List all releases using `helm list`

## Uninstalling the Chart

To uninstall the `my-release` deployment:

```console
helm uninstall my-release
```

The command removes all the Kubernetes components associated with the chart and
deletes the release.

## Linked CA

Linked CA is an instance of `step-ca` that you run that connects to your
[Certificate Manager](https://smallstep.com/certificate-manager/)) account for
reporting, alerting, revocation, and other managed services.

When you create a Linked CA authority, you will get a token that you will use to
connect your instance to it.

There're two ways to configure the token. You can define the value for `linkedca.token`:

```console
helm install --set linkedca.token=xxx \
  step-certificates smallstep/step-certificates
```

Or set the reference to another secret managed with your preferred
infrastructure automation tool.

```console
helm install \
  --set linkedca.secretKeyRef.name=my-secret-name \
  --set linkedca.secretKeyRef.key=my-key-name \
  step-certificates smallstep/step-certificates
```

## Configuration

The easiest way to configure step-certificates is to use [step](https://github.com/smallstep/cli).

Starting with `step` v0.17+ and `step-certificates` Chart v1.17+, you can use
`step ca init` to create a values.yaml that you can use to configure your CA:

```console
$ step ca init --helm > values.yaml
✔ Deployment Type: Standalone
What would you like to name your new PKI?
✔ (e.g. Smallstep): Smallstep
What DNS names or IP addresses would you like to add to your new CA?
✔ (e.g. ca.smallstep.com[,1.1.1.1,etc.]): step-certificates.default.svc.cluster.local
What IP and port will your new CA bind to (it should match service.targetPort)?
✔ (e.g. :443 or 127.0.0.1:443): :9000
What would you like to name the CA's first provisioner?
✔ (e.g. you@smallstep.com): me@example.org
Choose a password for your CA keys and first provisioner.
✔ [leave empty and we'll generate one]:

Generating root certificate... done!
Generating intermediate certificate... done!
```

By default, the values.yaml won't contain the password used to encrypt the keys,
nor the password of the default provisioner, so we have to pass it as values
using the base64 encoding. And the port where the CA binds to, in the example,
`:9000` must be set as `service.targetPort=9000`.

```console
echo "password" | base64 > password.txt
helm install -f values.yaml \
     --set inject.secrets.ca_password=$(cat password.txt) \
     --set inject.secrets.provisioner_password=$(cat password.txt) \
     --set service.targetPort=9000 \
     step-certificates smallstep/step-certificates
```

With this method, the automatic bootstrap of the PKI is deprecated and it will
be removed in future releases.


### Advanced configuration

In some circumstainces it is not an option to use Helm install or to inject secrets at the command line. For example when using GitOps / ArgoCD.
Secrets and configurations can be provided before the helm chart is deployed by defining `existingSecrets` in the values file:

```
existingSecrets: 
  enabled: true
  ca: true
  issuer: true
  configAsSecret: true
  sshHostCa: true
  sshUserCa: true

bootstrap:
  secrets: false
  enabled: false
  configmaps: false

inject:
  enabled: false
```

Enabling `existingSecrets` can't be combined with enabling `bootstrap` nor `inject` elements from helm chart.
Therefore the bootstrap and inject are disabled in the example above.

Note, the MutatingWebhookConfiguration created by autocert is not patched with CA bundle as the bootstrap init-container is not started when `existingSecrets` are enabled.

The following naming conventions are used for secret names:  

secret name: `{{ include "step-certificates.fullname" . }}-secrets`  
which contains:
- `intermediate_ca_key`
- `root_ca_key`
- `certificate_issuer_key` (optional)
- `ssh_host_ca_key` (optional)
- `ssh_user_ca_key` (optional)

When `existingSecrets.configAsSecret` is `true`  
secret name: `{{ include "step-certificates.fullname" . }}-config`  
which contains:
- `ca.json`
- `default.json`

When `existingSecrets.ca` is `true`  
secret name: `{{ include "step-certificates.fullname" . }}-ca-password`  
secret type: `smallstep.com/ca-password`  
which contains `password`

When `existingSecrets.issuer` is `true`  
secret name: `{{ include "step-certificates.fullname" . }}--certificate-issuer-password`  
secret type: `smallstep.com/certificate-issuer-password`  
which contains `password`

When `existingSecrets.sshHostCa` is `true`  
secret name: `{{ include "step-certificates.fullname" . }}-ssh-host-ca-password`  
secret type: `smallstep.com/ssh-host-ca-password`  
which contains `password`

When `existingSecrets.sshUserCa` is `true`  
secret name: `{{ include "step-certificates.fullname" . }}-ssh-user-ca-password`  
secret type: `smallstep.com/ssh-user-ca-password`  
which contains `password`

Further more the secret name `{{ include "step-certificates.fullname" . }}-provisioner-password` is used for the password used to encrypt JWK provisioner.  


### Configuration parameters

The following table lists the configurable parameters of the Step certificates
chart and their default values.

| Parameter                     | Description                                                                                                 | Default                                  |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| `ca.name`                     | Name for you CA                                                                                             | `Step Certificates`                      |
| `ca.address`                  | TCP address where Step CA runs                                                                              | `:9000`                                  |
| `ca.dns`                      | DNS of Step CA, if empty it will be inferred                                                                | `""`                                     |
| `ca.url`                      | URL of Step CA, if empty it will be inferred                                                                | `""`                                     |
| `ca.password`                 | Password for the CA keys, if empty it will be automatically generated                                       | `""`                                     |
| `ca.provisioner.name`         | Name for the default provisioner                                                                            | `admin`                                  |
| `ca.provisioner.password`     | Password for the default provisioner, if empty it will be automatically generated                           | `""`                                     |
| `ca.db.enabled`               | If true, step certificates will be configured with a database                                               | `true`                                   |
| `ca.db.persistent`            | If true a persistent volume will be used to store the db                                                    | `true`                                   |
| `ca.db.accessModes`           | Persistent volume access mode                                                                               | `["ReadWriteOnce"]`                      |
| `ca.db.size`                  | Persistent volume size                                                                                      | `10Gi`                                   |
| `ca.db.existingClaim`         | Persistent volume existing claim name. If defined, PVC must be created manually before volume will be bound | `""`                                     |
| `ca.kms.type`                 | Key management system to use.                                                                               | `""`                                     |
| `ca.env`                      | Environment variables to set in `step-certificates` container.                                              | `[]`                                     |
| `ca.runAsRoot`                | Run the CA as root.                                                                                         | `false`                                  |
| `ca.bootstrap.postInitHook`   | Extra script snippet to run after `step ca init` has completed.                                             | `""`                                     |
| `linkedca.token`              | The token used to configure step-ca using the linkedca mode.                                                | `""`                                     |
| `linkedca.secretKeyRef.name`  | The secret name where the linkedca token can be found.                                                      | `""`                                     |
| `linkedca.secretKeyRef.key`   | The secret key where the linkedca token can be found.                                                       | `""`                                     |
| `service.type`                | Service type                                                                                                | `ClusterIP`                              |
| `service.port`                | Incoming port to access Step CA                                                                             | `443`                                    |
| `service.nodePort`            | Incoming port to access Step CA                                                                             | `""`                                     |
| `service.targetPort`          | Internal port where Step CA runs                                                                            | `9000`                                   |
| `service.annotations`         | Service annotations (YAML)                                                                                  | `{}`                                     |
| `replicaCount`                | Number of Step CA replicas. Only one replica is currently supported.                                        | `1`                                      |
| `image.repository`            | Repository of the Step CA image                                                                             | `cr.step.sm/smallstep/step-ca`           |
| `image.initContainerRepository` | Repository of the Step CA Init Container image.                                                           | `busybox:latest`                         |
| `image.tag`                   | Tag of the Step CA image                                                                                    | `latest`                                 |
| `image.pullPolicy`            | Step CA image pull policy                                                                                   | `IfNotPresent`                           |
| `bootstrap.image.repository`  | Repository of the Step CA bootstrap image                                                                   | `cr.step.sm/smallstep/step-ca-bootstrap` |
| `bootstrap.image.tag`         | Tag of the Step CA bootstrap image                                                                          | `latest`                                 |
| `bootstrap.image.pullPolicy`  | Step CA bootstrap image pull policy                                                                         | `IfNotPresent`                           |
| `bootstrap.enabled`           | If false, it does not create the bootstrap job.                                                             | `true`                                   |
| `bootstrap.configmaps`        | If false, it does not create the configmaps.                                                                | `true`                                   |
| `bootstrap.secrets`           | If false, it does not create the secrets.                                                                   | `true`                                   |
| `nameOverride`                | Overrides the name of the chart                                                                             | `""`                                     |
| `fullnameOverride`            | Overrides the full name of the chart                                                                        | `""`                                     |
| `ingress.enabled`             | If true Step CA ingress will be created                                                                     | `false`                                  |
| `ingress.annotations`         | Step CA ingress annotations (YAML)                                                                          | `{}`                                     |
| `ingress.hosts`               | Step CA ingress hostNAMES (YAML)                                                                            | `[]`                                     |
| `ingress.tls`                 | Step CA ingress TLS configuration (YAML)                                                                    | `[]`                                     |
| `resources`                   | CPU/memory resource requests/limits (YAML)                                                                  | `{}`                                     |
| `nodeSelector`                | Node labels for pod assignment (YAML)                                                                       | `{}`                                     |
| `tolerations`                 | Toleration labels for pod assignment (YAML)                                                                 | `[]`                                     |
| `affinity`                    | Affinity settings for pod assignment (YAML)                                                                 | `{}`                                     |
| `inject.enabled`              | When true, configuration files and templates are injected into a Kubernetes objects and bootstrap capability is disabled.                      | `false`                                  |
| `inject.config.files.ca.json` | Yaml representation of the step-ca ca.json file.  This map object is converted to its equivalent json representation before being injected into a configMap.  See the step-ca [documentation](https://smallstep.com/docs/step-ca/configuration). | See [values.yaml](./values.yaml) |
| `inject.config.files.default.json` | Yaml representation of the step-cli defaults.json file.  This map object is converted to its equivalent json representation before being injected into a configMap.  See the step-cli [documentation](https://smallstep.com/docs/step-cli/reference). | See [values.yaml](./values.yaml) |
| `inject.config.templates.x509_leaf.tpl`   | Example X509 Leaf Certifixate Template to inject into the configMap.                            | See [values.yaml](./values.yaml)         |
| `inject.config.templates.ssh.tpl`         | Example SSH Certificate Template to inject into the configMap.                                  | See [values.yaml](./values.yaml)         |
| `inject.certificates.intermediate_ca`     | Plain text PEM representation of the intermediate CA certificate.                               | `""`                                     |
| `inject.certificates.root_ca`             | Plain text PEM representation of the root CA certificate.                                       | `""`                                     |
| `inject.certificates.ssh_host_ca`         | Plain text representation of the ssh host CA public key.                                        | `""`                                     |
| `inject.certificates.ssh_user_ca`         | Plain text representation of the ssh user CA public key.                                        | `""`                                     |
| `inject.secrets.ca_password`              | Base64 encoded string.  Password used to encrypt intermediate and ssh keys.                     | `Cg==`                                   |
| `inject.secrets.provisioner_password`     | Base64 encoded string.  Password used to encrypt JWK provisioner.                               | `Cg==`                                   |
| `inject.secrets.x509.intermediate_ca_key` | Plain text PEM representation of the intermediate CA private key.                               | `""`                                     |
| `inject.secrets.x509.root_ca_key`         | Plain text PEM representation of the root CA private key.                                       | `""`                                     |
| `inject.secrets.ssh.host_ca_key`          | Plain text representation of the ssh host CA private key.                                       | `""`                                     |
| `inject.secrets.ssh.user_ca_key`          | Plain text representation of the ssh user CA private key.                                       | `""`                                     |
| `existingSecrets.enabled`                 | Use secrets and configurations from existing secrets created outside of this chart              | `false`                                  |
| `existingSecrets.ca`                      | When `true`use existing secret for the ca-password.                                             | `false`                                  |
| `existingSecrets.issuer`                  | When `true`use existing secret for the issuer.                                                  | `false`                                  |
| `existingSecrets.sshHostCa`               | When `true`use existing secret for the ssh host CA public key.                                  | `false`                                  |
| `existingSecrets.sshUserCa`               | When `true`use existing secret for the ssh user CA public key.                                  | `false`                                  |
| `existingSecrets.configAsSecret`          | When `true`use existing secret for configuration instead of ConfigMap                           | `false`                                  |


Specify each parameter using the `--set key=value[,key=value]` argument to `helm
install`. For example,

```console
helm install --set provisioner.password=secretpassword,provisioner.name=Foo \
  my-release step-certificates
```

The above command sets the Step Certificates main provisioner `Foo` with the key
password `secretpassword`.

If you provide a custom value for `ca.dns`, be sure to append
`,{{fullname}}.{{namespace}}.svc.cluster.local,127.0.0.1` to the end, otherwise
accessing the CA by those DNS/IPs will fail (services internal to the cluster):

```console
helm install --set ca.dns="ca.example.com\,my-release-step-certificates.default.svc.cluster.local\,127.0.0.1" \
  my-release step-certificates
```

Alternatively, a YAML file that specifies the values for the parameters can be
provided while installing the chart. For example,

```console
helm install -f values.yaml my-release step-certificates
```

> **Tip**: You can use the default [values.yaml](values.yaml)

## Notes

At this moment only one replica is supported, step certificates supports
multiple ones using MariaDB or MySQL.


# Development

Testing chart by using an example yaml file:
```
helm template . -f examples/existing_secrets/value.yaml | kubectl apply -f - --dry-run=client
```
