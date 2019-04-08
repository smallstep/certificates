# Installing `autocert`

### Prerequisites

To get started you'll need [`kubectl`](https://kubernetes.io/docs/tasks/tools/install-kubectl/#install-kubectl) and a cluster running kubernetes `1.9` or later with [admission webhooks](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#admission-webhooks) enabled:

```bash
$ kubectl version --short
Client Version: v1.13.1
Server Version: v1.10.11
$ kubectl api-versions | grep "admissionregistration.k8s.io/v1beta1"
admissionregistration.k8s.io/v1beta1
```

### Install

The easiest way to install `autocert` is to run:

```bash
kubectl run autocert-init -it --rm --image smallstep/autocert-init --restart Never
```

💥 installation complete.

> You might want to [check out what this command does](init/autocert.sh) before running it.

## Manual install

To install manually you'll need to [install step](https://github.com/smallstep/cli#installing) version `0.8.3` or later.

```
$ step version
Smallstep CLI/0.8.3 (darwin/amd64)
Release Date: 2019-01-16 01:46 UTC
```

### Create a CA

Set your `STEPPATH` to a working directory where we can stage our CA artifacts before we push them to kubernetes. You can delete this directory once installation is complete.

```
$ export STEPPATH=$(mktemp -d /tmp/step.XXX)
$ step path
/tmp/step.0kE
```

Run `step ca init` to generate a root certificate and CA configuration for your cluster. You'll be prompted for a password that will be used to encrypt key material.

```
$ step ca init \
    --name Autocert \
    --dns "ca.step.svc.cluster.local,127.0.0.1" \
    --address ":4443" \
    --provisioner admin \
    --with-ca-url "ca.step.svc.cluster.local"
```

For older versions of `step` run this command without the flags.

Add provisioning credentials for use by `autocert`. You'll be prompted for a password for `autocert`.

```
$ step ca provisioner add autocert --create
```

For older versions of `step`:

* Run `step ca init` and follow prompts
* Edit `$(step path)/config/ca.json` and change base paths to `/home/step`
* Edit `$(step path)/config/defaults.json` to change base paths to `/home/step` and remove port from CA URL

```
$ sed -i "" "s|$(step path)|/home/step/.step|g" $(step path)/config/ca.json
$ sed -i "" "s|$(step path)|/home/step/.step|g" $(step path)/config/defaults.json
$ sed -i "" "s|ca.step.svc.cluster.local:4443|ca.step.svc.cluster.local|" $(step path)/config/defaults.json
```

### Install the CA in Kubernetes

We'll be creating a new kubernetes namespace and setting up some RBAC rules during installation. You'll need appropriate permissions in your cluster (e.g., you may need to be cluster-admin). GKE, in particular, does not give the cluster owner these rights by default. You can give yourself cluster-admin rights on GKE by running:

```bash
kubectl create clusterrolebinding cluster-admin-binding \
    --clusterrole cluster-admin \
    --user $(gcloud config get-value account)
```

We'll install our CA and the `autocert` controller in the `step` namespace.

```
$ kubectl create namespace step
```

To install the CA we need to configmap the CA certificates, signing keys, and configuration artifacts. Note that key material is encrypted so we don't need to use secrets.

```
$ kubectl -n step create configmap config --from-file $(step path)/config
$ kubectl -n step create configmap certs --from-file $(step path)/certs
$ kubectl -n step create configmap secrets --from-file $(step path)/secrets
```

But we will need to create secrets for the CA and autocert to decrypt their keys:

```
$ kubectl -n step create secret generic ca-password --from-literal password=<ca-password>
$ kubectl -n step create secret generic autocert-password --from-literal password=<autocert-password>
```

Where `<ca-password>` is the password you entered during `step ca init` and `<autocert-password>` is the password you entered during `step ca provisioner add`.

Next, we'll install the CA.

```
$ kubectl apply -f https://raw.githubusercontent.com/smallstep/certificates/master/autocert/install/01-step-ca.yaml
```

Once you've done this you can delete the temporary `$STEPPATH` directory and `unset STEPPATH` (though you may want to retain it as a backup).

### Install `autocert` in Kubernetes

Install the `autocert` controller.

```
$ kubectl apply -f https://raw.githubusercontent.com/smallstep/certificates/master/autocert/install/02-autocert.yaml
```

Autocert creates secrets containing single-use bootstrap tokens for pods to authenticate with the CA and obtain a certificate. The tokens are automatically cleaned up after they expire. To do this, `autocert` needs permission to create and delete secrets in your cluster.

If you have RBAC enabled in your cluster, apply `rbac.yaml` to give `autocert` these permissions.

```
$ kubectl apply -f https://raw.githubusercontent.com/smallstep/certificates/master/autocert/install/03-rbac.yaml
```

Finally, register the `autocert` mutation webhook with kubernetes.

```
$ cat <<EOF | kubectl apply -f -
apiVersion: admissionregistration.k8s.io/v1beta1
kind: MutatingWebhookConfiguration
metadata:
  name: autocert-webhook-config
  labels: {app: autocert}
webhooks:
  - name: autocert.step.sm
    clientConfig:
      service:
        name: autocert
        namespace: step
        path: "/mutate"
      caBundle: $(cat $(step path)/certs/root_ca.crt | base64)
    rules:
      - operations: ["CREATE"]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
    failurePolicy: Ignore
    namespaceSelector:
      matchLabels:
        autocert.step.sm: enabled
EOF
```

### Check your work

If everything  worked you should have CA and controller pods running in the `step` namespace and your webhook configuration should be installed:

```
$ kubectl -n step get pods
NAME                          READY   STATUS    RESTARTS   AGE
ca-7577d7d667-vtfq5           1/1     Running   0          1m
controller-86bd99bd96-s9zlc   1/1     Running   0          28s
$ kubectl get mutatingwebhookconfiguration
NAME                      CREATED AT
autocert-webhook-config   2019-01-17T22:57:57Z
```

### Move on to usage instructions

Make sure to follow the autocert usage steps at https://github.com/smallstep/certificates/tree/master/autocert#usage
