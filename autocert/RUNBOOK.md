# Runbook

## Common admin tasks

#### Recover `admin` and CA password

```
kubectl -n step get secret ca-password -o jsonpath='{$.data.password}' | base64 -D
```

#### Recover `autocert` password

```
kubectl -n step get secret autocert-password -o jsonpath='{$.data.password}' | base64 -D
```

#### Recompute root certificate fingerprint

```
export CA_POD=$(kubectl -n step get pods -l app=ca -o jsonpath={$.items[0].metadata.name})
kubectl -n step exec -it $CA_POD step certificate fingerprint /home/step/.step/certs/root_ca.crt
```

> Tip: Some slight fanciness is necessary to trim this string if you want to put it into an environment variable:
>
> ```
> export FINGERPRINT="$(kubectl -n step exec -it $CA_POD step certificate fingerprint /home/step/.step/certs/root_ca.crt | tr -d '[:space:]')"
> ```

#### Inspect a certificate

```
kubectl exec -it <pod> -c autocert-renewer -- step certificate inspect /var/run/autocert.step.sm/site.crt
```

#### Labelling a namespace (enabling `autocert` for a namespace)

To enable `autocert` for a namespace it must be labelled. To label an existing namespace run:

```
kubectl label namespace <namespace> autocert.step.sm=enabled
```

#### Checking which namespaces are labelled

```
kubectl get namespace -L autocert.step.sm
```

#### Removing a label from a namespace (disabling `autocert` for a namespace)

```
kubectl label namespace <namespace> autocert.step.sm-
```

#### Naming considerations

Use hostnames. Must be global. Everyone who connects to the service using mTLS must use the same hostname. For internal communication it's easy enough to use the FQDN of a service. For stuff you expose publicly you'll need to manage DNS yourself...

In any case, the critical invariant is: ...

Diagram here?

#### Cleaning up one-time token secrets

```
for ns in $(kubectl get namespace --selector autocert.step.sm=enabled -o jsonpath='{$.items[*].metadata.name}'); do
  kubectl -n "$ns" delete secrets --selector="autocert.step.sm/token=true"
done
```

### TODO:
* Change admin password
* Change autocert password
* Federating with another CA
* DNS tips and tricks
* Multiple SANs
* Getting rid of the sidecar
* Getting logs from the CA (certificates weren't issued)
* Getting logs from the init container / renewer (didn't start properly)
* Adjusting certificate expiration (default 24h)
* Remove label
* Clean up secrets
* Naming considerations (maybe this should be in hello-mtls)

## Federation

TODO: Example of federating a CA running in kubernetes with another CA.

For now, see https://smallstep.com/blog/step-v0.8.3-federation-root-rotation.html

## Multiple intermediates

TODO: Example of creating an additional intermediate signing certificate off of our kubernetes root CA.

For now, see https://smallstep.com/docs/cli/ca/init/ (specifically, the `--root` flag)

## Exposing the CA

Beware that the CA exposes an unauthenticated endpoint that lists your configured provisioners and their encrypted private keys. For this reason, you may not want to expose it directly to the public internet.

## Uninstalling

To uninstall `autocert` completely simply delete the mutating webhook configuration, the `step` namespace and the `autocert` RBAC artifacts:

```
kubectl delete mutatingwebhookconfiguration autocert-webhook-config
kubectl delete namespace step
kubectl delete clusterrolebinding autocert-controller
kubectl delete clusterrole autocert-controller
```

Remove any namespace labels and clean up any stray secrets that `autocert` hasn't cleaned up yet:

```
for ns in $(kubectl get namespace --selector autocert.step.sm=enabled -o jsonpath='{$.items[*].metadata.name}'); do
  kubectl label namespace "$ns" autocert.step.sm-
  kubectl -n "$ns" delete secrets --selector="autocert.step.sm/token=true"
done
```

Any remaining sidecar containers will go away once you remove annotations and re-deploy your workloads.