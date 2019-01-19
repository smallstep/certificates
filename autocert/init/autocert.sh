#!/bin/bash

#set -x
set -e

echo "Welcome to Autocert configuration. Press any key to begin."
read ANYKEY

STEPPATH=/home/step/.step

CA_PASSWORD=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32 ; echo '')
AUTOCERT_PASSWORD=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32 ; echo '')

step ca init \
  --name "$CA_NAME" \
  --dns "$CA_DNS" \
  --address "$CA_ADDRESS" \
  --provisioner "$CA_DEFAULT_PROVISIONER" \
  --with-ca-url "$CA_URL" \
  --password-file <(echo "$CA_PASSWORD")

echo
echo -e "\e[1mCreating autocert provisioner...\e[0m"

expect <<EOD
spawn step ca provisioner add autocert --create
expect "Please enter a password to encrypt the provisioner private key? \\\\\\[leave empty and we'll generate one\\\\\\]: "
send "${AUTOCERT_PASSWORD}\n"
expect eof
EOD

echo
echo -e "\e[1mCreating step namespace and preparing environment...\e[0m"

kubectl create namespace step

kubectl -n step create configmap config --from-file $(step path)/config
kubectl -n step create configmap certs --from-file $(step path)/certs
kubectl -n step create configmap secrets --from-file $(step path)/secrets

kubectl -n step create secret generic ca-password --from-literal "password=${CA_PASSWORD}"
kubectl -n step create secret generic autocert-password --from-literal "password=${AUTOCERT_PASSWORD}"

# Deploy CA and wait for rollout to complete
echo
echo -e "\e[1mDeploying certificate authority...\e[0m"

kubectl apply -f https://raw.githubusercontent.com/smallstep/certificates/autocert/autocert/install/01-step-ca.yaml
kubectl -n step rollout status deployment/ca

# Deploy autocert, setup RBAC, and wait for rollout to complete
echo
echo -e "\e[1mDeploying autocert...\e[0m"

kubectl apply -f https://raw.githubusercontent.com/smallstep/certificates/autocert/autocert/install/02-autocert.yaml
kubectl apply -f https://raw.githubusercontent.com/smallstep/certificates/autocert/autocert/install/03-rbac.yaml
kubectl -n step rollout status deployment/autocert

# Some `base64`s wrap lines... no thanks!
CA_BUNDLE=$(cat $(step path)/certs/root_ca.crt | base64 | tr -d '\n')

cat <<EOF | kubectl apply -f -
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
      caBundle: $CA_BUNDLE
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

echo
echo -e "\e[1mAutocert installed!\e[0m"
echo
echo "Store these passwords somewhere safe:"
echo "  CA & admin provisioner password: $CA_PASSWORD"
echo "  Autocert password: $AUTOCERT_PASSWORD"
echo

