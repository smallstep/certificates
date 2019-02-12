#!/bin/bash
while :
do
  response=$(curl -sS \
    --cacert /var/run/autocert.step.sm/root.crt \
    --cert /var/run/autocert.step.sm/site.crt \
    --key /var/run/autocert.step.sm/site.key \
    ${HELLO_MTLS_URL})
  echo "$(date): ${response}"
  sleep 5
done