#!/bin/sh

# Wait for CA
sleep 5

if [ ! -f /var/local/step/root_ca.crt ]; then
    # Donwload the root certificate
    step ca root /var/local/step/root_ca.crt
fi

if [ ! -f /var/local/step/site.crt ]; then
    # Get token
    STEP_TOKEN=$(step ca token $COMMON_NAME)
    # Donwload the root certificate
    step ca certificate --token $STEP_TOKEN $COMMON_NAME /var/local/step/site.crt /var/local/step/site.key
fi

exec "$@"