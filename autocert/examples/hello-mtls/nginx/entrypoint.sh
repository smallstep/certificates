#!/bin/sh

# Wait for renewer
sleep 10

# watch for the update of the cert and reload nginx
/src/certwatch.sh &

# Run docker CMD
exec "$@"