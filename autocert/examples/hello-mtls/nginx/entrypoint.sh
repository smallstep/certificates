#!/bin/sh

# watch for the update of the cert and reload nginx
/src/certwatch.sh &

# Run docker CMD
exec "$@"