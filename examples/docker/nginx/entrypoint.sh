#!/bin/sh

# watch for the update of the cert and reload nginx
/certwatch.sh &

# Run docker CMD
exec "$@"