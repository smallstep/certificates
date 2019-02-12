#!/bin/sh

# start hello world app
python3 /src/server.py &

# watch for the update of the cert and reload nginx
/src/certwatch.sh &

# Run docker CMD
exec "$@"