#!/bin/sh

while true; do
    inotifywait -e modify /var/local/step/site.crt
    nginx -s reload
done
