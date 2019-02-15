#!/bin/sh

while true; do
    inotifywait -e modify /var/run/autocert.step.sm/site.crt
    nginx -s reload
done
