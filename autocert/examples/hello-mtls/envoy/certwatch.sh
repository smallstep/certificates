#!/bin/sh

while true; do
    inotifywait -e modify /var/run/autocert.step.sm/site.crt
    kill -HUP 1
done
