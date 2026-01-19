#!/usr/bin/env sh
read -r firstline < .VERSION
last_half="${firstline##*tag: }"
case "$last_half" in
    v*)
        version_string="${last_half%%[,)]*}"
        ;;
esac
echo "${version_string:-v0.0.0}"
