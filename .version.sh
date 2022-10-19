#!/usr/bin/env sh
read -r firstline < .VERSION
last_half="${firstline##*tag: }"
if [[ ${last_half::1} == "v" ]]; then
    version_string="${last_half%%[,)]*}"
fi
echo "${version_string:-v0.0.0}"
