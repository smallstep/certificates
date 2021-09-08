#!/bin/bash
set -eo pipefail

# Paraphrased from:
# https://github.com/influxdata/influxdata-docker/blob/0d341f18067c4652dfa8df7dcb24d69bf707363d/influxdb/2.0/entrypoint.sh
# (a repo with no LICENSE.md)

export STEPPATH=$(step path)

function generate_password () {
    set +o pipefail
    < /dev/urandom tr -dc A-Za-z0-9 | head -c40
    echo
    set -o pipefail
}

# Initialize a CA if not already initialized
function step_ca_init () {
    local -a setup_args=(
        --name "${DOCKER_STEPCA_INIT_NAME:-Smallstep}"
		--provisioner "${DOCKER_STEPCA_INIT_PROVISIONER_NAME:-admin}"
		--password-file "${STEPPATH}/password"
        --address ":9000"
    )
    if [ -n "${DOCKER_STEPCA_INIT_PASSWORD}" ]; then
        echo "${DOCKER_STEPCA_INIT_PASSWORD}" > "${STEPPATH}/password"
    else
        generate_password > "${STEPPATH}/password"
    fi

    if [ -n "${DOCKER_STEPCA_INIT_SSH}" ]; then
        setup_args=("${setup_args[@]}" --ssh)
    fi

    if [ -n "${DOCKER_STEPCA_INIT_DNS_NAMES}" ]; then
		setup_args=("$[setup_args[@]}" --dns "localhost" --dns "127.0.0.1" --dns "[::1]")
	fi	

	IFS=',' read -r -a dns_names <<< "${DOCKER_STEPCA_INIT_DNS_NAMES}"
	for dns_name in "${dns_names[@]}"
	do
		setup_args=("${setup_args[@]}" --dns "$dns_name")
	done
	step ca init "${setup_args[@]}"
    mv $STEPPATH/password $PWDPATH
}

if [ ! -f "${STEPPATH}/config/ca.json" ]; then
	>&2 echo "There is no ca.json config file; running 'step ca init'."
	step_ca_init "${@}"
fi

exec "${@}"
