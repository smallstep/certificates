#!/bin/bash
set -e

# TODO:
# - Parse params using argbash (argbash.io). Here's a template that I have tested but have not implemented yet:
# 
# ARG_OPTIONAL_SINGLE([ca-url], , [the URL of the upstream (issuing) step-ca server])
# ARG_OPTIONAL_SINGLE([fingerprint], , [the SHA256 fingerprint of the upstream peer step-ca server])
# ARG_OPTIONAL_SINGLE([provisioner-name], , [the name of a JWK provisioner on the upstream CA that this RA will use])
# ARG_OPTIONAL_SINGLE([provisioner-password-file], , [the name a file containing the upstream JWK provisioner password])
# ARG_OPTIONAL_REPEATED([dns-name], , [DNS name of this RA that will appear on its TLS certificate; you may pass this flag multiple times])
# ARG_OPTIONAL_SINGLE([listen-address], , [the address (and port #) this RA will listen on, eg. :443 or 127.0.0.1:4443])
# ARG_HELP([This script will install and configure a Registration Authority that connects to an upstream CA running step-ca.])
# ARGBASH_GO

echo "This script will install and start a step-ca server running in Registration Authority (RA) mode."
echo ""
echo "You will need an upstream CA (URL and fingerprint)"
echo "Don't have a CA? Sign up for a hosted CA at smallstep.com — or run your own."
echo ""

# Fail if this script is not run as root.
if ! [ $(id -u) = 0 ]; then
  echo "This script must be run as root"
  exit 1
fi

# Architecture detection
arch=$(uname -m)
case $arch in
  x86_64) arch="amd64" ;;
  x86) arch="386" ;;
  i686) arch="386" ;;
  i386) arch="386" ;;
  aarch64) arch="arm64" ;;
  armv5*) arch="armv5" ;;
  armv6*) arch="armv6" ;;
  armv7*) arch="armv7" ;;
esac

if ! hash jq &> /dev/null; then
  echo "This script requires the jq commmand; please install it."
  exit 1
fi

if ! hash curl &> /dev/null; then
  echo "This script requires the curl commmand; please install it."
  exit 1
fi

if ! hash tar &> /dev/null; then
  echo "This script requires the tar commmand; please install it."
  exit 1
fi

while [ $# -gt 0 ]; do
  case "$1" in
    --ca-url)
      CA_URL="$2"
      shift
      shift
      ;;
    --fingerprint)
      CA_FINGERPRINT="$2"
      shift
      shift
      ;;
    --provisioner-name)
      CA_PROVISIONER_NAME="$2"
      shift
      shift
      ;;
    --provisioner-password-file)
      CA_PROVISIONER_JWK_PASSWORD_FILE="$2"
      shift
      shift
      ;;
    --dns-names)
      RA_DNS_NAMES="$2"
      shift
      shift
      ;;
    --listen-address)
      RA_ADDRESS="$2"
      shift
      shift
      ;;
    *)
      shift
      ;;
  esac
done

# Install step
if ! hash step &> /dev/null; then
  echo "Installing 'step' in /usr/bin..."
  STEP_VERSION=$(curl -s https://api.github.com/repos/smallstep/cli/releases/latest | jq -r '.tag_name')

  curl -sLO https://github.com/smallstep/cli/releases/download/$STEP_VERSION/step_linux_${STEP_VERSION:1}_$arch.tar.gz
  tar xvzf step_linux_${STEP_VERSION:1}_$arch.tar.gz
  install -m 0755 -t /usr/bin step_${STEP_VERSION:1}/bin/step

  rm step_linux_${STEP_VERSION:1}_$arch.tar.gz
  rm -rf step_${STEP_VERSION:1}
fi

# Prompt for required parameters
if [ -z "$CA_URL" ]; then
  CA_URL=""
  while [[ $CA_URL = "" ]]; do
    read -p "Issuing CA URL: " CA_URL < /dev/tty
  done
fi

if [ -z "$CA_FINGERPRINT" ]; then
  CA_FINGERPRINT=""
  while [[ $CA_FINGERPRINT = "" ]]; do
    read -p "Issuing CA Fingerprint: " CA_FINGERPRINT < /dev/tty
  done
fi

echo "Bootstrapping with the CA..."
export STEPPATH=$(mktemp -d)

step ca bootstrap --ca-url $CA_URL --fingerprint $CA_FINGERPRINT

if [ -z "$CA_PROVISIONER_NAME" ]; then
  declare -a provisioners
  readarray -t provisioners < <(step ca provisioner list | jq -r '.[] | select(.type == "JWK") | .name')
  printf '%s\n' "${provisioners[@]}"

  printf "%b" "\nSelect a JWK provisioner:\n" >&2
  select provisioner in "${provisioners[@]}"; do
    if [ -n "$provisioner" ]; then
      echo "Using existing provisioner $provisioner."
      CA_PROVISIONER_NAME=$provisioner
      break
    else
      echo "Invalid selection!"
    fi
  done
fi

if [ -z "$RA_DNS_NAMES" ]; then
  RA_DNS_NAMES=""
  while [[ $RA_DNS_NAMES = "" ]]; do
    echo "What DNS names or IP addresses will your RA use?"
    read -p "(e.g. acme.example.com[,1.1.1.1,etc.]): " RA_DNS_NAMES < /dev/tty
  done
fi


count=0
ra_dns_names_quoted=""

for i in ${RA_DNS_NAMES//,/ }
do
  if [ "$count" = "0" ]; then
    ra_dns_names_quoted="\"$i\""
  else 
    ra_dns_names_quoted="${ra_dns_names_quoted}, \"$i\""
  fi
  count=$((count+1))
done

if [ "$count" = "0" ]; then
  echo "You must supply at least one RA DNS name"
  exit 1
fi

echo "Got here"

if [ -z "$RA_ADDRESS" ]; then
  RA_ADDRESS=""
  while [[ $RA_ADDRESS = "" ]] ; do
    echo "What address should your RA listen on?"
    read -p "(e.g. :443 or 10.2.1.201:4430): " RA_ADDRESS < /dev/tty
  done
fi

if [ -z "$CA_PROVISIONER_JWK_PASSWORD_FILE" ]; then
    read -s -p "Enter the CA Provisioner Password: " CA_PROVISIONER_JWK_PASSWORD < /dev/tty
    printf "%b" "\n"
fi

echo "Installing 'step-ca' in /usr/bin..."
CA_VERSION=$(curl -s https://api.github.com/repos/smallstep/certificates/releases/latest | jq -r '.tag_name')

curl -sLO https://github.com/smallstep/certificates/releases/download/$CA_VERSION/step-ca_linux_${CA_VERSION:1}_$arch.tar.gz
tar -xf step-ca_linux_${CA_VERSION:1}_$arch.tar.gz
install -m 0755 -t /usr/bin step-ca_${CA_VERSION:1}/bin/step-ca
setcap CAP_NET_BIND_SERVICE=+eip $(which step-ca)
rm step-ca_linux_${CA_VERSION:1}_$arch.tar.gz
rm -rf step-ca_${CA_VERSION:1}

echo "Creating 'step' user..."
export STEPPATH=/etc/step-ca

useradd --system --home $(step path) --shell /bin/false step

echo "Creating RA configuration..."
mkdir -p $(step path)/db
mkdir -p $(step path)/config

cat <<EOF > $(step path)/config/ca.json
{
  "address": "$RA_ADDRESS",
  "dnsNames": [$ra_dns_names_quoted],
  "db": {
    "type": "badgerV2",
    "dataSource": "/etc/step-ca/db"
  },
  "logger": {"format": "text"},
  "authority": {
    "type": "stepcas",
    "certificateAuthority": "$CA_URL",
    "certificateAuthorityFingerprint": "$CA_FINGERPRINT",
    "certificateIssuer": {
      "type" : "jwk",
      "provisioner": "$CA_PROVISIONER_NAME"
    },
    "provisioners": [{
      "type": "ACME",
      "name": "acme"
    }]
  },
  "tls": {
    "cipherSuites": [
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
       "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
    ],
    "minVersion": 1.2,
    "maxVersion": 1.3,
    "renegotiation": false
  }
}
EOF

if ! [ -z "$CA_PROVISIONER_JWK_PASSWORD" ]; then
  echo "Saving provisoiner password to $(step path)/password.txt..."
  echo $CA_PROVISIONER_JWK_PASSWORD > $(step path)/password.txt
else
  echo "Copying provisioner password file to $(step path)/password.txt..."
  cp $CA_PROVISIONER_JWK_PASSWORD_FILE $(step path)/password.txt
fi
chmod 440 $(step path)/password.txt

# Add a service to systemd for the RA.
echo "Creating systemd service step-ca.service..."
curl -sL https://raw.githubusercontent.com/smallstep/certificates/master/systemd/step-ca.service \
     -o /etc/systemd/system/step-ca.service

echo "Creating RA mode override /etc/systemd/system/step-ca.service.d/local.conf..."
mkdir /etc/systemd/system/step-ca.service.d
cat <<EOF > /etc/systemd/system/step-ca.service.d/local.conf 
[Service]
; The empty ExecStart= clears the inherited ExecStart= value
ExecStart=
ExecStart=/usr/bin/step-ca config/ca.json --issuer-password-file password.txt
EOF

echo "Starting step-ca.service..."
systemctl daemon-reload

chown -R step:step $(step path)

systemctl enable --now step-ca

echo "Adding STEPPATH export to /root/.bash_profile..."
echo "export STEPPATH=$STEPPATH" >> /root/.bash_profile

echo "Finished. Check the journal with journalctl -fu step-ca.service"

