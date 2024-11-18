#!/usr/bin/env bash

set -e

: ${GCLOUD_LOCATION:=us-central1}
: ${GCLOUD_RPM_REPO:=rpms}
: ${GCLOUD_DEB_REPO:=debs}

PACKAGE="${1}"
VERSION="${2}"
RELEASE="1"
EPOCH="0"
GORELEASER_PHASE=${GORELEASER_PHASE:-release}

echo "Package: ${PACKAGE}"
echo "Version: ${VERSION}"

check_package() {
  local EXITCODE=0
  local REPO="${1}"
  local VER="${2}"
  if [ ! -f /tmp/version-deleted.stamp ]; then
    gcloud artifacts versions list \
       --repository "${REPO}" \
       --location "${GCLOUD_LOCATION}" \
       --package "${PACKAGE}" \
       --filter "VERSION:${VER}" \
       --format json  2> /dev/null \
       | jq -re '.[].name?' >/dev/null 2>&1 \
       || EXITCODE=$?
    if [[ "${EXITCODE}" -eq 0 ]]; then
      echo "Package version already exists. Removing it..."
      gcloud artifacts versions delete \
      --quiet "${VER}" \
      --package "${PACKAGE}" \
      --repository "${REPO}" \
      --location "${GCLOUD_LOCATION}"
      touch /tmp/version-deleted.stamp
    fi
  fi
}

if [[ ${IS_PRERELEASE} == "true" ]]; then
  echo "Skipping artifact import; IS_PRERELEASE is 'true'"
  exit 0;
fi

check_package "${GCLOUD_RPM_REPO}" "${EPOCH}:${VERSION}-${RELEASE}"
gcloud artifacts yum import "${GCLOUD_RPM_REPO}" \
  --location "${GCLOUD_LOCATION}" \
  --gcs-source "gs://artifacts-outgoing/${PACKAGE}/rpm/${VERSION}/*"

check_package ${GCLOUD_DEB_REPO} "${VERSION}-${RELEASE}"}
gcloud artifacts apt import "${GCLOUD_DEB_REPO}" \
  --location "${GCLOUD_LOCATION}" \
  --gcs-source "gs://artifacts-outgoing/${PACKAGE}/deb/${VERSION}/*"
