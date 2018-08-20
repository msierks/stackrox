#!/usr/bin/env bash
set -e

export CLUSTER_API_ENDPOINT="${CLUSTER_API_ENDPOINT:-central.stackrox:443}"
echo "In-cluster Central endpoint set to $CLUSTER_API_ENDPOINT"

export PREVENT_IMAGE_TAG=${PREVENT_IMAGE_TAG:-$(git describe --tags --abbrev=10 --dirty)}
export PREVENT_IMAGE=${PREVENT_IMAGE:-stackrox/prevent:$PREVENT_IMAGE_TAG}
echo "PREVENT_IMAGE set to $PREVENT_IMAGE"

export RUNTIME_SUPPORT=${RUNTIME_SUPPORT:-false}
echo "RUNTIME_SUPPORT set to $RUNTIME_SUPPORT"
