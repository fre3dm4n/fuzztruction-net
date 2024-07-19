#!/usr/bin/env bash

set -eu
set -o pipefail

export BUILD_TARGET="prebuilt"

./env/build.sh

exit 1

# Push Docker image to the given URL if set.
if [[ ! -z "$PREBUILT_PUSH_URL" ]]; then
    docker tag $PREBUILT_IMAGE_NAME $PREBUILT_PUSH_URL
    cmd="docker push $PREBUILT_PUSH_URL"
    echo "[+] Running $cmd"
    $cmd
fi
