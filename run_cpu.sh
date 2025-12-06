#!/bin/sh
cd "$('dirname' '--' "${0}")"
IMAGE_NAME="$(basename -- "$(realpath -- .)")"
podman run \
    -it --rm \
    '--device' '/dev/dri' \
    '--net' 'host' \
    '--security-opt' 'seccomp=unconfined' \
    --mount 'type=tmpfs,destination=/data/TMPFS,tmpfs-size=137438953472' \
    -v "$(realpath .):/data/source" \
    -v "${HOME}/BUILD:/data/build" \
    -v "CACHE:/usr/local/cargo/registry" \
    -v "CACHE:/root/.cache" \
    "${IMAGE_NAME}" zsh \
;
