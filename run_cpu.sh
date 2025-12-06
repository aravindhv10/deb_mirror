#!/bin/sh
cd "$('dirname' '--' "${0}")"
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
    '6_pytorch' zsh \
;
