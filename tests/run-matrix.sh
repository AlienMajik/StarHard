#!/usr/bin/env bash
# tests/run-matrix.sh [image ...]
# Runs tests/checks.sh against StarHard in throw-away containers, one per distro family.
# Needs podman or docker. Logs: tests/logs/<image>.log     Engine override: ENGINE=docker tests/run-matrix.sh
set -u
cd "$(dirname "$0")/.." || exit 2
ENGINE="${ENGINE:-$(command -v podman || command -v docker || true)}"
[[ -n "$ENGINE" ]] || { echo "podman or docker is required" >&2; exit 2; }
IMAGES=("$@")
if [[ ${#IMAGES[@]} -eq 0 ]]; then
    IMAGES=(
        docker.io/library/debian:12
        docker.io/library/ubuntu:24.04
        docker.io/library/fedora:41
        docker.io/rockylinux/rockylinux:9
        docker.io/opensuse/leap:15.6
        docker.io/library/archlinux:latest
        docker.io/library/alpine:3.20
    )
fi
mkdir -p tests/logs
rc_all=0
declare -a summary=()
for img in "${IMAGES[@]}"; do
    name="${img##*/}"; name="${name//:/-}"
    echo ">>> $img"
    if "$ENGINE" run --rm -v "$PWD:/src:ro" "$img" sh /src/tests/in-container.sh > "tests/logs/$name.log" 2>&1; then
        summary+=("PASS  $img")
    else
        summary+=("FAIL  $img   (tests/logs/$name.log)"); rc_all=1
        grep -E '^  FAIL|^RESULT' "tests/logs/$name.log" | sed 's/^/    /'
    fi
done
echo
printf '%s\n' "${summary[@]}"
exit $rc_all
