#!/bin/sh
# Runs inside a throw-away container (started by tests/run-matrix.sh). Installs the few tools a real
# install always has but a base image lacks, then hands over to tests/checks.sh.
set -e
if command -v apk >/dev/null 2>&1; then
    apk add -q bash coreutils iproute2 procps util-linux grep sed gawk findutils shadow sudo openssh-server python3 kmod >/dev/null
elif command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null
    apt-get install -y -qq iproute2 procps kmod sudo openssh-server python3 libpam-pwquality >/dev/null
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q iproute procps-ng kmod findutils util-linux sudo openssh-server python3 diffutils >/dev/null
elif command -v zypper >/dev/null 2>&1; then
    zypper -q -n install iproute2 procps kmod findutils util-linux sudo openssh python3 diffutils gawk >/dev/null
elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm --needed iproute2 procps-ng kmod sudo openssh python diffutils >/dev/null
fi
# sshd -t needs host keys and its privilege-separation directory
command -v ssh-keygen >/dev/null 2>&1 && ssh-keygen -A >/dev/null 2>&1 || true
mkdir -p /run/sshd
exec bash /src/tests/checks.sh
