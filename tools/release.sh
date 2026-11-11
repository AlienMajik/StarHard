#!/usr/bin/env bash
# tools/release.sh — build dist/ for a release: the scripts, SHA256SUMS, and a detached signature.
#
# Signing uses whichever of these is set up (both if both are):
#   minisign:  MINISIGN_KEY=/path/to/minisign.key tools/release.sh      -> SHA256SUMS.minisig
#   GnuPG:     GPG_KEY=<key id or e-mail> tools/release.sh              -> SHA256SUMS.asc
# Publish the matching PUBLIC key in the README once; users verify every later download against it.
# Without a key the checksums are still written, and the script says the release is unsigned.
set -euo pipefail
cd "$(dirname "$0")/.."
tools/embed.sh --check
ver="$(sed -n 's/^VERSION="\(.*\)"/\1/p' StarHard.sh)"
[[ -n "$ver" ]] || { echo "release: could not read VERSION from StarHard.sh" >&2; exit 1; }
grep -q "^\*\*Current version: $ver\*\*" README.md || { echo "release: README.md does not say 'Current version: $ver'" >&2; exit 1; }
rm -rf dist && mkdir dist
cp StarHard.sh starhard-scan starhard-status starhard-notify README.md dist/
( cd dist && sha256sum StarHard.sh starhard-scan starhard-status starhard-notify README.md > SHA256SUMS )
signed=0
if [[ -n "${MINISIGN_KEY:-}" ]]; then
    minisign -S -s "$MINISIGN_KEY" -m dist/SHA256SUMS -t "StarHard $ver"
    signed=1
fi
if [[ -n "${GPG_KEY:-}" ]]; then
    gpg --batch --yes --local-user "$GPG_KEY" --armor --detach-sign --output dist/SHA256SUMS.asc dist/SHA256SUMS
    signed=1
fi
echo "release: StarHard $ver -> dist/"
ls -1 dist | sed 's/^/    /'
[[ $signed -eq 1 ]] || echo "release: UNSIGNED — set MINISIGN_KEY or GPG_KEY to sign SHA256SUMS"
