#!/usr/bin/env bash
# tools/embed.sh [--check]
# StarHard.sh is self-contained: it carries starhard-scan, starhard-status and starhard-notify
# inside here-documents. The standalone files in the repository root are the source; this script
# copies them into StarHard.sh.   --check: change nothing, exit 1 if StarHard.sh is out of date (CI).
set -euo pipefail
cd "$(dirname "$0")/.."
check=0; [[ "${1:-}" == "--check" ]] && check=1
tmp="$(mktemp)"; trap 'rm -f "$tmp" "$tmp.new"' EXIT
cp StarHard.sh "$tmp"
for name in starhard-scan starhard-status starhard-notify; do
    tag="__$(printf '%s' "$name" | tr 'a-z-' 'A-Z_')__"
    [[ "$(grep -c "<<'$tag'\$" "$tmp")" == "1" ]] || { echo "embed: expected exactly one <<'$tag' marker in StarHard.sh" >&2; exit 1; }
    if grep -qx "$tag" "$name"; then echo "embed: $name contains the delimiter line $tag" >&2; exit 1; fi
    bash -n "$name"
    awk -v tag="$tag" -v src="$name" '
        skip && $0 == tag { skip = 0; print; next }
        skip { next }
        { print }
        $0 ~ ("<<\047" tag "\047$") { while ((getline line < src) > 0) print line; close(src); skip = 1 }
    ' "$tmp" > "$tmp.new"
    mv "$tmp.new" "$tmp"
done
bash -n "$tmp"
if cmp -s "$tmp" StarHard.sh; then
    echo "embed: StarHard.sh is up to date"
elif [[ $check -eq 1 ]]; then
    echo "embed: StarHard.sh does not match the standalone helpers — run tools/embed.sh" >&2
    exit 1
else
    cat "$tmp" > StarHard.sh
    echo "embed: StarHard.sh updated"
fi
