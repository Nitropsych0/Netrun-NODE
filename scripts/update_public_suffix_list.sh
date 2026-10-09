#!/usr/bin/env bash
# NETRUN per-GB, amendment A12 — refresh the vendored Public Suffix List
# (node_runtime/radius/public_suffix_list.dat) that the agent's smart-rotation
# site keys (node_agent/pergb_psl.js) and RADIUS use. Run it on a workstation,
# review the diff, commit; the nodes get it with the next deploy (never
# fetched at run time on a node).
#
#   bash scripts/update_public_suffix_list.sh            # download + check + replace
#   bash scripts/update_public_suffix_list.sh --check    # only check the vendored file
#
# The list is MPL-2.0 (https://publicsuffix.org/list/); the PSL asks to be
# fetched from publicsuffix.org only.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
DST="$REPO/node_runtime/radius/public_suffix_list.dat"
URL="${PSL_URL:-https://publicsuffix.org/list/public_suffix_list.dat}"

check() {
  local f="$1" rules
  grep -q '===BEGIN ICANN DOMAINS===' "$f" || { echo "no ICANN section in $f" >&2; return 1; }
  grep -q '===BEGIN PRIVATE DOMAINS===' "$f" || { echo "no PRIVATE section in $f" >&2; return 1; }
  rules="$(grep -cv '^\s*\(//.*\)\?$' "$f")"
  [ "$rules" -ge 5000 ] || { echo "only $rules rules in $f" >&2; return 1; }
  # the shared site-key vectors must still hold
  (cd "$REPO" && NETRUN_PSL_FILE="$f" node -e '
    const p = require("./node_runtime/node_agent/pergb_psl.js");
    const v = require("./node_runtime/radius/tests/psl_vectors.json");
    const data = p.loadDefault(process.env.NETRUN_PSL_FILE);
    const bad = v.vectors.filter((x) => p.siteKey(x.host, x.dst, data) !== x.site);
    if (bad.length) { console.error("site-key vectors changed:", JSON.stringify(bad)); process.exit(1); }
  ') || return 1
  echo "ok: $rules rules, vectors hold ($f)"
}

if [ "${1:-}" = "--check" ]; then
  check "$DST"
  exit
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
curl -fsSL --max-time 60 -o "$tmp" "$URL"
check "$tmp"
if cmp -s "$tmp" "$DST"; then
  echo "unchanged"
else
  install -m 0644 "$tmp" "$DST"
  echo "updated $DST — review the diff and commit"
fi
