#!/usr/bin/env bash
# Audit S-U2 — node registration only over HTTPS:
#   * quick-install.sh refuses an http:// --orch-url (it sends the admin
#     orchestrator key and the node's agent key); --allow-insecure-http opts in
#     and then gets past that check;
#   * the usage text shows an https:// example;
#   * the legacy cloud-init.sh / cloud-init.yaml (unconditional plain-HTTP
#     register) are gone — the orchestrator renders the only user_data.
# Run as a non-root user (the script's own root check is the next line after the
# https guard and stops it before it installs anything):
#   bash scripts/test_quick_install_https.sh
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd -P)"
QI="$ROOT_DIR/scripts/quick-install.sh"
fail() { echo "FAIL: $1"; exit 1; }
ok() { echo "ok: $1"; }

bash -n "$QI" || fail "bash -n quick-install.sh"
if [ "$(id -u)" -eq 0 ]; then
  echo "SKIP: running as root would let quick-install continue past the guards (run as a normal user)"; exit 0
fi

ARGS=(--orch-api-key k --node-name n --geo DE)
out="$(bash "$QI" --orch-url http://x:8090 "${ARGS[@]}" 2>&1)"; rc=$?
[ "$rc" -eq 1 ] && echo "$out" | grep -q 'orch-url must be https://' || fail "http:// --orch-url not refused (rc=$rc): $out"
echo "$out" | grep -q 'must run as root' && fail "the https guard must come before the root check"
ok "http:// --orch-url refused"

out="$(bash "$QI" --orch-url ftp://x "${ARGS[@]}" 2>&1)"; rc=$?
[ "$rc" -eq 1 ] && echo "$out" | grep -q 'orch-url must be https://' || fail "a non-http(s) scheme must be refused: $out"
out="$(bash "$QI" --orch-url x:8090 "${ARGS[@]}" 2>&1)"; rc=$?
[ "$rc" -eq 1 ] && echo "$out" | grep -q 'orch-url must be https://' || fail "a schemeless URL must be refused: $out"
ok "ftp:// and schemeless URLs refused"

out="$(bash "$QI" --orch-url http://x:8090 --allow-insecure-http "${ARGS[@]}" 2>&1)"; rc=$?
[ "$rc" -eq 1 ] && echo "$out" | grep -q 'must run as root' && ! echo "$out" | grep -q 'orch-url must be https://' \
  || fail "--allow-insecure-http must get past the https check and stop at the root check (rc=$rc): $out"
ok "--allow-insecure-http gets past the https guard"

out="$(bash "$QI" --orch-url https://orch.example.com "${ARGS[@]}" 2>&1)"; rc=$?
echo "$out" | grep -q 'must run as root' && ! echo "$out" | grep -q 'orch-url must be https://' || fail "https:// must pass the guard: $out"
ok "https:// --orch-url passes the guard"

help="$(bash "$QI" --help 2>&1)"
echo "$help" | grep -q -- '--orch-url https://' || fail "usage example is not https://"
echo "$help" | grep -q 'http://51.38' && fail "usage still shows the old http:// example"
echo "$help" | grep -q -- '--allow-insecure-http' || fail "usage does not document --allow-insecure-http"
ok "usage shows an https:// example and --allow-insecure-http"

[ ! -e "$ROOT_DIR/deploy/node/cloud-init.sh" ] || fail "deploy/node/cloud-init.sh (plain-HTTP register) still exists"
[ ! -e "$ROOT_DIR/deploy/node/cloud-init.yaml" ] || fail "deploy/node/cloud-init.yaml still exists"
ok "legacy plain-HTTP cloud-init files are gone"

grep -q 'ORCHESTRATOR_REGISTER_URL' "$ROOT_DIR/docs/cloud_init_provisioning.md" || fail "docs must name ORCHESTRATOR_REGISTER_URL"
grep -qE 'https://netrun.world/node-register' "$ROOT_DIR/docs/cloud_init_provisioning.md" || fail "docs must name the https register URL"
ok "docs name the https-only register path"
echo "test_quick_install_https.sh — all checks passed"
