#!/usr/bin/env bash
# Pay-per-GB v2 (lane L9) — the nftables side of the per-GB shields against a
# REAL kernel (Linux, root, nft): run it inside a throwaway network namespace
# so the host's ruleset is never touched:
#   sudo unshare -n bash scripts/test_pergb_nft_shield.sh
# (CI: .github/workflows/pergb-linux.yml). Elsewhere it prints SKIP.
#   1. accounting.js ensurePergbBlockInfra(): option B swaps the plain
#      `tcp dport @pergb_blocked drop` for `ip daddr <primary IPv4> tcp dport
#      @pergb_blocked drop` in ONE nft -f (the kernel accepts the script, the
#      chain then holds exactly that rule), option A / no per-GB swaps it back,
#      duplicates collapse, a repeated call changes nothing;
#   2. what the scoped rule does: a blocked port is dropped on the primary
#      IPv4 and served on the per-GB IPv4 (the same port number);
#   3. netrun-harden.sh agent-firewall: the guard text loads (`nft -c`), and
#      the add + delete + define idiom replaces an existing table atomically.
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd -P)"
AGENT="$ROOT_DIR/node_runtime/node_agent"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
fail() { echo "FAIL: $1"; exit 1; }
ok() { PASS=$((PASS + 1)); echo "ok: $1"; }

if [ "$(uname -s)" != Linux ] || [ "$(id -u)" != 0 ] || ! command -v nft >/dev/null 2>&1 || ! command -v node >/dev/null 2>&1; then
  echo "SKIP: needs Linux, root, nft and node (run: sudo unshare -n bash $0)"
  exit 0
fi
# Refuse to run in the host's namespace: this test flushes the ruleset.
if [ "${NETRUN_TEST_ALLOW_HOST_NS:-0}" != 1 ] && [ "$(readlink /proc/self/ns/net)" = "$(readlink /proc/1/ns/net 2>/dev/null)" ]; then
  echo "SKIP: not inside a private network namespace (sudo unshare -n bash $0)"
  exit 0
fi

PRIMARY=10.77.0.1
PERGB=10.77.0.2
ip link set lo up
ip link add d0 type dummy 2>/dev/null || true
ip link set d0 up
ip addr add "$PRIMARY/24" dev d0 2>/dev/null || true
ip addr add "$PERGB/24" dev d0 2>/dev/null || true
nft flush ruleset

export NODE_AGENT_PROXY_ROOT="$TMP/proxyserver" NETRUN_PRIMARY_IPV4="$PRIMARY" NETRUN_PERGB_ENABLE_FILE="$TMP/enable.json"
mkdir -p "$NODE_AGENT_PROXY_ROOT/3proxy"

ensure() { # (re)load accounting.js in a fresh process and ensure the infra
  node -e '
    const a = require(process.argv[1] + "/accounting.js");
    a.ensurePergbBlockInfra().then(() => process.exit(0), (e) => { console.error(e); process.exit(1); });' "$AGENT" >/dev/null 2>"$TMP/ensure.err" \
    || fail "ensurePergbBlockInfra: $(cat "$TMP/ensure.err")"
}
rules() { nft list chain inet proxy_accounting input | grep '@pergb_blocked' | sed 's/^[[:space:]]*//'; }

# ── 1. the drop rule's two forms ──────────────────────────────────
ensure
[ "$(rules)" = "tcp dport @pergb_blocked drop" ] || fail "no per-GB: $(rules)"
printf '{"base":10000,"count":1000,"egressIpv4":"%s"}' "$PERGB" > "$NETRUN_PERGB_ENABLE_FILE"
ensure
[ "$(rules)" = "ip daddr $PRIMARY tcp dport @pergb_blocked drop" ] || fail "option B: $(rules)"
ensure
[ "$(rules | wc -l | tr -d ' ')" = 1 ] || fail "option B, again: $(rules)"
printf '{"base":31000,"count":1000,"egressIpv4":null}' > "$NETRUN_PERGB_ENABLE_FILE"
ensure
[ "$(rules)" = "tcp dport @pergb_blocked drop" ] || fail "option A: $(rules)"
nft insert rule inet proxy_accounting input tcp dport @pergb_blocked drop
[ "$(rules | wc -l | tr -d ' ')" = 2 ] || fail "duplicate not set up"
printf '{"base":10000,"count":1000,"egressIpv4":"%s"}' "$PERGB" > "$NETRUN_PERGB_ENABLE_FILE"
ensure
[ "$(rules)" = "ip daddr $PRIMARY tcp dport @pergb_blocked drop" ] || fail "duplicates collapsed into the scoped rule: $(rules)"
ok "drop rule: plain without per-GB / option A, \`ip daddr $PRIMARY …\` with option B; swapped by the kernel in one nft -f; duplicates collapse; idempotent"

# ── 2. what the scoped rule does ──────────────────────────────────
python3 -c '
import socket, sys, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 10005)); s.listen(16)
open(sys.argv[1], "w").write("up")
deadline = time.time() + 30
s.settimeout(1)
while time.time() < deadline:
    try:
        c, _ = s.accept(); c.sendall(b"hi"); c.close()
    except socket.timeout:
        pass' "$TMP/listener.up" &
LPID=$!
for _ in $(seq 1 50); do [ -s "$TMP/listener.up" ] && break; sleep 0.1; done
connects() { python3 -c '
import socket, sys
try:
    socket.create_connection((sys.argv[1], 10005), timeout=1.5).recv(2)
    print("open")
except Exception:
    print("dropped")' "$1"; }
[ "$(connects "$PRIMARY")" = open ] && [ "$(connects "$PERGB")" = open ] || fail "the listener is not reachable before any block"
nft add element inet proxy_accounting pergb_blocked '{ 10005 }'
[ "$(connects "$PRIMARY")" = dropped ] || fail "option B: a blocked per-piece port still answers on the primary IPv4"
[ "$(connects "$PERGB")" = open ] || fail "option B: the per-GB IPv4 is hit by a per-piece block"
printf '{"base":31000,"count":1000,"egressIpv4":null}' > "$NETRUN_PERGB_ENABLE_FILE"
ensure
[ "$(connects "$PERGB")" = dropped ] || fail "the plain rule must drop on every address"
kill "$LPID" 2>/dev/null; wait "$LPID" 2>/dev/null
ok "scoped rule: a blocked port is dropped on the primary IPv4 and served on the per-GB IPv4"

# ── 3. netrun-harden.sh agent-firewall: the guard text loads, atomically replaced ──
H="$ROOT_DIR/scripts/netrun-harden.sh"
bash "$H" agent-firewall 192.0.2.10 --dry-run > "$TMP/guard.nft" || fail "dry-run"
nft -c -f "$TMP/guard.nft" || fail "nft -c rejects the guard: $(cat "$TMP/guard.nft")"
nft -f "$TMP/guard.nft" || fail "first load (no table yet)"
bash "$H" agent-firewall 192.0.2.11 --dry-run | nft -f - || fail "replacing an existing table"
t="$(nft list table inet netrun_agent_guard)"
grep -q 'tcp dport { 8085, 8086 } ip saddr 192.0.2.11 accept' <<< "$t" && grep -q 'tcp dport { 8085, 8086 } drop' <<< "$t" \
  && ! grep -q '192.0.2.10' <<< "$t" || fail "guard table: $t"
[ "$(nft list tables | grep -c netrun_agent_guard)" = 1 ] || fail "two guard tables"
ok "agent guard: 8085 + 8086 from the orchestrator only; the text loads and replaces an older table in one transaction"

nft flush ruleset
echo "test_pergb_nft_shield.sh — all $PASS checks passed"
