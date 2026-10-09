#!/usr/bin/env bash
# netrun-harden.sh, audit 2026-10-08 subcommands: perms (customer credential
# files root-only), ssh (keys only, never without a root key, sshd -t),
# dns-egress (unbound recursion from the node's own last /64 of the routed
# prefix, IPv4 unchanged, verified with a lookup, put back on failure),
# agent-firewall persisting through netrun-nft-persist and covering the
# pay-per-GB TLS port 8086 (one atomic nft -f; --dry-run; re-apply with the
# live table's IP; `secure` adds 8086 to an older guard). ip / nft / systemctl /
# unbound-checkconf / dig / sshd are stubs on PATH; python3 is real. No root.
#   bash scripts/test_netrun_harden_security.sh
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd -P)"
H="$ROOT_DIR/scripts/netrun-harden.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
fail() { echo "FAIL: $1"; exit 1; }
ok() { PASS=$((PASS + 1)); echo "ok: $1"; }
mode_of() { stat -f %Lp "$1" 2>/dev/null || stat -c %a "$1"; }

command -v python3 >/dev/null 2>&1 || { echo "SKIP: no python3"; exit 0; }
bash -n "$H" || fail "bash -n netrun-harden.sh"

STUB="$TMP/bin"; mkdir -p "$STUB"
export STUB_LOG="$TMP/calls.log" ROUTES_FILE="$TMP/routes"
: > "$STUB_LOG"; : > "$ROUTES_FILE"
cat > "$STUB/ip" <<'EOF'
#!/usr/bin/env bash
echo "ip $*" >> "$STUB_LOG"
case "$*" in
  "-6 route show table local dev lo") echo "local ::1 proto kernel metric 0 pref medium"; cat "$ROUTES_FILE" ;;
  *) exit 1 ;;
esac
EOF
for c in systemctl unbound-control; do
  printf '#!/usr/bin/env bash\necho "%s $*" >> "$STUB_LOG"\n' "$c" > "$STUB/$c"
done
cat > "$STUB/unbound-checkconf" <<'EOF'
#!/usr/bin/env bash
echo "unbound-checkconf $*" >> "$STUB_LOG"
[ ! -f "$TMP_FLAGS/checkconf_fail" ]
EOF
cat > "$STUB/dig" <<'EOF'
#!/usr/bin/env bash
echo "dig $*" >> "$STUB_LOG"
if [ -f "$TMP_FLAGS/dig_fail" ]; then echo ";; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1"; echo ";; flags: qr rd ra; QUERY: 1, ANSWER: 0"; exit 0; fi
echo ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1"; echo ";; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0"
EOF
cat > "$STUB/sshd" <<'EOF'
#!/usr/bin/env bash
echo "sshd $*" >> "$STUB_LOG"
[ ! -f "$TMP_FLAGS/sshd_fail" ]
EOF
cat > "$STUB/nft-persist" <<'EOF'
#!/usr/bin/env bash
echo "nft-persist $*" >> "$STUB_LOG"
EOF
cat > "$STUB/nft" <<'EOF'
#!/usr/bin/env bash
echo "nft $*" >> "$STUB_LOG"
case "$*" in
  "-f -") cat > "$TMP_FLAGS/nft_stdin" ;;
  "list table inet netrun_agent_guard") [ -f "$TMP_FLAGS/guard_table" ] && cat "$TMP_FLAGS/guard_table" || exit 1 ;;
esac
exit 0
EOF
chmod +x "$STUB"/*
export TMP_FLAGS="$TMP/flags"; mkdir -p "$TMP_FLAGS"
export PATH="$STUB:$PATH"
export NODE_AGENT_PROXY_ROOT="$TMP/proxyserver" NODE_AGENT_JOBS_ROOT="$TMP/jobs" NETRUN_ENV_FILE="$TMP/netrun.env" \
       NETRUN_NFT_CONF="$TMP/etc/nftables.conf" NETRUN_SSHD_HARDENING="$TMP/ssh/sshd_config.d/00-netrun-hardening.conf" \
       NETRUN_ROOT_AUTH_KEYS="$TMP/authorized_keys" NETRUN_UNBOUND_EGRESS_CONF="$TMP/unbound/netrun-egress.conf" \
       NETRUN_NFT_PERSIST_BIN="$STUB/nft-persist"
run() { bash "$H" "$@"; }

# ── 1. perms ──────────────────────────────────────────────────────
P="$NODE_AGENT_PROXY_ROOT"; mkdir -p "$P/3proxy/bin" "$NODE_AGENT_JOBS_ROOT/job-1" "$TMP/etc" "$TMP/other"
for f in "$P/3proxy/3proxy_18100.cfg" "$P/3proxy/3proxy_19600.cfg.disabled" "$P/ipv6_18100.list" "$P/random_users_18100.list" \
         "$P/backconnect_proxies_18100.list" "$P/port_ipv6_map_18100.csv" "$P/egress_state.json" \
         "$NODE_AGENT_JOBS_ROOT/job-1/proxies.txt" "$NODE_AGENT_JOBS_ROOT/job-1/result.json" "$NETRUN_NFT_CONF" "$NETRUN_ENV_FILE" "$TMP/other/keep.txt"; do
  echo x > "$f"; chmod 0644 "$f"
done
printf '#!/bin/bash\n' > "$P/proxy-startup_18100.sh"; chmod 0755 "$P/proxy-startup_18100.sh"
chmod 0755 "$P" "$P/3proxy" "$NODE_AGENT_JOBS_ROOT" "$NODE_AGENT_JOBS_ROOT/job-1"
out="$(run perms)" || fail "perms: $out"
for f in "$P/3proxy/3proxy_18100.cfg" "$P/3proxy/3proxy_19600.cfg.disabled" "$P/ipv6_18100.list" "$P/random_users_18100.list" \
         "$P/backconnect_proxies_18100.list" "$P/port_ipv6_map_18100.csv" "$P/egress_state.json" \
         "$NODE_AGENT_JOBS_ROOT/job-1/proxies.txt" "$NODE_AGENT_JOBS_ROOT/job-1/result.json" "$NETRUN_NFT_CONF" "$NETRUN_ENV_FILE"; do
  [ "$(mode_of "$f")" = 600 ] || fail "perms: $f is $(mode_of "$f")"
done
[ "$(mode_of "$P/proxy-startup_18100.sh")" = 700 ] || fail "start-up script keeps u+x: $(mode_of "$P/proxy-startup_18100.sh")"
for d in "$P" "$P/3proxy" "$NODE_AGENT_JOBS_ROOT" "$NODE_AGENT_JOBS_ROOT/job-1"; do [ "$(mode_of "$d")" = 700 ] || fail "dir $d $(mode_of "$d")"; done
[ "$(mode_of "$TMP/other/keep.txt")" = 644 ] || fail "perms touched a file elsewhere"
echo "$out" | grep -q "now root-only (0 left)" || fail "perms report: $out"
out="$(run perms)"; echo "$out" | grep -q "perms: 0 path(s)" || fail "perms is idempotent: $out"
ok "perms: cfgs, lists, maps, state, start-up scripts (u+x kept), job files, nftables.conf, netrun.env root-only; idempotent"

# ── 2. ssh keys only ──────────────────────────────────────────────
: > "$STUB_LOG"
out="$(run ssh)" || fail "ssh without a key: $out"
echo "$out" | grep -q "NOT applied" && [ ! -e "$NETRUN_SSHD_HARDENING" ] || fail "keys-only applied without a root key"
echo "ssh-ed25519 AAAAC3Nz test@laptop" > "$NETRUN_ROOT_AUTH_KEYS"
out="$(run ssh)" || fail "ssh: $out"
grep -qx 'PasswordAuthentication no' "$NETRUN_SSHD_HARDENING" && grep -qx 'PermitRootLogin prohibit-password' "$NETRUN_SSHD_HARDENING" \
  && grep -qx 'KbdInteractiveAuthentication no' "$NETRUN_SSHD_HARDENING" || fail "hardening file: $(cat "$NETRUN_SSHD_HARDENING")"
grep -q '^sshd -t' "$STUB_LOG" && grep -q '^systemctl reload ssh' "$STUB_LOG" || fail "sshd -t + reload"
: > "$STUB_LOG"; out="$(run ssh)"
echo "$out" | grep -q "already keys-only" && ! grep -q reload "$STUB_LOG" || fail "ssh rerun reloaded"
rm -f "$NETRUN_SSHD_HARDENING"; touch "$TMP_FLAGS/sshd_fail"
run ssh >/dev/null 2>&1 && fail "ssh passed with sshd -t failing"
[ ! -e "$NETRUN_SSHD_HARDENING" ] || fail "a config sshd -t rejects was left"
rm -f "$TMP_FLAGS/sshd_fail"
ok "ssh: keys-only file (as on the live nodes), sshd -t + reload; skipped without a root key; rejected -> put back"

# ── 3. dns-egress ─────────────────────────────────────────────────
: > "$NETRUN_ENV_FILE"; : > "$STUB_LOG"
out="$(run dns-egress)" || fail "dns-egress without a prefix: $out"
echo "$out" | grep -q "nothing to do" && [ ! -e "$NETRUN_UNBOUND_EGRESS_CONF" ] || fail "no prefix: $out"
echo 'NETRUN_IPV6_ROUTED_PREFIX=2602:f2dc:a9::/48' > "$NETRUN_ENV_FILE"
out="$(run dns-egress)" || fail "dns-egress not routed: $out"
echo "$out" | grep -q "not routed to this host" && [ ! -e "$NETRUN_UNBOUND_EGRESS_CONF" ] || fail "an unrouted prefix must not be used: $out"
echo "local 2602:f2dc:a9::/48 metric 1024 pref medium" > "$ROUTES_FILE"
: > "$STUB_LOG"
out="$(run dns-egress)" || fail "dns-egress: $out"
grep -qx '    outgoing-interface: 2602:f2dc:a9:ffff::53' "$NETRUN_UNBOUND_EGRESS_CONF" || fail "outgoing-interface: $(cat "$NETRUN_UNBOUND_EGRESS_CONF")"
grep -qx '    outgoing-interface: 0.0.0.0' "$NETRUN_UNBOUND_EGRESS_CONF" || fail "IPv4 recursion must stay (0.0.0.0)"
grep -qx '    prefer-ip6: yes' "$NETRUN_UNBOUND_EGRESS_CONF" || fail "prefer-ip6"
grep -q 'do-ip4' "$NETRUN_UNBOUND_EGRESS_CONF" && fail "do-ip4 must not be touched"
[ "$(grep -c 'outgoing-interface' "$NETRUN_UNBOUND_EGRESS_CONF")" = 2 ] || fail "two outgoing interfaces"
grep -q '^unbound-checkconf' "$STUB_LOG" && grep -q '^systemctl reload unbound' "$STUB_LOG" && grep -q '^dig .*@127.0.0.1' "$STUB_LOG" \
  || fail "checkconf + reload + lookup: $(cat "$STUB_LOG")"
grep -q 'restart' "$STUB_LOG" && fail "unbound restarted instead of reloaded"
: > "$STUB_LOG"; out="$(run dns-egress)"
echo "$out" | grep -q "already recurses from 2602:f2dc:a9:ffff::53" && ! grep -q reload "$STUB_LOG" || fail "rerun reloaded: $out"
good="$(cat "$NETRUN_UNBOUND_EGRESS_CONF")"
# a new prefix whose lookups fail: the old config comes back
echo 'NETRUN_IPV6_ROUTED_PREFIX=2602:f2dc:b0::/48' > "$NETRUN_ENV_FILE"
echo "local 2602:f2dc:b0::/48 metric 1024 pref medium" >> "$ROUTES_FILE"
touch "$TMP_FLAGS/dig_fail"
out="$(run dns-egress 2>&1)" && fail "dns-egress passed with failing lookups"
echo "$out" | grep -q "put back" && [ "$(cat "$NETRUN_UNBOUND_EGRESS_CONF")" = "$good" ] || fail "failed lookup: old config not put back: $out"
rm -f "$TMP_FLAGS/dig_fail"; touch "$TMP_FLAGS/checkconf_fail"
run dns-egress >/dev/null 2>&1 && fail "dns-egress passed with unbound-checkconf failing"
[ "$(cat "$NETRUN_UNBOUND_EGRESS_CONF")" = "$good" ] || fail "checkconf failure: old config not put back"
rm -f "$TMP_FLAGS/checkconf_fail"
echo 'NETRUN_IPV6_ROUTED_PREFIX=2602:f2dc:a9:5::/64' > "$NETRUN_ENV_FILE"
run dns-egress >/dev/null 2>&1 && fail "a /64 prefix has no /64 to reserve"
: > "$NETRUN_ENV_FILE"; : > "$STUB_LOG"
out="$(run dns-egress)" || fail "prefix gone: $out"
[ ! -e "$NETRUN_UNBOUND_EGRESS_CONF" ] && grep -q '^systemctl reload unbound' "$STUB_LOG" || fail "prefix gone: drop-in removed + reload"
ok "dns-egress: <last /64>::53 + prefer-ip6, IPv4 kept; only when routed here; verified lookup; failures put the old config back; /64 refused; prefix gone -> removed"

# reserved_net is the same rule as the generator and egress.js
rn="$(NETRUN_HARDEN_SOURCED=1 bash -c 'source <(sed "/^case \"\${1:-}\" in/,\$d" "$1"); reserved_net 2602:f2dc:a0::/44' _ "$H")"
[ "$rn" = "2602:f2dc:af:ffff::/64 2602:f2dc:af:ffff::53 2602:f2dc:af:ffff::1" ] || fail "reserved_net /44: $rn"
ok "reserved_net: the last /64 of the prefix (+ ::53 unbound, ::1 self-check)"

# ── 4. agent-firewall persists through netrun-nft-persist ─────────
: > "$STUB_LOG"
out="$(run agent-firewall 95.217.98.125)" || fail "agent-firewall: $out"
grep -qx 'nft-persist save' "$STUB_LOG" || fail "agent-firewall did not persist through netrun-nft-persist: $(cat "$STUB_LOG")"
grep -q 'list ruleset' "$STUB_LOG" && fail "agent-firewall dumped the ruleset itself"
ok "agent-firewall: persisted through netrun-nft-persist"

# ── 5. pay-per-GB: the agent guard covers 8086 (plan D16) ─────────
grep -q 'tcp dport { 8085, 8086 } ip saddr 95.217.98.125 accept' "$TMP_FLAGS/nft_stdin" \
  && grep -q 'tcp dport { 8085, 8086 } drop' "$TMP_FLAGS/nft_stdin" || fail "applied guard: $(cat "$TMP_FLAGS/nft_stdin")"
grep -qx 'table inet netrun_agent_guard|delete table inet netrun_agent_guard|' <<< "$(head -n2 "$TMP_FLAGS/nft_stdin" | tr '\n' '|')" \
  || fail "the guard is not replaced in one transaction: $(head -n3 "$TMP_FLAGS/nft_stdin")"
grep -q '^nft delete table' "$STUB_LOG" && fail "a separate delete leaves the agent open between two nft calls"
: > "$STUB_LOG"; rm -f "$TMP_FLAGS/nft_stdin"
out="$(run agent-firewall 95.217.98.125 --dry-run)" || fail "dry-run: $out"
echo "$out" | grep -q 'tcp dport { 8085, 8086 } ip saddr 95.217.98.125 accept' && echo "$out" | grep -q 'tcp dport { 8085, 8086 } drop' \
  || fail "dry-run text: $out"
echo "$out" | grep -q 'iifname "lo" accept' || fail "dry-run: localhost (the generator's reserve_nets call) must stay open"
[ ! -s "$STUB_LOG" ] && [ ! -e "$TMP_FLAGS/nft_stdin" ] || fail "dry-run changed something: $(cat "$STUB_LOG")"
run agent-firewall 999.1.2.3 >/dev/null 2>&1 && fail "a bad IPv4 accepted"
run agent-firewall >/dev/null 2>&1 && fail "no IP and no live table: must refuse"
# an older guard (8085 only): `agent-firewall` without an IP re-applies with its IP; `status` and `secure` notice
printf 'table inet netrun_agent_guard {\n\tchain input {\n\t\ttcp dport 8085 ip saddr 95.217.98.125 accept\n\t\ttcp dport 8085 drop\n\t}\n}\n' > "$TMP_FLAGS/guard_table"
out="$(run status 2>&1)"; echo "$out" | grep -q 'not for every agent port' || fail "status on an 8085-only guard: $out"
: > "$STUB_LOG"
out="$(run agent-firewall)" || fail "refresh: $out"
grep -q 'ip saddr 95.217.98.125 accept' "$TMP_FLAGS/nft_stdin" && grep -q '8086' "$TMP_FLAGS/nft_stdin" || fail "refresh: $(cat "$TMP_FLAGS/nft_stdin")"
rm -f "$TMP_FLAGS/nft_stdin"
grep -qx REFRESH <<< "$(NETRUN_HARDEN_SOURCED=1 bash -c 'source <(sed "/^case \"\${1:-}\" in/,\$d" "$1"); if [ -n "$(agent_guard_ip)" ] && ! agent_guard_covers_all; then echo REFRESH; fi' _ "$H")" \
  || fail "secure's check: an 8085-only guard must be refreshed"
printf 'table inet netrun_agent_guard {\n\tchain input {\n\t\ttcp dport { 8085, 8086 } ip saddr 95.217.98.125 accept\n\t\ttcp dport { 8085, 8086 } drop\n\t}\n}\n' > "$TMP_FLAGS/guard_table"
grep -qx COVERED <<< "$(NETRUN_HARDEN_SOURCED=1 bash -c 'source <(sed "/^case \"\${1:-}\" in/,\$d" "$1"); agent_guard_covers_all && echo COVERED' _ "$H")" \
  || fail "a guard with 8086 counts as covered"
rm -f "$TMP_FLAGS/guard_table"
ok "agent-firewall: 8085 + 8086 only from the orchestrator (one transaction, --dry-run, refresh from the live table, secure upgrades an 8085-only guard)"

echo "PASS ($PASS)"
