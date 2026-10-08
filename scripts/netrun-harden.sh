#!/usr/bin/env bash
# netrun-harden.sh — security fixes for a live NETRUN node (2026-10-02 and
# 2026-10-08 audits).
#
#   status                 show what is still open (read-only)
#   auth-fix               A1+A2: each proxy port admits ONLY its own login and
#                          no empty login. Rewrites every 3proxy_*.cfg (backup
#                          first), restarts each 3proxy (~2 s per batch file),
#                          then probes a port: empty/foreign login must fail.
#   agent-key <hex>        A3: require X-API-KEY on the node-agent (8085).
#                          Without it only GET /health answers, as a liveness
#                          {ok:true} (the agent fails closed since 2026-10-08;
#                          install_node_v2.sh generates a key). 3proxy is NOT
#                          restarted (KillMode=process).
#   agent-firewall <ip>    A3: 8085 reachable only from the orchestrator <ip>
#                          and localhost. Persisted to /etc/nftables.conf.
#   drop-ssh-key <comment> A6: remove authorized_keys lines ending in <comment>.
#
#   Audit 2026-10-08 (all idempotent; nothing restarts 3proxy):
#   perms                  customer credentials root-only: 3proxy cfgs, start-up
#                          scripts, ipv6 / users / backconnect lists, port maps,
#                          egress state (0600 files, 0700 dirs under
#                          $PROXY_ROOT), every job directory under $JOBS_ROOT,
#                          /etc/nftables.conf*, /etc/netrun/netrun.env. Nothing
#                          non-root reads them: 3proxy parses its cfg as root
#                          before `setuid 65535` (and never re-reads it), haproxy
#                          reads /etc/haproxy + /etc/netrun/tls only, netrun-https
#                          / the agent / the boot scripts run as root. New files
#                          are 0600 already (umask 077 in the generator, the
#                          batch start-up scripts and the agent).
#   ssh                    $SSHD_HARDENING: keys only, root by key (skipped when
#                          root has no authorized key); `sshd -t`, then
#                          `systemctl reload ssh` (sessions stay).
#   dns-egress             unbound recurses from the node's own /64 of the
#                          routed prefix (NETRUN_IPV6_ROUTED_PREFIX, the last /64
#                          of it — <prefix>:ffff::/64 of a /48 — which the
#                          generator and the agent never give a proxy), address
#                          <that /64>::53, prefer-ip6; IPv4 recursion unchanged
#                          (outgoing-interface 0.0.0.0, do-ip4 untouched). No
#                          routed prefix: the drop-in is removed. Checked with
#                          unbound-checkconf, `systemctl reload unbound`, then a
#                          test lookup; a failed lookup puts the old config back.
#   secure                 all of the above for a node: netrun-nft-persist
#                          install (atomic ruleset saves, boot fallback),
#                          netrun-proxy-guard apply, perms, ssh, dns-egress.
#                          Called by install_node_v2.sh and node_followup_v2.sh.
#
# Why A1/A2: 3proxy's `users` list is GLOBAL — `flush` resets the ACLs, not the
# users — so the old per-proxy `allow * *` let every login of a batch file in
# on every port of it, and the header `users :CL:` declared an EMPTY login.
# The generator (node_runtime/soft/generator/proxyyy_automated.sh) now writes
# `allow <login> *` per port; this rewrites the configs already on the node.
set -euo pipefail

PROXY_ROOT="${NODE_AGENT_PROXY_ROOT:-/opt/netrun/proxyserver}"
CFG_DIR="$PROXY_ROOT/3proxy"
BIN="$CFG_DIR/bin/3proxy"
SPAWN_HELPER="${NETRUN_3PROXY_SPAWN:-$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd -P)/netrun-3proxy-spawn.sh}"
AGENT_UNIT="netrun-node-agent"
AGENT_DROPIN_DIR="/etc/systemd/system/${AGENT_UNIT}.service.d"
AGENT_KEY_FILE="$AGENT_DROPIN_DIR/20-api-key.conf"
NFT_GUARD_TABLE="netrun_agent_guard"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd -P || echo /opt/netrun/scripts)"
JOBS_ROOT="${NODE_AGENT_JOBS_ROOT:-/opt/netrun/jobs}"
NETRUN_ENV="${NETRUN_ENV_FILE:-/etc/netrun/netrun.env}"
NFT_CONF="${NETRUN_NFT_CONF:-/etc/nftables.conf}"
SSHD_HARDENING="${NETRUN_SSHD_HARDENING:-/etc/ssh/sshd_config.d/00-netrun-hardening.conf}"
ROOT_AUTH_KEYS="${NETRUN_ROOT_AUTH_KEYS:-/root/.ssh/authorized_keys}"
UNBOUND_EGRESS_CONF="${NETRUN_UNBOUND_EGRESS_CONF:-/etc/unbound/unbound.conf.d/netrun-egress.conf}"
DNS_TEST_NAME="${NETRUN_DNS_TEST_NAME:-api64.ipify.org}"

log() { printf '[netrun-harden] %s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

cfg_files() { ls "$CFG_DIR"/3proxy_*.cfg "$CFG_DIR"/3proxy_*.cfg.disabled 2>/dev/null || true; }

# A config is open when it still declares the empty login or a per-proxy
# `allow * *` after a `users` line.
cfg_is_open() {
  awk '
    /^[ \t]*users[ \t]+:CL:[ \t]*$/ { open = 1 }
    /^[ \t]*flush[ \t]*$/            { inblock = 1 }
    inblock && /^[ \t]*allow[ \t]+\*([ \t]|$)/ { open = 1 }
    END { exit open ? 0 : 1 }
  ' "$1"
}

# Rewrite one config to stdout: drop the empty login; inside each block replace
# `allow * <rest>` / bare `allow *` with the block's own login.
rewrite_cfg() {
  awk '
    /^[ \t]*users[ \t]+:CL:[ \t]*$/ { next }
    /^[ \t]*flush[ \t]*$/ { inblock = 1; login = ""; print; next }
    inblock && match($0, /^[ \t]*users[ \t]+[^:]+:CL:/) {
      line = $0
      sub(/^[ \t]*users[ \t]+/, "", line)
      login = substr(line, 1, index(line, ":") - 1)
      print; next
    }
    inblock && login != "" && /^[ \t]*allow[ \t]+\*[ \t]+\*/ {
      rest = $0
      sub(/^[ \t]*allow[ \t]+\*[ \t]+\*/, "", rest)
      print "allow " login " *" rest; next
    }
    inblock && login != "" && /^[ \t]*allow[ \t]+\*[ \t]*$/ {
      print "allow " login; next
    }
    { print }
  ' "$1"
}

restart_cfg() {
  local cfg="$1" pids
  # Match the exact running cmdline (3proxy may have been started through the
  # /root/proxyserver symlink): compare by config basename.
  pids="$(pgrep -f "3proxy[^ ]* [^ ]*/$(basename "$cfg")\$" || true)"
  [ -n "$pids" ] && kill $pids 2>/dev/null || true
  sleep 2
  pids="$(pgrep -f "3proxy[^ ]* [^ ]*/$(basename "$cfg")\$" || true)"
  [ -n "$pids" ] && kill -9 $pids 2>/dev/null || true
  case "$cfg" in *.disabled) return 0 ;; esac   # disabled batches stay down
  # Audit RES-11 — the node's one spawn helper: its own systemd scope (run from
  # an SSH session, a plain nohup would leave the batch inside that session's
  # scope), idempotent, never a duplicate.
  if [ -f "$SPAWN_HELPER" ]; then
    NETRUN_3PROXY_BIN="$BIN" bash "$SPAWN_HELPER" "$cfg" >/dev/null 2>&1 \
      || log "WARNING: spawn helper failed for $(basename "$cfg") (the agent's supervisor retries)"
    return 0
  fi
  # No helper on this node: the previous inline start.
  # No fallback after systemd-run: the daemonizing parent's exit code is not a
  # launch failure, and a second spawn would start a duplicate 3proxy.
  if command -v systemd-run >/dev/null 2>&1; then
    systemd-run --scope --quiet --collect \
      --unit "netrun-3proxy-$(basename "$cfg" .cfg | sed 's/^3proxy_//')-h$(date +%s)" \
      "$BIN" "$cfg" </dev/null >/dev/null 2>&1 &
  else
    nohup "$BIN" "$cfg" </dev/null >/dev/null 2>&1 &
  fi
  disown 2>/dev/null || true
}

# SOCKS5 probe from the node itself: prints ALLOWED / acl-denied / auth-rejected.
socks_probe() {
  python3 - "$@" <<'PY'
import socket, struct, sys
host, port, user, pw = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
try:
    s = socket.create_connection((host, port), timeout=5)
    s.sendall(b"\x05\x01\x02")
    if s.recv(2)[1:2] != b"\x02":
        print("no-auth-method"); sys.exit()
    u, p = user.encode(), pw.encode()
    s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
    if s.recv(2)[1:2] != b"\x00":
        print("auth-rejected"); sys.exit()
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) + struct.pack(">H", 8085))
    rep = s.recv(10)
    # Past auth, only reply 2 is an ACL refusal; any other reply (0 = connected,
    # 4/5 = target unreachable over the -6 egress) means the login got through.
    print("acl-denied" if rep[1] == 2 else "ALLOWED(reply %d)" % rep[1])
except Exception as exc:  # noqa
    print("error:", exc)
PY
}

# First (port, login, password, listen-ip) of a config, for the probes.
first_proxy() {
  awk '
    /^[ \t]*flush/ { inblock = 1 }
    inblock && /^[ \t]*users[ \t]+[^:]+:CL:/ { u = $2; sub(/:CL:.*/, "", u); p = $2; sub(/^[^:]*:CL:/, "", p) }
    inblock && /^[ \t]*socks / && u != "" {
      for (i = 1; i <= NF; i++) { if ($i ~ /^-p[0-9]+$/) port = substr($i, 3); if ($i ~ /^-i/) ip = substr($i, 3) }
      print port, u, p, ip; exit
    }' "$1"
}

cmd_status() {
  local open=0 total=0 f
  for f in $(cfg_files); do total=$((total + 1)); cfg_is_open "$f" && open=$((open + 1)); done
  log "A1/A2 3proxy configs: $open of $total still open"
  if [ -f "$AGENT_KEY_FILE" ]; then log "A3 agent key: set"; else log "A3 agent key: NOT set"; fi
  if nft list table inet "$NFT_GUARD_TABLE" >/dev/null 2>&1; then log "A3 8085 firewall: on"; else log "A3 8085 firewall: OFF"; fi
  log "A6 authorized_keys comments: $(awk '{print $NF}' /root/.ssh/authorized_keys 2>/dev/null | tr '\n' ' ')"
  log "2026-10-08 credential files readable by others: $(open_cred_paths | wc -l | tr -d ' ')"
  if nft list table inet netrun_proxy_guard 2>/dev/null | grep -q "meta skuid 65535 jump"; then log "2026-10-08 3proxy egress guard: on"; else log "2026-10-08 3proxy egress guard: OFF (or the old skuid != form)"; fi
  if [ -f /etc/systemd/system/nftables.service.d/netrun-boot-fallback.conf ]; then log "2026-10-08 nftables boot fallback: on"; else log "2026-10-08 nftables boot fallback: OFF"; fi
  if [ -f "$SSHD_HARDENING" ]; then log "2026-10-08 ssh keys-only: on"; else log "2026-10-08 ssh keys-only: OFF"; fi
  if [ -f "$UNBOUND_EGRESS_CONF" ]; then log "2026-10-08 unbound egress: $(awk '/outgoing-interface: .*:/ {print $2}' "$UNBOUND_EGRESS_CONF")"; else log "2026-10-08 unbound egress: primary addresses"; fi
}

cmd_auth_fix() {
  [ -x "$BIN" ] || die "3proxy binary not found at $BIN"
  local backup f tmp changed=0
  backup="/root/netrun-harden-backup-$(date +%Y%m%d-%H%M%S)"
  for f in $(cfg_files); do
    cfg_is_open "$f" || continue
    mkdir -p "$backup"
    cp -p "$f" "$backup/"
    tmp="$(mktemp)"
    rewrite_cfg "$f" > "$tmp"
    # Sanity: same number of service lines, no `allow * *` left in a block.
    [ "$(grep -cE '^[ \t]*(socks|proxy) ' "$f")" = "$(grep -cE '^[ \t]*(socks|proxy) ' "$tmp")" ] \
      || die "service line count changed in $f — left untouched (backup in $backup)"
    cfg_is_open "$tmp" && die "rewrite of $f still open — left untouched"
    cat "$tmp" > "$f"; rm -f "$tmp"
    restart_cfg "$f"
    changed=$((changed + 1))
    log "fixed + restarted $(basename "$f")"
  done
  if [ "$changed" -gt 0 ]; then log "$changed config(s) rewritten; backups in $backup"; else log "nothing to fix"; fi
  sleep 3
  # Probe the first proxy of the first live config.
  f="$(ls "$CFG_DIR"/3proxy_*.cfg 2>/dev/null | head -1)"
  [ -n "$f" ] || return 0
  read -r port user pw ip < <(first_proxy "$f")
  [ -n "${port:-}" ] || { log "no proxy found for the probe"; return 0; }
  log "probe $ip:$port own login:   $(socks_probe "$ip" "$port" "$user" "$pw")   (want ALLOWED…)"
  log "probe $ip:$port empty login: $(socks_probe "$ip" "$port" "" "")   (want acl-denied / auth-rejected)"
  log "probe $ip:$port wrong login: $(socks_probe "$ip" "$port" "nobody" "x")   (want acl-denied / auth-rejected)"
}

cmd_agent_key() {
  local key="${1:-}"
  [[ "$key" =~ ^[0-9a-f]{32,128}$ ]] || die "usage: agent-key <hex key, 32-128 chars>"
  mkdir -p "$AGENT_DROPIN_DIR"
  umask 077
  printf '[Service]\nEnvironment=NODE_AGENT_API_KEY=%s\n' "$key" > "$AGENT_KEY_FILE"
  chmod 600 "$AGENT_KEY_FILE"
  systemctl daemon-reload
  systemctl restart "$AGENT_UNIT"
  sleep 2
  local open locked
  open="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:8085/jobs || true)"
  locked="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H "X-API-KEY: $key" http://127.0.0.1:8085/jobs || true)"
  log "agent /jobs without key: $open (want 401), with key: $locked (want 200)"
  [ "$open" = "401" ] && [ "$locked" = "200" ] || die "agent key check failed"
}

cmd_agent_firewall() {
  local ip="${1:-}"
  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "usage: agent-firewall <orchestrator IPv4>"
  nft delete table inet "$NFT_GUARD_TABLE" 2>/dev/null || true
  nft -f - <<NFT
table inet $NFT_GUARD_TABLE {
  chain input {
    type filter hook input priority -5; policy accept;
    iifname "lo" accept
    tcp dport 8085 ip saddr $ip accept
    tcp dport 8085 drop
  }
}
NFT
  nft_persist || log "WARNING: the ruleset was not persisted (rerun: netrun-nft-persist save)"
  log "8085 now open only to $ip and localhost (persisted to /etc/nftables.conf)"
}

# KEY DEFAULT -> the environment wins, then $NETRUN_ENV (KEY=VALUE lines).
netrun_setting() {
  local key="$1" def="$2" v="${!1:-}"
  if [ -z "$v" ] && [ -r "$NETRUN_ENV" ]; then
    v="$(awk -v k="$key" '{ sub(/^[ \t]+/, "") } index($0, k "=") == 1 { v = substr($0, length(k) + 2) } END { gsub(/^["\047 \t]+|["\047 \t\r]+$/, "", v); print v }' "$NETRUN_ENV")"
  fi
  printf '%s' "${v:-$def}"
}

# Audit 2026-10-08 — the ruleset goes to /etc/nftables.conf only through
# netrun-nft-persist (atomic, one lock for every writer, .prev kept).
nft_persist() {
  local h t
  for h in "${NETRUN_NFT_PERSIST_BIN:-}" /usr/local/sbin/netrun-nft-persist "$SCRIPT_DIR/netrun-nft-persist.sh"; do
    if [ -n "$h" ] && [ -f "$h" ]; then bash "$h" save "$@"; return; fi
  done
  t="$(mktemp "$(dirname "$NFT_CONF")/.nftables.conf.XXXXXX")" || return 1
  if nft list ruleset > "$t" && [ -s "$t" ]; then mv -f "$t" "$NFT_CONF"; else rm -f "$t"; return 1; fi
}

# ── audit 2026-10-08 ──────────────────────────────────────────────

# The files under PROXY_ROOT / its 3proxy dir / JOBS_ROOT that are still
# readable by group or others (count).
open_cred_paths() {
  { for d in "$PROXY_ROOT" "$CFG_DIR"; do [ -d "$d" ] && find "$d" -maxdepth 1 \( -type f -o -type d \) -print; done
    [ -d "$JOBS_ROOT" ] && find "$JOBS_ROOT" \( -type f -o -type d \) -print; } 2>/dev/null \
    | while IFS= read -r f; do
        m="$(stat -c %a "$f" 2>/dev/null || stat -f %Lp "$f" 2>/dev/null)"
        case "$m" in *00) ;; *) echo "$f" ;; esac
      done
}

cmd_perms() {
  local n
  n="$(open_cred_paths | wc -l | tr -d ' ')"
  { for d in "$PROXY_ROOT" "$CFG_DIR"; do [ -d "$d" ] && find "$d" -maxdepth 1 \( -type f -o -type d \) -print0; done
    [ -d "$JOBS_ROOT" ] && find "$JOBS_ROOT" \( -type f -o -type d \) -print0; } 2>/dev/null \
    | xargs -0 -r chmod go-rwx 2>/dev/null || true
  chmod go-rwx "$NFT_CONF" "$NFT_CONF".prev "$NFT_CONF".bak* "$NETRUN_ENV" 2>/dev/null || true
  [ -d /var/backups/netrun-legacy48 ] && chmod -R go-rwx /var/backups/netrun-legacy48 2>/dev/null || true
  log "perms: $n path(s) under $PROXY_ROOT / $JOBS_ROOT were readable by others — now root-only ($(open_cred_paths | wc -l | tr -d ' ') left)"
}

sshd_hardening_text() {
  cat <<'EOF'
# NETRUN (audit 2026-10-08): keys only; sorts before 50-cloud-init.conf, so it wins
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
EOF
}

cmd_ssh() {
  local text prev=""
  text="$(sshd_hardening_text)"
  if [ -f "$SSHD_HARDENING" ] && [ "$(cat "$SSHD_HARDENING")" = "$text" ]; then
    log "ssh: $SSHD_HARDENING already keys-only"
    return 0
  fi
  if ! grep -qE '^(ssh-|ecdsa-|sk-)' "$ROOT_AUTH_KEYS" 2>/dev/null; then
    log "WARNING ssh: root has no authorized key in $ROOT_AUTH_KEYS — keys-only would lock root out; NOT applied"
    return 0
  fi
  [ -f "$SSHD_HARDENING" ] && prev="$(cat "$SSHD_HARDENING")"
  mkdir -p "$(dirname "$SSHD_HARDENING")"
  printf '%s\n' "$text" > "$SSHD_HARDENING.tmp" && chmod 0644 "$SSHD_HARDENING.tmp" && mv -f "$SSHD_HARDENING.tmp" "$SSHD_HARDENING" \
    || die "cannot write $SSHD_HARDENING"
  if command -v sshd >/dev/null 2>&1 && ! sshd -t >/dev/null 2>&1; then
    if [ -n "$prev" ]; then printf '%s\n' "$prev" > "$SSHD_HARDENING"; else rm -f "$SSHD_HARDENING"; fi
    die "sshd -t rejects the config with $SSHD_HARDENING — put back as it was"
  fi
  systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1 || log "WARNING ssh: reload failed — applies at the next sshd start"
  log "ssh: keys only ($SSHD_HARDENING), sshd reloaded (open sessions stay)"
}

# reserved_net <prefix>: "<the last /64 of the prefix> <its ::53> <its ::1>",
# or nothing (not an IPv6 prefix shorter than /64). Same rule: the generator's
# routed allocator and egress.js (nodeReservedNet) — that /64 is never a proxy's.
reserved_net() {
  python3 - "$1" <<'PYR' 2>/dev/null
import ipaddress, sys
try:
    p = ipaddress.IPv6Network(sys.argv[1].strip(), strict=False)
except ValueError:
    sys.exit(1)
if not 16 <= p.prefixlen <= 63:
    sys.exit(1)
last = ((int(p.network_address) | ((1 << (128 - p.prefixlen)) - 1)) >> 64) << 64
print(ipaddress.IPv6Network((last, 64)), ipaddress.IPv6Address(last | 0x53), ipaddress.IPv6Address(last | 1))
PYR
}

# 0 when PREFIX is inside a `local … dev lo` route (the node answers for it).
prefix_routed_here() {
  ip -6 route show table local dev lo 2>/dev/null | python3 -c '
import ipaddress, re, sys
want = ipaddress.IPv6Network(sys.argv[1], strict=False)
for line in sys.stdin:
    m = re.match(r"local\s+([0-9a-fA-F:]+/\d+)", line)
    if m and want.subnet_of(ipaddress.IPv6Network(m.group(1), strict=False)):
        sys.exit(0)
sys.exit(1)' "$1"
}

unbound_egress_text() {  # <prefix> <reserved /64> <dns address>
  cat <<EOF
# NETRUN — unbound's recursion leaves from the node's own /64 of the routed
# prefix $1 ($2: the last /64, never a proxy's), not from the primary
# addresses next to the customer exits (DNS leak, audit 2026-10-08).
# Written by netrun-harden.sh dns-egress — do not edit. IPv4 recursion is
# unchanged (0.0.0.0 = the kernel's source, as without this file).
server:
    outgoing-interface: 0.0.0.0
    outgoing-interface: $3
    prefer-ip6: yes
EOF
}

unbound_reload() {
  systemctl reload unbound >/dev/null 2>&1 || unbound-control reload >/dev/null 2>&1 || systemctl restart unbound >/dev/null 2>&1
}

# A lookup through the local unbound answers (NOERROR with an answer).
dns_lookup_ok() {
  local i out
  command -v dig >/dev/null 2>&1 || { log "dns-egress: no dig — lookup not verified"; return 0; }
  for i in 1 2 3; do
    out="$(dig +time=3 +tries=1 @127.0.0.1 "$DNS_TEST_NAME" AAAA 2>/dev/null)"
    if printf '%s\n' "$out" | grep -q 'status: NOERROR' && printf '%s\n' "$out" | grep -qE 'ANSWER: [1-9]'; then return 0; fi
    sleep 1
  done
  return 1
}

cmd_dns_egress() {
  local prefix rn net addr text prev=""
  prefix="$(netrun_setting NETRUN_IPV6_ROUTED_PREFIX "")"
  if [ -z "$prefix" ] || [ "$(printf '%s' "$prefix" | tr '[:upper:]' '[:lower:]')" = off ]; then
    if [ -f "$UNBOUND_EGRESS_CONF" ]; then
      rm -f "$UNBOUND_EGRESS_CONF"
      unbound_reload || log "WARNING dns-egress: unbound reload failed"
      log "dns-egress: no routed prefix — $UNBOUND_EGRESS_CONF removed, unbound recurses from the primary addresses"
    else
      log "dns-egress: no routed prefix (NETRUN_IPV6_ROUTED_PREFIX) — nothing to do"
    fi
    return 0
  fi
  rn="$(reserved_net "$prefix")" || die "dns-egress: $prefix is not an IPv6 prefix /16../63 (no /64 to reserve)"
  read -r net addr _ <<< "$rn"
  if ! prefix_routed_here "$prefix"; then
    log "WARNING dns-egress: $prefix is not routed to this host (no local route on lo) — unbound left as it is"
    return 0
  fi
  text="$(unbound_egress_text "$prefix" "$net" "$addr")"
  if [ -f "$UNBOUND_EGRESS_CONF" ] && [ "$(cat "$UNBOUND_EGRESS_CONF")" = "$text" ]; then
    log "dns-egress: unbound already recurses from $addr"
    return 0
  fi
  [ -f "$UNBOUND_EGRESS_CONF" ] && prev="$(cat "$UNBOUND_EGRESS_CONF")"
  put_back() {
    if [ -n "$prev" ]; then printf '%s\n' "$prev" > "$UNBOUND_EGRESS_CONF"; else rm -f "$UNBOUND_EGRESS_CONF"; fi
  }
  mkdir -p "$(dirname "$UNBOUND_EGRESS_CONF")"
  printf '%s\n' "$text" > "$UNBOUND_EGRESS_CONF" && chmod 0644 "$UNBOUND_EGRESS_CONF" || die "cannot write $UNBOUND_EGRESS_CONF"
  if ! unbound-checkconf >/dev/null 2>&1; then
    put_back
    die "dns-egress: unbound-checkconf rejects $UNBOUND_EGRESS_CONF — put back as it was"
  fi
  if ! unbound_reload || ! dns_lookup_ok; then
    put_back
    unbound_reload || true
    die "dns-egress: no answer through unbound from $addr (is $prefix announced / net.ipv6.ip_nonlocal_bind=1?) — put back as it was"
  fi
  # The lookup above may have been answered over IPv4: say so when a query
  # sent FROM the address gets no answer (the prefix does not route back).
  if command -v dig >/dev/null 2>&1 \
     && ! dig -b "$addr" +time=3 +tries=1 +norec @2001:500:2f::f . SOA 2>/dev/null | grep -q 'status: NOERROR'; then
    log "WARNING dns-egress: no answer to a query sent from $addr — IPv6 recursion falls back to IPv4 until $prefix routes back (BGP)"
  fi
  log "dns-egress: unbound recurses from $addr ($net reserved for the node), prefer-ip6"
}

cmd_secure() {
  local rc=0
  bash "$SCRIPT_DIR/netrun-nft-persist.sh" install || { log "WARNING: netrun-nft-persist install failed"; rc=1; }
  bash "$SCRIPT_DIR/netrun-proxy-guard.sh" apply || { log "WARNING: netrun-proxy-guard apply failed"; rc=1; }
  ( cmd_perms ) || rc=1
  ( cmd_ssh ) || rc=1
  ( cmd_dns_egress ) || rc=1
  nft_persist || log "WARNING: the ruleset was not persisted (the previous /etc/nftables.conf is kept)"
  return "$rc"
}

cmd_drop_ssh_key() {
  local comment="${1:-}" f=/root/.ssh/authorized_keys
  [ -n "$comment" ] || die "usage: drop-ssh-key <key comment>"
  [ -f "$f" ] || die "$f missing"
  cp -p "$f" "$f.bak-$(date +%Y%m%d-%H%M%S)"
  local before after
  before="$(wc -l < "$f")"
  awk -v c="$comment" '$NF != c' "$f" > "$f.tmp" && cat "$f.tmp" > "$f" && rm -f "$f.tmp"
  after="$(wc -l < "$f")"
  log "removed $((before - after)) key(s) with comment $comment"
}

case "${1:-}" in
  status) cmd_status ;;
  auth-fix) cmd_auth_fix ;;
  agent-key) shift; cmd_agent_key "$@" ;;
  agent-firewall) shift; cmd_agent_firewall "$@" ;;
  drop-ssh-key) shift; cmd_drop_ssh_key "$@" ;;
  perms) cmd_perms ;;
  ssh) cmd_ssh ;;
  dns-egress) cmd_dns_egress ;;
  secure) cmd_secure ;;
  rewrite-preview) shift; rewrite_cfg "$1" ;;   # test hook: print the rewrite of one cfg
  *) sed -n '2,52p' "$0"; exit 2 ;;
esac
