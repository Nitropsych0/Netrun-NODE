#!/usr/bin/env bash
# netrun-harden.sh — security fixes for a live NETRUN node (2026-10-02 audit).
#
#   status                 show what is still open (read-only)
#   auth-fix               A1+A2: each proxy port admits ONLY its own login and
#                          no empty login. Rewrites every 3proxy_*.cfg (backup
#                          first), restarts each 3proxy (~2 s per batch file),
#                          then probes a port: empty/foreign login must fail.
#   agent-key <hex>        A3: require X-API-KEY on the node-agent (8085).
#                          /health and /describe stay open (local watchdog).
#                          3proxy is NOT restarted (KillMode=process).
#   agent-firewall <ip>    A3: 8085 reachable only from the orchestrator <ip>
#                          and localhost. Persisted to /etc/nftables.conf.
#   drop-ssh-key <comment> A6: remove authorized_keys lines ending in <comment>.
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
AGENT_UNIT="netrun-node-agent"
AGENT_DROPIN_DIR="/etc/systemd/system/${AGENT_UNIT}.service.d"
AGENT_KEY_FILE="$AGENT_DROPIN_DIR/20-api-key.conf"
NFT_GUARD_TABLE="netrun_agent_guard"

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
  # Respawn in its OWN systemd scope (the cfg has `daemon`, so 3proxy forks and
  # systemd-run returns): run from an SSH session, a plain nohup would leave the
  # batch inside that session's scope.
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
  nft list ruleset > /etc/nftables.conf
  log "8085 now open only to $ip and localhost (persisted to /etc/nftables.conf)"
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
  rewrite-preview) shift; rewrite_cfg "$1" ;;   # test hook: print the rewrite of one cfg
  *) sed -n '2,20p' "$0"; exit 2 ;;
esac
