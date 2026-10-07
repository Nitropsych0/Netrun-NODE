#!/usr/bin/env bash
# NETRUN — follow-up hardening v2.
#
# Changes vs v1 (post-2026-05-15 incident, see project memory):
#   - watchdog NO LONGER reboots — it restarts netrun-node-agent.
#     v1 watchdog rebooted nodes daily because /health periodically stalled.
#   - restore_3proxy spawns 3proxy in bounded parallel batches instead of
#     blasting 4000+ forks at once. v1 hit fork EAGAIN at boot and left
#     phantom inventory.
#   - kernel pids / threads / FD / conntrack limits raised. Old defaults
#     (pid_max=65536, threads-max=65536) topple over with 4000 3proxy.
#   - systemd unit gets TasksMax=infinity + LimitNOFILE=1048576 so the
#     restore script itself doesn't get cgroup-throttled.

set -euo pipefail

log()  { printf "\033[01;32m[followup-v2]\033[0m %s\n" "$*"; }
warn() { printf "\033[01;33m[followup-v2]\033[0m %s\n" "$*"; }
fail() { printf "\033[01;31m[followup-v2]\033[0m %s\n" "$*"; exit 1; }

# ── 1) Discover 3proxy paths ─────────────────────────────────────
PROXY_BIN=""
PROXY_CFG_DIR=""
for candidate in \
  "/opt/netrun/proxyserver/3proxy" \
  "/root/proxyserver/3proxy" \
  "/opt/3proxy" \
  "/usr/local/3proxy"; do
  if [ -x "$candidate/bin/3proxy" ]; then
    PROXY_BIN="$candidate/bin/3proxy"
    PROXY_CFG_DIR="$candidate"
    break
  fi
done

if [ -z "$PROXY_CFG_DIR" ]; then
  warn "3proxy binary not found in any known location"
  warn "Searching disk for 3proxy_*.cfg…"
  sample=$(find / -maxdepth 6 -name "3proxy_*.cfg" 2>/dev/null | head -1 || true)
  if [ -n "$sample" ]; then
    PROXY_CFG_DIR="$(dirname "$sample")"
    log "  found cfgs in $PROXY_CFG_DIR"
    parent="$(dirname "$PROXY_CFG_DIR")"
    if [ -x "$parent/bin/3proxy" ]; then
      PROXY_BIN="$parent/bin/3proxy"
    elif [ -x "$PROXY_CFG_DIR/3proxy" ]; then
      PROXY_BIN="$PROXY_CFG_DIR/3proxy"
    else
      PROXY_BIN="$(find / -maxdepth 6 -name 3proxy -type f -executable 2>/dev/null | head -1 || true)"
    fi
  fi
fi

if [ -z "$PROXY_BIN" ] || [ ! -x "$PROXY_BIN" ]; then
  fail "Cannot find 3proxy binary. Set PROXY_BIN manually and re-run."
fi
log "  3proxy bin: $PROXY_BIN"
log "  cfg dir   : $PROXY_CFG_DIR"

# ── 2) Kernel limits ─────────────────────────────────────────────
# Wave CAPACITY-18K — MERGE into 99-netrun.conf instead of overwriting it. The
# old `cat > 99-netrun.conf` threw away what install_node_v2.sh had written
# there (accept_ra=2, tcp_timestamps=1, tcp_mtu_probing=1 — the Android-like
# fingerprint — and the capacity ephemeral range ip_local_port_range=1024 8000)
# and forced the range back to 10000-65000, i.e. into the proxy listener ports.
# Now only the keys below are set (same values as install_node_v2.sh); every
# other line, including ip_local_port_range, is kept as found. The ephemeral
# range is owned by install_node_v2.sh (new nodes) and
# scripts/apply_capacity_tuning.sh (existing nodes, opt-in).
merge_sysctl_conf() {
  local file="$1"; shift
  local kv key value ek tmp
  [ -f "$file" ] || printf '# NETRUN — node sysctl (install_node_v2.sh + node_followup_v2.sh)\n' > "$file"
  for kv in "$@"; do
    key="${kv%%=*}"; value="${kv#*=}"
    ek="$(printf '%s' "$key" | sed 's/[.]/\\./g')"
    if grep -Eq "^[[:space:]]*${ek}[[:space:]]*=" "$file"; then
      tmp="$(mktemp)"
      sed -E "s|^[[:space:]]*${ek}[[:space:]]*=.*$|${key} = ${value}|" "$file" > "$tmp" && cat "$tmp" > "$file"
      rm -f "$tmp"
    else
      printf '%s = %s\n' "$key" "$value" >> "$file"
    fi
  done
}

log "Applying kernel sysctl tweaks (merge into /etc/sysctl.d/99-netrun.conf)"
# NETRUN — raised limits for 4000+ concurrent 3proxy instances.
# Default kernel.pid_max=65536 / threads-max=65536 trips fork EAGAIN
# when restore script respawns the full pool at boot.
merge_sysctl_conf /etc/sysctl.d/99-netrun.conf \
  "kernel.pid_max=4194304" \
  "kernel.threads-max=4194304" \
  "net.netfilter.nf_conntrack_tcp_timeout_established=7200" \
  "net.core.somaxconn=8192" \
  "net.ipv4.tcp_max_syn_backlog=8192" \
  "fs.file-max=2097152" \
  "net.ipv6.ip_nonlocal_bind=1" \
  "net.ipv6.conf.all.forwarding=1" \
  "net.ipv6.conf.default.forwarding=1"

# Wave FLEET-HEALTH — conntrack: RAM-sized ceiling that survives reboots (same
# logic as install_node_v2.sh configure_conntrack_persistence; see there).
# nf_conntrack is loaded from modules-load.d BEFORE systemd-sysctl, and a udev
# rule re-applies net.netfilter.* whenever the module is (re)loaded — without
# that the persisted value was skipped at boot and the kernel default (65536
# at 1-4 GB) won. One entry per 8 KB RAM, power of two, 65536..1048576
# (NETRUN_CONNTRACK_MAX overrides): 2c/4GB -> 262144 (~85 MB when full).
conntrack_max_for_mem_kb() {
  local kb="${1:-0}" v=65536
  case "$kb" in ''|*[!0-9]*) kb=0 ;; esac
  while [ "$v" -lt 1048576 ] && [ $((v * 2)) -le $((kb / 8)) ]; do v=$((v * 2)); done
  echo "$v"
}
CONNTRACK_MAX="${NETRUN_CONNTRACK_MAX:-$(conntrack_max_for_mem_kb "$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo 2>/dev/null || true)")}"
log "Conntrack: nf_conntrack_max=$CONNTRACK_MAX, nf_conntrack loaded at boot before systemd-sysctl"
mkdir -p /etc/modules-load.d /etc/udev/rules.d
printf '# NETRUN — load conntrack before systemd-sysctl so net.netfilter.* in /etc/sysctl.d apply at boot\nnf_conntrack\n' \
  > /etc/modules-load.d/netrun-conntrack.conf
printf '# NETRUN — re-apply net.netfilter.* sysctls whenever nf_conntrack is (re)loaded\nACTION=="add", SUBSYSTEM=="module", KERNEL=="nf_conntrack", RUN+="/usr/lib/systemd/systemd-sysctl --prefix=/net/netfilter"\n' \
  > /etc/udev/rules.d/90-netrun-conntrack.rules
udevadm control --reload >/dev/null 2>&1 || true
merge_sysctl_conf /etc/sysctl.d/99-netrun.conf "net.netfilter.nf_conntrack_max=$CONNTRACK_MAX"
modprobe nf_conntrack 2>/dev/null || true
sysctl -p /etc/sysctl.d/99-netrun.conf >/dev/null 2>&1 || warn "sysctl -p had warnings (likely nf_conntrack module not loaded yet — applied on next boot)"

log "Applying ulimit raises (/etc/security/limits.d/99-netrun.conf)"
cat > /etc/security/limits.d/99-netrun.conf <<'LIMITS'
root soft nofile 1048576
root hard nofile 1048576
*    soft nofile 1048576
*    hard nofile 1048576
root soft nproc  unlimited
root hard nproc  unlimited
*    soft nproc  unlimited
*    hard nproc  unlimited
LIMITS

# ── 3) Install netrun-3proxy-restore.service (bounded parallel) ──
log "Installing netrun-3proxy-restore (v2 — bounded parallel, no fork-bomb)"
mkdir -p /opt/netrun/scripts
RESTORE_SCRIPT="/opt/netrun/scripts/restore_3proxy.sh"

cat > "$RESTORE_SCRIPT" <<RESTORESH
#!/usr/bin/env bash
# v2: bounded parallel spawn (4 streams), no fork-bomb.
# Sleeps every batch to give scheduler/cgroup time to absorb new pids.
set -u
PROXY_BIN="$PROXY_BIN"
PROXY_CFG_DIR="$PROXY_CFG_DIR"
LOG_TAG="netrun-3proxy-restore"
PARALLEL=4
SLEEP_MS=300

if [ ! -x "\$PROXY_BIN" ]; then
  logger -t "\$LOG_TAG" "skip: 3proxy binary not found at \$PROXY_BIN"
  exit 0
fi

# Crank up our own FD/proc limits early
ulimit -n 1048576 2>/dev/null || true
ulimit -u unlimited 2>/dev/null || true

# Snapshot what's already listening — one ss call, not per-port
listening=\$(ss -tln 2>/dev/null | awk '{print \$4}' | awk -F: '{print \$NF}' | sort -u)

# Build worklist
shopt -s nullglob
worklist=\$(mktemp)
trap 'rm -f \$worklist' EXIT
for cfg in "\$PROXY_CFG_DIR"/3proxy_*.cfg; do
  [ -f "\$cfg" ] || continue
  port=\$(basename "\$cfg" .cfg | sed 's/3proxy_//')
  if ! echo "\$listening" | grep -qx "\$port"; then
    printf '%s\n' "\$cfg" >> "\$worklist"
  fi
done

total=\$(wc -l < "\$worklist")
logger -t "\$LOG_TAG" "starting: \$total cfgs need 3proxy spawn, parallel=\$PARALLEL"

# Spawn in batches via xargs — controlled parallelism, never explodes
started=0
< "\$worklist" xargs -n 1 -P "\$PARALLEL" -I {} bash -c '
  "'"\$PROXY_BIN"'" "{}" </dev/null >/dev/null 2>&1 & disown 2>/dev/null || true
  sleep 0.'"\$SLEEP_MS"'
' 2>/dev/null || true

sleep 3
active=\$(ss -tln 2>/dev/null | grep -cE ':[1-9][0-9]{3,4} ' || echo 0)
logger -t "\$LOG_TAG" "done: queued=\$total, total_listening_after=\$active"
exit 0
RESTORESH
chmod +x "$RESTORE_SCRIPT"

cat > /etc/systemd/system/netrun-3proxy-restore.service <<EOF
[Unit]
Description=NETRUN — restore all 3proxy instances from saved cfg files (v2)
After=network-online.target netrun-node-agent.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$RESTORE_SCRIPT
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal
TimeoutStartSec=900
# v2: don't let our own cgroup throttle the respawn
TasksMax=infinity
LimitNOFILE=1048576
LimitNPROC=infinity

[Install]
WantedBy=multi-user.target
EOF

# ── 4) Install netrun-watchdog v3 (two-tier: restart, then reboot) ────
log "Installing netrun-watchdog (v3 — restart-then-reboot for Vultr abuse-block)"

WATCHDOG_SCRIPT="/opt/netrun/scripts/watchdog_probe.sh"
mkdir -p /var/lib/netrun

cat > "$WATCHDOG_SCRIPT" <<'WATCHDOG'
#!/usr/bin/env bash
# v3 watchdog with two tiers (Incident 2026-05-18 finding):
#
#   Tier 1: RESTART_THRESHOLD (5) consecutive /health fails →
#           `systemctl restart netrun-node-agent`.
#           Cooldown 10 min between restarts.
#           Lечит локальные зависания node-agent.
#
#   Tier 2: REBOOT_THRESHOLD (20) consecutive fails — i.e. ~20 min
#           continuous downtime → `reboot`.
#           Cooldown 4 hours between reboots.
#           Lечит Vultr abuse-network-block (VM Running но сетка blocked,
#           SSH/8085 unreachable извне; reboot снимает block).
#
# v1 (rebooted at 3 fails) — too aggressive, daily reboots.
# v2 (restart only, no reboot) — Vultr-block остаётся, ноды лежат намертво.
# v3 (restart + reboot fallback) — компромисс: локальные зависания и
# Vultr-block обрабатываются разной механикой.
set -u
STATE_FAIL="/var/lib/netrun/watchdog_failures"
STATE_LAST_RESTART="/var/lib/netrun/watchdog_last_restart"
STATE_LAST_REBOOT="/var/lib/netrun/watchdog_last_reboot"
LOG_TAG="netrun-watchdog"
RESTART_THRESHOLD=5
RESTART_COOLDOWN_SEC=600
REBOOT_THRESHOLD=20
REBOOT_COOLDOWN_SEC=14400
PROBE_TIMEOUT=5

current=$(cat "$STATE_FAIL" 2>/dev/null || echo 0)
current=${current//[^0-9]/}
: "${current:=0}"

if curl --silent --fail --max-time "$PROBE_TIMEOUT" http://127.0.0.1:8085/health >/dev/null 2>&1; then
  if [ "$current" -gt 0 ]; then
    logger -t "$LOG_TAG" "recovery: was $current consecutive failures, now OK"
    echo 0 > "$STATE_FAIL"
  fi
  exit 0
fi

new=$((current + 1))
echo "$new" > "$STATE_FAIL"
logger -t "$LOG_TAG" "probe failed ($new fails — restart@$RESTART_THRESHOLD, reboot@$REBOOT_THRESHOLD)"

now=$(date +%s)

# ── Tier 2: REBOOT after $REBOOT_THRESHOLD continuous failures ──
if [ "$new" -ge "$REBOOT_THRESHOLD" ]; then
  last_reboot=$(cat "$STATE_LAST_REBOOT" 2>/dev/null || echo 0)
  last_reboot=${last_reboot//[^0-9]/}
  : "${last_reboot:=0}"
  elapsed=$((now - last_reboot))

  if [ "$elapsed" -ge "$REBOOT_COOLDOWN_SEC" ]; then
    logger -t "$LOG_TAG" "REBOOT — $REBOOT_THRESHOLD consecutive /health failures (~$(( new * 60 / 60 )) min downtime), last reboot ${elapsed}s ago"
    echo "$now" > "$STATE_LAST_REBOOT"
    echo 0 > "$STATE_FAIL"
    /sbin/reboot
    exit 0
  else
    logger -t "$LOG_TAG" "reboot threshold reached but in cooldown ($elapsed/${REBOOT_COOLDOWN_SEC}s) — waiting"
    exit 0
  fi
fi

# ── Tier 1: RESTART netrun-node-agent after $RESTART_THRESHOLD failures ──
if [ "$new" -lt "$RESTART_THRESHOLD" ]; then
  exit 0
fi

last_restart=$(cat "$STATE_LAST_RESTART" 2>/dev/null || echo 0)
last_restart=${last_restart//[^0-9]/}
: "${last_restart:=0}"
elapsed=$((now - last_restart))

if [ "$elapsed" -lt "$RESTART_COOLDOWN_SEC" ]; then
  logger -t "$LOG_TAG" "restart threshold reached but in cooldown ($elapsed/${RESTART_COOLDOWN_SEC}s) — waiting"
  exit 0
fi

logger -t "$LOG_TAG" "RESTART netrun-node-agent — $RESTART_THRESHOLD consecutive /health failures"
echo "$now" > "$STATE_LAST_RESTART"
# Note: do NOT reset STATE_FAIL here — let it keep counting up to REBOOT_THRESHOLD
# in case restart didn't help (i.e. Vultr-block, not local hang).
systemctl restart netrun-node-agent || logger -t "$LOG_TAG" "systemctl restart failed: $?"
WATCHDOG
chmod +x "$WATCHDOG_SCRIPT"

cat > /etc/systemd/system/netrun-watchdog.service <<EOF
[Unit]
Description=NETRUN — /health watchdog (v3: restart-then-reboot tier)
After=netrun-node-agent.service

[Service]
Type=oneshot
ExecStart=$WATCHDOG_SCRIPT
EOF

cat > /etc/systemd/system/netrun-watchdog.timer <<'EOF'
[Unit]
Description=NETRUN — fire watchdog probe every 60 sec

[Timer]
OnBootSec=2min
OnUnitActiveSec=60s
AccuracySec=5s
Unit=netrun-watchdog.service

[Install]
WantedBy=timers.target
EOF

# Wave IPV6-ROTATION — a saved /etc/nftables.conf may hold the agent's table
# ip6 netrun_egress, whose addresses are gone after a reboot (the watchdog's
# tier 2 reboots): nftables.service deletes it right after the boot load, so
# proxies leave from their anchors until the agent rebuilds it. The agent
# writes the same file at start (egress.js nftDropinText).
NFT_BIN="$(command -v nft || echo /usr/sbin/nft)"
mkdir -p /etc/systemd/system/nftables.service.d
cat > /etc/systemd/system/nftables.service.d/netrun-egress.conf <<EOF
# NETRUN IPv6 egress rotation (node-agent egress.js; install_node_v2.sh, node_followup_v2.sh).
# A saved ruleset may hold table ip6 netrun_egress, whose addresses are gone after a
# reboot: drop it after the boot load. Proxies leave from their anchors until the agent
# rebuilds the table from egress_state.json.
[Service]
ExecStartPost=-${NFT_BIN} delete table ip6 netrun_egress
EOF

# ── 5) Enable + reset stale failure counter ─────────────────────
systemctl daemon-reload
systemctl enable netrun-3proxy-restore.service >/dev/null
systemctl enable netrun-watchdog.timer >/dev/null
echo 0 > /var/lib/netrun/watchdog_failures 2>/dev/null || true
rm -f /var/lib/netrun/watchdog_last_restart 2>/dev/null || true
systemctl start  netrun-watchdog.timer

# Also bump node-agent service limits if it's installed
if [ -f /etc/systemd/system/netrun-node-agent.service ]; then
  if ! grep -q "TasksMax=infinity" /etc/systemd/system/netrun-node-agent.service; then
    log "Patching netrun-node-agent.service with raised limits"
    # Insert under [Service] block
    sed -i '/^\[Service\]/a TasksMax=infinity\nLimitNOFILE=1048576\nLimitNPROC=infinity' /etc/systemd/system/netrun-node-agent.service
    systemctl daemon-reload
  fi
fi

# ── 5b) HTTPS on the HTTP proxy ports ────────────────────────────
# haproxy fronts every HTTP proxy port and answers both plain HTTP and HTTPS
# (TLS) proxy clients with a Let's Encrypt IP certificate (auto-renewed).
# Non-fatal: HTTP / SOCKS keep working if it fails; rerun `netrun-https setup`.
if [ "${NETRUN_HTTPS:-1}" = "1" ]; then
  _https_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/netrun-https.sh"
  if [ -f "$_https_script" ]; then
    log "Enabling HTTPS on the HTTP proxy ports"
    bash "$_https_script" setup || log "WARNING: HTTPS setup failed — HTTP/SOCKS unaffected; rerun: netrun-https setup"
  fi
fi

# ── 6) Post-conditions ──────────────────────────────────────────
log "─── Verification ───"
printf "  restore unit  : "
systemctl is-enabled netrun-3proxy-restore.service 2>/dev/null
printf "  watchdog timer: "
systemctl is-active  netrun-watchdog.timer 2>/dev/null
printf "  watchdog next : "
systemctl list-timers netrun-watchdog.timer --no-pager 2>/dev/null \
  | awk 'NR==2 {print $1, $2}'
printf "  /health probe : "
curl -s --max-time 3 http://127.0.0.1:8085/health >/dev/null \
  && echo "200 OK" || echo "FAIL (watchdog will restart node-agent if persists)"
printf "  pid_max       : "
cat /proc/sys/kernel/pid_max
printf "  threads-max   : "
cat /proc/sys/kernel/threads-max
printf "  nf_conntrack  : "
cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo "(module not loaded)"

log "Follow-up v2 complete on $(hostname)"
