#!/usr/bin/env bash
# install_node_v2.sh — copy of install_node.sh + 4 fixes from 2026-05-15 incident:
#   1. sysctl: kernel.pid_max + threads-max raised to 4M (default 65536 trips
#      fork EAGAIN when restore-3proxy respawns 4400+ instances at boot)
#   2. systemd: restore service gets TasksMax=infinity + LimitNOFILE=1048576
#      + LimitNPROC=infinity (so its own cgroup doesn't throttle the spawn)
#   3. restore-3proxy.sh: bounded parallel via `xargs -P 4` + setsid detach
#      (old version `for cfg; do 3proxy & done` was the fork-bomb)
#   4. node-agent service gets the same raised limits (1M FDs, infinity pids)
#
# Diff against install_node.sh is intentionally minimal — only the functions
# below have actual changes. Diff with:
#   diff install_node.sh install_node_v2.sh

set -euo pipefail

NETRUN_HOME="/opt/netrun"
PROXY_ROOT="/opt/netrun/proxyserver"
JOBS_ROOT="/opt/netrun/jobs"
SERVICE_NAME="netrun-node-agent"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SYSCTL_FILE="/etc/sysctl.d/99-netrun.conf"
SYSCTL_IPV6_FILE="/etc/sysctl.d/98-netrun-ipv6.conf"
LIMITS_FILE="/etc/security/limits.d/99-netrun.conf"
RESOLV_CONF="/etc/resolv.conf"
RESTORE_SERVICE_NAME="netrun-3proxy-restore"
RESTORE_SERVICE_FILE="/etc/systemd/system/${RESTORE_SERVICE_NAME}.service"
RESTORE_SCRIPT="/opt/netrun/scripts/restore-3proxy.sh"
DOCTOR_SCRIPT="/opt/netrun/scripts/netrun-doctor.sh"
HEALTH_URL="http://127.0.0.1:8085/health"

CLEAN_REQUESTED=0
REMOVE_LEGACY_ROOT=0
TMP_SOURCE=""

log() { printf '[install_node_v2] %s\n' "$*"; }
warn() { printf '[install_node_v2] WARNING: %s\n' "$*" >&2; }
die() { printf '[install_node_v2] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: bash install_node_v2.sh [--clean] [--remove-legacy-root]

Options:
  --clean               Run scripts/clean_node.sh before installing.
  --remove-legacy-root  With --clean, also remove /root/proxyserver.
EOF
}

cleanup_tmp() { [ -n "$TMP_SOURCE" ] && [ -d "$TMP_SOURCE" ] && rm -rf "$TMP_SOURCE" || true; }
trap cleanup_tmp EXIT

for arg in "$@"; do
  case "$arg" in
    --clean) CLEAN_REQUESTED=1 ;;
    --remove-legacy-root) REMOVE_LEGACY_ROOT=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $arg" ;;
  esac
done

[ "${EUID}" -ne 0 ] && die "must_run_as_root"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SOURCE_DIR="$SCRIPT_DIR"

ensure_bundled_3proxy() {
  local binary="$1/deploy/node/bin/3proxy"
  [ -f "$binary" ] || die "missing_bundled_3proxy_binary: expected $binary"
}

copy_source_to_tmp() {
  TMP_SOURCE="$(mktemp -d /tmp/netrun-node-source.XXXXXX)"
  tar -C "$SOURCE_DIR" --exclude='./.git' -cf - . | tar -C "$TMP_SOURCE" -xpf -
  SOURCE_DIR="$TMP_SOURCE"
}

run_clean_if_requested() {
  [ "$CLEAN_REQUESTED" -ne 1 ] && return 0
  local source_real
  source_real="$(realpath "$SOURCE_DIR")"
  if [ "$source_real" = "$NETRUN_HOME" ] || [[ "$source_real" == "$NETRUN_HOME/"* ]]; then
    copy_source_to_tmp
  fi
  local clean_script="$SOURCE_DIR/scripts/clean_node.sh"
  [ -f "$clean_script" ] || die "clean_script_not_found: $clean_script"
  chmod +x "$clean_script" || true
  log "Running cleanup before install"
  if [ "$REMOVE_LEGACY_ROOT" -eq 1 ]; then
    bash "$clean_script" --remove-legacy-root
  else
    bash "$clean_script"
  fi
}

install_os_dependencies() {
  command -v apt-get >/dev/null 2>&1 || die "apt_get_not_found"
  export DEBIAN_FRONTEND=noninteractive
  log "Installing OS dependencies"
  apt-get update
  apt-get install -y curl wget jq ca-certificates nftables
}

node_major() {
  command -v node >/dev/null 2>&1 || { echo 0; return; }
  node -p 'Number(process.versions.node.split(".")[0])' 2>/dev/null || echo 0
}

install_nodejs_20_if_needed() {
  local major; major="$(node_major)"
  if [ "$major" -ge 20 ] 2>/dev/null; then
    log "Node.js major version is $major"
  else
    export DEBIAN_FRONTEND=noninteractive
    log "Installing Node.js 20"
    apt-get install -y ca-certificates curl gnupg
    mkdir -p /etc/apt/keyrings
    rm -f /etc/apt/keyrings/nodesource.gpg
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
      | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
    chmod 0644 /etc/apt/keyrings/nodesource.gpg
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" \
      > /etc/apt/sources.list.d/nodesource.list
    apt-get update
    apt-get install -y nodejs
  fi
  if [ ! -x /usr/bin/node ]; then
    local node_bin; node_bin="$(command -v node || true)"
    [ -n "$node_bin" ] || die "node_binary_not_found_after_install"
    ln -sf "$node_bin" /usr/bin/node
  fi
  local final_major
  final_major="$(/usr/bin/node -p 'Number(process.versions.node.split(".")[0])' 2>/dev/null || echo 0)"
  [ "$final_major" -ge 20 ] 2>/dev/null || die "nodejs_20_required"
}

copy_repo_to_opt() {
  mkdir -p "$NETRUN_HOME"
  local source_real; source_real="$(realpath "$SOURCE_DIR")"
  [ "$source_real" = "$NETRUN_HOME" ] && { log "Using existing repo at $NETRUN_HOME"; return 0; }
  log "Copying node runtime to $NETRUN_HOME"
  tar -C "$SOURCE_DIR" --exclude='./.git' -cf - . | tar -C "$NETRUN_HOME" -xpf -
}

install_runtime_files() {
  mkdir -p "$NETRUN_HOME" "$JOBS_ROOT" "$PROXY_ROOT" "$PROXY_ROOT/3proxy/bin"
  local bundled="$NETRUN_HOME/deploy/node/bin/3proxy"
  [ -f "$bundled" ] || die "missing_bundled_3proxy_binary: expected $bundled"
  install -m 0755 "$bundled" "$PROXY_ROOT/3proxy/bin/3proxy"
  chmod +x "$PROXY_ROOT/3proxy/bin/3proxy"
  chmod +x "$NETRUN_HOME/node_runtime/generator/proxyyy_automated.sh"
  chmod +x "$NETRUN_HOME/node_runtime/soft/generator/proxyyy_automated.sh"
  chmod +x "$NETRUN_HOME/scripts/"*.sh
}

# === CHANGE 1: kernel.pid_max + threads-max added ===
# Wave IPV6-ROTATION — all.forwarding=1 below is also what IPv6 egress
# rotation's proxy NDP relies on: rotated / per-connection addresses are
# proxy neighbour entries, not NIC addresses (an `ip address add|del` costs
# O(n) next to ~16k anchors: 1000 adds ≈ 35 s on a production node; 1000
# proxy entries ≈ 0.37 s), and the kernel answers for them only on a
# forwarding interface. The agent (egress.js) sets the rest itself at start —
# net.ipv6.conf.{all,<if>}.proxy_ndp=1, net.ipv6.neigh.<if>.proxy_delay=0 —
# writing only what differs, and keeps them in
# /etc/sysctl.d/99-netrun-egress.conf (rewritten whenever it differs; this
# script never writes that file). Its nft table drops forwarded packets to the
# node's /64, so forwarding=1 forwards nothing.
configure_sysctl() {
  log "Configuring sysctl (IPv6 forwarding + raised kernel pid/thread limits)"
  # nf_conntrack module is lazy-loaded by nftables; on a freshly-cleaned node
  # (clean_node.sh deletes nft tables) the /proc/sys/net/netfilter/* keys do
  # not exist yet, so `sysctl -p` exits non-zero and `set -e` kills the script.
  # Force-load conntrack so the keys are present, and tolerate sysctl warnings.
  modprobe nf_conntrack 2>/dev/null || true
  modprobe nf_conntrack_ipv6 2>/dev/null || true
  cat > "$SYSCTL_FILE" <<'EOF'
# === IPv6 forwarding ===
net.ipv6.ip_nonlocal_bind = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1

# === Process limits (v2: raised from 65536 default) ===
# Restore-3proxy spawns 4000+ procs at boot. Default pid_max=65536
# trips fork EAGAIN once active pids cross ~50k.
kernel.pid_max = 4194304
kernel.threads-max = 4194304

# === Connection tuning ===
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.ipv4.tcp_max_syn_backlog = 8192
net.core.somaxconn = 8192
# Wave CAPACITY-18K — ephemeral ports BELOW every listener. Proxy listeners
# use 8100-65535 (socks >= 18100, dual http = socks - 10000 >= 8100) and the
# agent :8085; 1024-8000 never overlaps them, so an outbound socket can never
# hold a port a (re)starting 3proxy/haproxy listener needs. The range is shared
# by IPv4 and IPv6 (there is no IPv6 knob). 3proxy binds each upstream socket
# to its -e<IPv6> with port 0 BEFORE connect (doconnect: bind(extsa6:0)), and
# bind-time port allocation is per source address — so every proxy gets its
# own 6977-port pool, far above its ceiling of 2 listeners x maxconn 200
# (TIME_WAIT left by node-side closes also holds a slot for 60 s: ~110 new
# upstream connections/s sustained per proxy). haproxy's loopback leg to
# 3proxy uses plain connect(), whose ports are reused per destination port.
# The one node-wide pool is IPv4 egress (bind 0.0.0.0:0), used only in the
# dualstack egress mode for IPv4-only targets.
net.ipv4.ip_local_port_range = 1024 8000
fs.file-max = 2097152

# === TCP/IP fingerprint normalization (Android-like) ===
# tcp_timestamps=1: Linux/Android default. =0 makes p0f read OS as Windows.
# tcp_mtu_probing=1: PLPMTUD — discovers PMTU dynamically; safer than fixed
# MSS-clamp (which produced MTU=1380 → p0f classified link as OpenVPN).
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_mtu_probing = 1

# === IPv6 multi-homed ===
net.ipv6.conf.all.accept_ra = 2
net.ipv6.conf.default.accept_ra = 2
EOF
  # === DAD/MLD off (second file, name 98- so node_followup_v2.sh — which
  # overwrites ONLY 99-netrun.conf — leaves it intact) ===
  cat > "$SYSCTL_IPV6_FILE" <<'EOF'
# NETRUN — DAD/MLD off. Тысячи IPv6 на интерфейсе → DAD/MLD overload
# (mld_ifc_work грузит CPU). DAD не нужен для наших управляемых unicast-адресов
# (контролируем /64 сами, коллизий нет). Без этого файла нода деградирует
# при раздувании пула до тысяч портов. Имя 98- (раньше 99-netrun.conf), чтобы
# node_followup_v2.sh (перезаписывает только 99-) его не затирал.
net.ipv6.conf.all.dad_transmits = 0
net.ipv6.conf.default.dad_transmits = 0
net.ipv6.conf.all.accept_dad = 0
net.ipv6.conf.default.accept_dad = 0
net.ipv6.mld_max_msf = 1
EOF
  # Strip any legacy tcp_timestamps line from /etc/sysctl.conf — old generator
  # wrote =0 there, which is processed AFTER sysctl.d and would override our =1.
  if [ -f /etc/sysctl.conf ]; then
    sed -i -E '/^[[:space:]]*net\.ipv4\.tcp_timestamps[[:space:]]*=/d' /etc/sysctl.conf || true
  fi
  # Tolerate "cannot stat" warnings (e.g. if a netfilter key still not exposed)
  sysctl --system >/dev/null 2>&1 || true
  sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || sysctl -p "$SYSCTL_FILE" || true
  sysctl -p "$SYSCTL_IPV6_FILE" >/dev/null 2>&1 || true
}

configure_file_limits() {
  log "Configuring file descriptor limits (1M open FDs)"
  cat > "$LIMITS_FILE" <<'EOF'
root soft nofile 1048576
root hard nofile 1048576
*    soft nofile 1048576
*    hard nofile 1048576
root soft nproc  unlimited
root hard nproc  unlimited
*    soft nproc  unlimited
*    hard nproc  unlimited
EOF
  if [ -d /etc/systemd/system.conf.d ]; then
    cat > /etc/systemd/system.conf.d/99-netrun-limits.conf <<'EOF'
[Manager]
DefaultLimitNOFILE=1048576
DefaultLimitNPROC=infinity
DefaultTasksMax=infinity
EOF
  fi
}

disable_ufw() {
  log "Removing UFW"
  if command -v ufw >/dev/null 2>&1; then
    ufw --force disable 2>/dev/null || true
    apt-get purge -y ufw 2>/dev/null || true
  fi
  systemctl mask ufw 2>/dev/null || true
}

configure_colored_prompt() {
  log "Setting up coloured root prompt"
  local bashrc="/root/.bashrc"
  if [ -f "$bashrc" ] && grep -q "NETRUN colored prompt" "$bashrc"; then return 0; fi
  cat >> "$bashrc" <<'EOF'

# === NETRUN colored prompt ===
export PS1='\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
EOF
}

pin_dns_resolvers() {
  # Install-time resolver: fast public DNS so apt/git work during setup.
  # configure_unbound() re-points resolv.conf to the local recursive resolver
  # (127.0.0.1) at the end — that's the production state (see below).
  log "Pinning /etc/resolv.conf (install-time upstreams)"
  chattr -i "$RESOLV_CONF" 2>/dev/null || true
  cat > "$RESOLV_CONF" <<'EOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 2606:4700:4700::1111
nameserver 2001:4860:4860::8888
options edns0 trust-ad timeout:2 attempts:1
EOF
  chattr +i "$RESOLV_CONF" 2>/dev/null || true
}

# Local recursive resolver so proxy DNS egresses from THIS node (resolver IP ==
# exit IP, geo/ASN-consistent) instead of leaking to Cloudflare/Google.
# NOTE: this 3proxy build IGNORES the `nserver` directive and resolves via
# /etc/resolv.conf — so the real lever is resolv.conf, not the cfg nserver lines.
configure_unbound() {
  log "Installing local recursive resolver (unbound)"
  DEBIAN_FRONTEND=noninteractive apt-get install -y unbound >/dev/null 2>&1 \
    || { apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y unbound >/dev/null 2>&1; }
  mkdir -p /etc/unbound/unbound.conf.d
  cat > /etc/unbound/unbound.conf.d/netrun.conf <<'EOF'
server:
    interface: 127.0.0.1
    interface: ::1
    access-control: 127.0.0.0/8 allow
    access-control: ::1 allow
    do-ip6: yes
    num-threads: 4
    # Wave CAPACITY-18K — 32m/64m (was 128m/256m, up to ~450 MB RSS): the cache
    # only serves this node's own proxies, and the RAM goes to proxies instead.
    msg-cache-size: 32m
    rrset-cache-size: 64m
    cache-min-ttl: 60
    prefetch: yes
    qname-minimisation: yes
    hide-identity: yes
    hide-version: yes
EOF
  if ! unbound-checkconf >/dev/null 2>&1; then
    warn "unbound-checkconf failed — keeping upstream resolv.conf (no local resolver)"
    return 0
  fi
  systemctl enable unbound >/dev/null 2>&1 || true
  systemctl restart unbound || true
  sleep 1
  if ! systemctl is-active --quiet unbound; then
    warn "unbound not active — keeping upstream resolv.conf"
    return 0
  fi
  # Re-point resolv.conf to the local resolver. 1.1.1.1 stays as LAST-RESORT
  # fallback so the node never loses DNS if unbound dies (degraded > broken).
  chattr -i "$RESOLV_CONF" 2>/dev/null || true
  cat > "$RESOLV_CONF" <<'EOF'
nameserver 127.0.0.1
nameserver ::1
nameserver 1.1.1.1
options edns0 trust-ad timeout:2 attempts:1
EOF
  chattr +i "$RESOLV_CONF" 2>/dev/null || true
  log "unbound active; resolv.conf -> 127.0.0.1 (recursion egress = node IP)"
}

configure_nftables() {
  log "Configuring nftables"
  # Fresh Ubuntu 24.04 (Vultr image) ships UFW whose rules use xtables-compat
  # (`xt match "icmp6"`). After `apt purge ufw` those rules linger in the live
  # ruleset; `nft list ruleset > /etc/nftables.conf` then writes xt-compat
  # expressions that a pure `nft -f` CANNOT parse → `systemctl start nftables`
  # crashes → set -e kills the installer (incident 2026-05-22, Tokyo fresh test).
  # Flush the inherited ruleset first so we install ONLY our accounting tables.
  nft flush ruleset 2>/dev/null || true
  systemctl enable nftables >/dev/null 2>&1 || true
  nft add table inet proxy_normalization 2>/dev/null || true
  nft add chain inet proxy_normalization output '{ type filter hook output priority -150; policy accept; }' 2>/dev/null || true
  nft add chain inet proxy_normalization postrouting '{ type filter hook postrouting priority -150; policy accept; }' 2>/dev/null || true
  nft add table inet proxy_accounting 2>/dev/null || true
  nft add chain inet proxy_accounting input '{ type filter hook input priority 0; policy accept; }' 2>/dev/null || true
  nft add chain inet proxy_accounting output '{ type filter hook output priority 0; policy accept; }' 2>/dev/null || true
  # MSS clamp 1460 (NOT 1340). Previous 1340 produced effective MTU=1380 which
  # p0f classified as OpenVPN UDP link. 1460 = standard Ethernet MSS for MTU
  # 1500 (Android default). PMTU edge cases are handled by tcp_mtu_probing=1
  # in configure_sysctl above. (Incident 2026-05-23: TCP/IP fingerprint = Win+VPN)
  nft add rule inet proxy_normalization output meta l4proto tcp tcp flags syn tcp option maxseg size set 1460 2>/dev/null || true
  # Now ruleset has ONLY our tables (no xt-compat) → valid for nft -f on boot
  nft list ruleset > /etc/nftables.conf
  systemctl restart nftables 2>/dev/null || systemctl start nftables 2>/dev/null || true
}

# Wave IPV6-ROTATION — `nft list ruleset > /etc/nftables.conf` (here, the
# generator, deprovision, netrun-harden, netrun-https) also saves the agent's
# table ip6 netrun_egress, whose rotated / pool addresses (proxy-NDP entries)
# are gone after a reboot. This drop-in deletes it right after nftables.service loads the file:
# proxies leave from their anchors until the agent rebuilds the table from
# egress_state.json. The agent writes the same file at start (egress.js
# nftDropinText; egress.test.js keeps the texts equal).
install_nftables_egress_dropin() {
  local nft_bin
  nft_bin="$(command -v nft || echo /usr/sbin/nft)"
  log "Installing nftables.service drop-in (boot: drop a saved table ip6 netrun_egress)"
  mkdir -p /etc/systemd/system/nftables.service.d
  cat > /etc/systemd/system/nftables.service.d/netrun-egress.conf <<EOF
# NETRUN IPv6 egress rotation (node-agent egress.js; install_node_v2.sh, node_followup_v2.sh).
# A saved ruleset may hold table ip6 netrun_egress, whose addresses are gone after a
# reboot: drop it after the boot load. Proxies leave from their anchors until the agent
# rebuilds the table from egress_state.json.
[Service]
ExecStartPost=-${nft_bin} delete table ip6 netrun_egress
EOF
  systemctl daemon-reload
}

write_bootstrap_marker() {
  log "Writing bootstrap marker"
  cat > "$PROXY_ROOT/.netrun_bootstrap.json" <<EOF
{
  "bootstrapped_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "proxy_root": "$PROXY_ROOT",
  "jobs_root": "$JOBS_ROOT",
  "bundled_3proxy": "$NETRUN_HOME/deploy/node/bin/3proxy",
  "runtime_3proxy": "$PROXY_ROOT/3proxy/bin/3proxy",
  "installer": "install_node_v2.sh"
}
EOF
}

# === Wave EGRESS-STATE-SEED: a fresh node MUST ship an egress_mode.state, else
# the agent falls back to its env default (NODE_AGENT_REQUIRED_IPV6_POLICY,
# i.e. strict_dual_stack) while the orchestrator's production profile sends
# ipv6_only → policy mismatch → EVERY /generate fails with
# {"error":"ipv6_only_required"} and the node never mints a single proxy. This
# was the silent root cause of fresh / re-imaged nodes not generating. Seed
# ipv6_only (the production egress policy). Preserve a non-empty existing file —
# an admin may have intentionally selected a different egress mode (e.g. a
# dualstack pool); we only fill the gap, never clobber a deliberate choice. ===
seed_egress_mode_state() {
  local state_file="$PROXY_ROOT/egress_mode.state"
  if [ -s "$state_file" ]; then
    log "egress_mode.state present (= $(cat "$state_file" 2>/dev/null)) — keeping"
  else
    printf 'ipv6_only' > "$state_file"
    log "Seeded egress_mode.state=ipv6_only (fresh-node generation default)"
  fi
}

ensure_legacy_root_proxyserver_symlink() {
  log "Linking /root/proxyserver -> $PROXY_ROOT (legacy script compat)"
  if [ -e /root/proxyserver ] && [ ! -L /root/proxyserver ]; then
    log "WARNING: /root/proxyserver exists as directory, removing first"
    rm -rf /root/proxyserver
  fi
  ln -sfn "$PROXY_ROOT" /root/proxyserver
}

# === CHANGE 4: patch node-agent.service with raised limits ===
install_systemd_service() {
  local template="$NETRUN_HOME/deploy/node/netrun-node-agent.service.template"
  [ -f "$template" ] || die "service_template_not_found: $template"
  log "Installing systemd service (v2: with drop-in raised limits)"
  install -m 0644 "$template" "$SERVICE_FILE"

  # v2 fix: use drop-in override instead of sed-injecting into the unit.
  # Earlier sed approach used `\n` in the replacement string, which GNU sed
  # interprets as literal `\n` (not a newline) unless under `s///`. The result
  # was a single garbled line that didn't set TasksMax. Drop-ins are also the
  # systemd-recommended way to override unit settings.
  mkdir -p "${SERVICE_FILE}.d"
  cat > "${SERVICE_FILE}.d/99-netrun-limits.conf" <<'EOF'
[Service]
TasksMax=infinity
LimitNOFILE=1048576
LimitNPROC=infinity
# KillMode=process: don't tear down agent-spawned 3proxy on agent restart /
# code-deploy (default control-group kills the whole cgroup → partial proxy
# outage until the restore unit relaunches them). Restore-unit 3proxy already
# survive; this makes the agent restart non-destructive for generated ones too.
KillMode=process
EOF

  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" >/dev/null
  systemctl restart "$SERVICE_NAME"
}

# === CHANGES 2 + 3: bounded parallel restore + raised service limits ===
install_3proxy_restore_unit() {
  log "Installing 3proxy auto-restore systemd unit (v2: bounded parallel)"
  mkdir -p "$(dirname "$RESTORE_SCRIPT")"
  cat > "$RESTORE_SCRIPT" <<'RESTORESH'
#!/usr/bin/env bash
# v2: bounded parallel via xargs -P 4 + setsid detach.
# v1 was `for cfg; do 3proxy & done` — that hit fork EAGAIN with 4000+ cfgs.
set -u

PROXY_BIN="/opt/netrun/proxyserver/3proxy/bin/3proxy"
PROXY_CFG_DIR="/opt/netrun/proxyserver/3proxy"
LOG_TAG="netrun-3proxy-restore"
PARALLEL=4
SLEEP_BETWEEN=0.3

if [ ! -x "$PROXY_BIN" ]; then
  logger -t "$LOG_TAG" "skip: 3proxy binary not found at $PROXY_BIN"
  exit 0
fi

# Crank our own FD/proc limits
ulimit -n 1048576 2>/dev/null || true
ulimit -u unlimited 2>/dev/null || true

# Snapshot what's already listening — one ss call, not per-port
listening_ports=$(ss -tln 2>/dev/null | awk '{print $4}' | awk -F: '{print $NF}' | sort -u)

# Build worklist of cfgs whose base-port isn't yet listening
shopt -s nullglob
worklist=$(mktemp)
trap 'rm -f $worklist' EXIT
for cfg in "$PROXY_CFG_DIR"/3proxy_*.cfg; do
  [ -f "$cfg" ] || continue
  port=$(basename "$cfg" .cfg | sed 's/3proxy_//')
  if ! echo "$listening_ports" | grep -qx "$port"; then
    printf '%s\n' "$cfg" >> "$worklist"
  fi
done

total=$(wc -l < "$worklist")
logger -t "$LOG_TAG" "v2 starting: total=$total, parallel=$PARALLEL"

# Bounded parallel spawn with setsid (detach from systemd cgroup so each
# 3proxy lives in its own session.scope — won't deplete service TasksMax)
< "$worklist" xargs -n 1 -P "$PARALLEL" -I {} bash -c '
  setsid "'"$PROXY_BIN"'" "{}" </dev/null >/dev/null 2>&1 & disown 2>/dev/null || true
  sleep '"$SLEEP_BETWEEN"'
' 2>/dev/null || true

sleep 5
active=$(ss -tln 2>/dev/null | grep -cE ':[1-9][0-9]{3,4} ' || echo 0)
logger -t "$LOG_TAG" "v2 done: queued=$total, total_listening_after=$active"
exit 0
RESTORESH
  chmod +x "$RESTORE_SCRIPT"

  cat > "$RESTORE_SERVICE_FILE" <<EOF
[Unit]
Description=NETRUN — restore all 3proxy instances from saved cfg files (v2)
After=network-online.target ${SERVICE_NAME}.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${RESTORE_SCRIPT}
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal
TimeoutStartSec=900
TasksMax=infinity
LimitNOFILE=1048576
LimitNPROC=infinity

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "$RESTORE_SERVICE_NAME" >/dev/null
}

install_doctor_script() {
  log "Installing netrun-doctor.sh"
  cat > "$DOCTOR_SCRIPT" <<'DOCTOR'
#!/usr/bin/env bash
set -u
c() { echo -e "\n\033[1;36m=== $* ===\033[0m"; }
ok() { echo -e "  \033[32m✓\033[0m $*"; }
warn() { echo -e "  \033[33m⚠\033[0m $*"; }
fail() { echo -e "  \033[31m✗\033[0m $*"; }

c "1. System"
echo "  hostname: $(hostname)"
echo "  uptime:   $(uptime -p)"
echo "  kernel:   $(uname -r)"

c "2. Kernel limits (v2 expects raised values)"
for key in kernel.pid_max kernel.threads-max net.netfilter.nf_conntrack_max fs.file-max; do
  val=$(sysctl -n "$key" 2>/dev/null || echo "?")
  printf "  %-32s = %s\n" "$key" "$val"
done

c "3. DNS"
if lsattr /etc/resolv.conf 2>/dev/null | grep -q 'i'; then ok "resolv.conf immutable"; else warn "resolv.conf NOT immutable"; fi
if timeout 3 curl -fsSL -o /dev/null https://1.1.1.1 2>/dev/null; then ok "outbound HTTPS works"; else fail "outbound HTTPS fails"; fi

c "4. UFW"
if command -v ufw >/dev/null 2>&1; then fail "ufw still installed"; else ok "ufw absent"; fi

c "5. node-agent"
if systemctl is-active --quiet netrun-node-agent; then
  ok "netrun-node-agent active"
  curl -m 3 -fsS http://127.0.0.1:8085/health 2>/dev/null | head -c 200; echo
else
  fail "netrun-node-agent NOT active"
fi

c "6. Restore unit"
if systemctl is-enabled --quiet netrun-3proxy-restore 2>/dev/null; then ok "restore unit enabled"; else warn "restore unit NOT enabled"; fi

c "7. 3proxy state"
cfg_count=$(ls /opt/netrun/proxyserver/3proxy/3proxy_*.cfg 2>/dev/null | wc -l)
proc_count=$(pgrep -c 3proxy 2>/dev/null || echo 0)
listening=$(ss -Hltn 2>/dev/null | awk '{ p = $4; sub(/.*:/, "", p); if (p + 0 >= 8100) n++ } END { print n + 0 }')
echo "  cfg files / procs / listeners: $cfg_count / $proc_count / $listening"

c "8. Resources"
echo "  load: $(cut -d' ' -f1-3 /proc/loadavg)"
echo "  mem:  $(free -h | awk '/^Mem:/ {print $3"/"$2}')"
echo "  disk: $(df -h / | awk 'NR==2 {print $5" used"}')"
DOCTOR
  chmod +x "$DOCTOR_SCRIPT"
}

# Trend monitor — logs node metrics every 5 min to /var/log/netrun-trend.log.
# Canary for the IPv6/MLD leak the 98-netrun-ipv6.conf sysctl guards against.
# Was a manual step (NODE_SETUP_RUNBOOK.md §5); now auto-installed by v2.
install_trend_monitor() {
  log "Installing trend_monitor.sh + cron (*/5)"
  mkdir -p /opt/netrun/scripts
  cat > /opt/netrun/scripts/trend_monitor.sh <<'TREND'
#!/usr/bin/env bash
LOG=/var/log/netrun-trend.log
ts=$(date '+%Y-%m-%d %H:%M:%S')
threads=$(ls -d /proc/*/task/* 2>/dev/null | wc -l)
proc3=$(pgrep -c 3proxy)
listening=$(ss -Hltn 2>/dev/null | awk '{ p = $4; sub(/.*:/, "", p); if (p + 0 >= 8100) n++ } END { print n + 0 }')
estab=$(ss -tn state established 2>/dev/null | wc -l)
ipv6cnt=$(ip -6 addr show scope global 2>/dev/null | grep -c 'inet6')
mem=$(free -m | awk '/^Mem:/ {print $3"/"$2}')
conntrack=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0)
cronpids=$(cat /sys/fs/cgroup/system.slice/cron.service/pids.current 2>/dev/null || echo 0)
fd=$(awk '{print $1}' /proc/sys/fs/file-nr)
load=$(cut -d' ' -f1 /proc/loadavg)
echo "$ts threads=$threads 3proxy=$proc3 listen=$listening estab=$estab ipv6=$ipv6cnt mem=${mem}MB conntrack=$conntrack cronpids=$cronpids fd=$fd load=$load" >> $LOG
TREND
  chmod +x /opt/netrun/scripts/trend_monitor.sh

  # cron.d (NOT root crontab — the generator owns its @reboot proxy-startup
  # entries there; we must not touch them). cron.d format has a user field.
  cat > /etc/cron.d/netrun-trend-monitor <<'EOF'
# NETRUN trend monitor — метрики ноды каждые 5 мин в /var/log/netrun-trend.log
*/5 * * * * root /opt/netrun/scripts/trend_monitor.sh
EOF
  chmod 0644 /etc/cron.d/netrun-trend-monitor
}

# Re-add proxy egress IPv6 (-e addrs from 3proxy configs) on boot. The kernel
# does NOT persist the thousands of /64 addresses across reboots; without them
# 3proxy binds a missing source address and egress fails ("proxy invalid").
# DAD/MLD off (98-netrun-ipv6.conf, set by configure_sysctl earlier) makes
# re-adding thousands of addresses cheap (no MLD-overload).
# Wave CAPACITY-18K — the script itself lives in the repo
# (deploy/node/netrun-ipv6-restore.sh): ONE `ip -batch` with `nodad` instead of
# one `ip` fork per address (18k forks at boot), installed under scripts/ so a
# later code deploy of the repo never rewrites an existing node's boot script.
install_ipv6_restore_unit() {
  log "Installing netrun-ipv6-restore (re-add proxy IPv6 addrs after boot)"
  mkdir -p /opt/netrun/scripts
  install -m 0755 "$NETRUN_HOME/deploy/node/netrun-ipv6-restore.sh" /opt/netrun/scripts/netrun-ipv6-restore.sh
  cat > /etc/systemd/system/netrun-ipv6-restore.service <<'EOF'
[Unit]
Description=NETRUN - re-add proxy IPv6 /64 addresses (egress) after boot
After=network-online.target
Wants=network-online.target
Before=netrun-3proxy-restore.service

[Service]
Type=oneshot
ExecStart=/opt/netrun/scripts/netrun-ipv6-restore.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable netrun-ipv6-restore.service >/dev/null 2>&1 || true
}

verify_health() {
  log "Waiting for /health"
  local health=""
  for _ in $(seq 1 30); do
    health="$(curl -fsS "$HEALTH_URL" 2>/dev/null || true)"
    if [ -n "$health" ] && printf '%s' "$health" | jq -e '.success == true and .status == "ready"' >/dev/null 2>&1; then
      printf '%s\n' "$health" | jq .
      return 0
    fi
    sleep 1
  done
  systemctl status "$SERVICE_NAME" --no-pager || true
  journalctl -u "$SERVICE_NAME" -n 100 --no-pager || true
  die "health_check_failed"
}

main() {
  ensure_bundled_3proxy "$SOURCE_DIR"
  run_clean_if_requested
  ensure_bundled_3proxy "$SOURCE_DIR"

  disable_ufw
  pin_dns_resolvers
  configure_file_limits
  configure_colored_prompt

  install_os_dependencies
  configure_unbound
  install_nodejs_20_if_needed
  copy_repo_to_opt
  install_runtime_files
  configure_sysctl
  configure_nftables
  install_nftables_egress_dropin
  write_bootstrap_marker
  seed_egress_mode_state
  ensure_legacy_root_proxyserver_symlink
  install_systemd_service

  install_3proxy_restore_unit
  install_doctor_script
  install_trend_monitor
  install_ipv6_restore_unit

  verify_health

  log "Install v2 complete"
  log "NETRUN_HOME=$NETRUN_HOME"
  log "SERVICE=$SERVICE_NAME (active)"
  log "RESTORE_SERVICE=$RESTORE_SERVICE_NAME (enabled)"
  log "DOCTOR=$DOCTOR_SCRIPT"
  log "Next: bash node_followup_v2.sh to install non-rebooting watchdog"
}

main "$@"
