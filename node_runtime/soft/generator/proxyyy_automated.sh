#!/bin/bash

# AUTOMATED IPv6 Proxy Server Installer (Non-Interactive)
# Based on proxyyy.sh but adapted for API usage

# Script must be running from root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Wave FLEET-HEALTH (SPD-05) — a node setting: the environment wins, then
# ${NETRUN_ENV_FILE:-/etc/netrun/netrun.env} (KEY=VALUE lines), then the default.
function netrun_setting() {
  local key="$1" def="$2" v="${!1:-}" f="${NETRUN_ENV_FILE:-/etc/netrun/netrun.env}"
  if [ -z "$v" ] && [ -r "$f" ]; then
    v="$(awk -v k="$key" '{ sub(/^[ \t]+/, "") } index($0, k "=") == 1 { v = substr($0, length(k) + 2) } END { gsub(/^["\047 \t]+|["\047 \t\r]+$/, "", v); print v }' "$f")"
  fi
  printf '%s' "${v:-$def}"
}

# Program help info for users
function usage() { echo "Usage: $0 [-s | --subnet <16|32|48|64|80|96|112> proxy subnet (default 64)] 
                          [-c | --proxy-count <number> count of proxies] 
                          [-u | --username <string> proxy auth username] 
                          [-p | --password <string> proxy password]
                          [--random <bool> generate random username/password for each IPv4 backconnect proxy instead of predefined (default false)] 
                          [-t | --proxies-type <http|socks5|dual> result proxies type (default socks5; 'dual' = socks5 + paired http on port-10000)]
                          [-r | --rotating-interval <0-59> proxies external address rotating time in minutes (default 0, disabled)]
                          [--start-port <8100-65535> start port for backconnect ipv4 (default 30000; every listener port,
                                incl. the dual http = start - 10000, must be >= NETRUN_MIN_LISTEN_PORT, default 8100)]
                          [-l | --localhost <bool> allow connections only for localhost (backconnect on 127.0.0.1)]
                          [-f | --backconnect-proxies-file <string> path to file, in which backconnect proxies list will be written
                                when proxies start working (default \`~/proxyserver/backconnect_proxies.list\`)]    
                          [-d | --disable-inet6-ifaces-check <bool> disable /etc/network/interfaces configuration check & exit when error
                                use only if configuration handled by cloud-init or something like this (for example, on Vultr servers)]                                                      
                          [-m | --ipv6-mask <string> constant ipv6 address mask, to which the rotated part is added (or gateway)
                                use only if the gateway is different from the subnet address]
                          [-i | --interface <string> full name of ethernet interface, on which IPv6 subnet was allocated
                                automatically parsed by default, use ONLY if you have non-standard/additional interfaces on your server]
                          [-b | --backconnect-ip <string> server IPv4 backconnect address for proxies
                                automatically parsed by default, use ONLY if you have non-standard ip allocation on your server]
                          [--allowed-hosts <string> allowed hosts or IPs (3proxy format), for example \"google.com,*.google.com,*.gstatic.com\"
                                if at least one host is allowed, the rest are banned by default]
                          [--denied-hosts <string> banned hosts or IP addresses in quotes (3proxy format)]
                          [--dns-servers <ip1,ip2> explicit upstream DNS resolvers override (default: the node's unbound, 127.0.0.1 / ::1)]
                          [--maxconn <number> 3proxy maxconn for this instance; the listen backlog is maxconn/16+1
                                (default \$NETRUN_3PROXY_MAXCONN, else /etc/netrun/netrun.env, else 512)]
                          [--ipv6-policy <strict_dual_stack|ipv6_required|ipv6_only> egress family policy (default strict_dual_stack)]
                          [--dns-country, --network-profile, --tcp-timestamps-mode, --self-check-samples <value>,
                           --skip-self-check: accepted and IGNORED (audit CLN-03/CLN-04: the TCP stack is set only by
                           install_node_v2.sh / deploy/node/99-zz-netrun-tcp.conf, DNS is the local unbound, and the
                           post-start self-check never ran under the agent)]
                          [--port-ipv6-map-file <string> path to CSV file with port-to-IPv6 mapping
                                (default \`~/proxyserver/port_ipv6_map_<start_port>.csv\`)]
                          [--bootstrap-only run one-time node bootstrap and exit]
                          [--runtime-only run proxy generation only (no bootstrap side-effects)]
                          [--verify-bootstrap check bootstrap prerequisites and exit]
                          [--uninstall <bool> disable active proxies, uninstall server and clear all metadata]
                          [--info <bool> print info about running proxy server]
                          " 1>&2; exit 1; }

options=$(getopt -o ldhs:c:u:p:t:r:m:f:i:b: --long help,localhost,disable-inet6-ifaces-check,random,uninstall,info,bootstrap-only,runtime-only,verify-bootstrap,skip-self-check,self-check-samples:,port-ipv6-map-file:,dns-country:,dns-servers:,network-profile:,tcp-timestamps-mode:,maxconn:,ipv6-policy:,subnet:,proxy-count:,username:,password:,proxies-type:,rotating-interval:,ipv6-mask:,interface:,start-port:,backconnect-proxies-file:,backconnect-ip:,allowed-hosts:,denied-hosts: -- "$@")

if [ $? != 0 ]; then echo "Error: no arguments provided. Terminating..." >&2; usage; fi;

eval set -- "$options"

# Set default values for optional arguments
subnet=64
proxies_type="socks5"
start_port=30000
rotating_interval=0
use_localhost=false
use_random_auth=false
uninstall=false
print_info=false
inet6_network_interfaces_configuration_check=true
backconnect_proxies_file="default"
port_ipv6_map_file="default"
interface_name="$(ip -br l | awk '$1 !~ "lo|vir|wl|@NONE" { print $1 }' | awk 'NR==1')"
script_log_file="/var/tmp/ipv6-proxy-server-logs.log"
backconnect_ipv4=""
mode_flag="-64"  # Universal mode by default
ip_preference_mode="compat_ipv6_first"
dns_servers_override=""
ipv6_policy="strict_dual_stack"
# Speed audit — 3proxy 0.9.3 has NO listen-backlog option: every service calls
# listen(sock, (maxconn >> 4) + 1) (mainfunc 0xc408-0xc421 in the bundled
# binary), and net.core.somaxconn only caps a LARGER request. maxconn 200 gave
# each proxy port an accept queue of 13 (a burst of ~14 parallel connects ->
# SYN drops, 1/3/7 s retransmits); 512 gives 33 and lets one proxy carry 512
# concurrent connections instead of 200 (at the cap the listener stops
# accepting). RAM is spent per ACTIVE connection only, so the per-port cap is
# not a node budget. Applies to NEW batches (the cfg header); the setting
# NETRUN_3PROXY_MAXCONN (environment, else /etc/netrun/netrun.env) or
# --maxconn overrides it; 200 restores the old value.
proxy_maxconn="$(netrun_setting NETRUN_3PROXY_MAXCONN 512)"
proxy_count=1
# Wave CAPACITY-18K — lowest port a proxy listener may bind (see check_startup_parameters).
min_listen_port="${NETRUN_MIN_LISTEN_PORT:-8100}"
dns_selected_servers_csv="127.0.0.1,::1"
dns_selection_strategy="local_unbound"
dns_nserver_lines=$'  nserver 127.0.0.1\n  nserver ::1'
bootstrap_only=false
runtime_only=false
verify_bootstrap=false
bootstrap_side_effects_allowed=true

while true; do
  case "$1" in
    -h | --help ) usage; shift ;;
    -s | --subnet ) subnet="$2"; shift 2 ;;
    -c | --proxy-count ) proxy_count="$2"; shift 2 ;;
    -u | --username ) user="$2"; shift 2 ;;
    -p | --password ) password="$2"; shift 2 ;;
    -t | --proxies-type ) proxies_type="$2"; shift 2 ;;
    -r | --rotating-interval ) rotating_interval="$2"; shift 2 ;;
    -m | --ipv6-mask ) subnet_mask="$2"; shift 2 ;;
    -b | --backconnect-ip ) backconnect_ipv4="$2"; shift 2 ;;
    -f | --backconnect_proxies_file | --backconnect-proxies-file ) backconnect_proxies_file="$2"; shift 2 ;;
    -i | --interface ) interface_name="$2"; shift 2 ;;
    -l | --localhost ) use_localhost=true; shift ;;
    -d | --disable-inet6-ifaces-check ) inet6_network_interfaces_configuration_check=false; shift ;;
    --allowed-hosts ) allowed_hosts="$2"; shift 2 ;;
    --denied-hosts ) denied_hosts="$2"; shift 2 ;;
    --dns-servers ) dns_servers_override="$2"; shift 2 ;;
    --ipv6-policy ) ipv6_policy="$2"; shift 2 ;;
    --maxconn ) proxy_maxconn="$2"; shift 2 ;;
    # Audit CLN-03 — accepted and ignored for one release (the agent and older
    # orchestrators still pass some of them): they changed nothing on the wire.
    --dns-country | --network-profile | --tcp-timestamps-mode | --self-check-samples ) shift 2 ;;
    --skip-self-check ) shift ;;
    --port-ipv6-map-file ) port_ipv6_map_file="$2"; shift 2 ;;
    --bootstrap-only ) bootstrap_only=true; shift ;;
    --runtime-only ) runtime_only=true; shift ;;
    --verify-bootstrap ) verify_bootstrap=true; shift ;;
    --uninstall ) uninstall=true; shift ;;
    --info ) print_info=true; shift ;;
    --start-port ) start_port="$2"; shift 2 ;;
    --random ) use_random_auth=true; shift ;;
    -- ) shift; break ;;
    * ) break ;;
  esac
done

if [ "$bootstrap_only" = true ] && [ "$runtime_only" = true ]; then
  echo "Error: --bootstrap-only and --runtime-only cannot be used together" 1>&2
  exit 1
fi;

function log_err() {
  echo $1 1>&2;
  echo -e "$1\n" &>> $script_log_file;
}

function log_err_and_exit() {
  log_err "$1";
  exit 1;
}

function log_err_print_usage_and_exit() {
  log_err "$1";
  usage;
}

function is_valid_ip() {
  if [[ "$1" =~ ^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$ ]]; then return 0; else return 1; fi;
}

function looks_like_ipv6() {
  if [[ "$1" == *:* ]]; then return 0; else return 1; fi;
}

function is_auth_used() {
  if [ -z $user ] && [ -z $password ] && [ $use_random_auth = false ]; then false; return; else true; return; fi;
}

function check_startup_parameters() {
  re='^[0-9]+$'
  if ! [[ $proxy_count =~ $re ]]; then
    log_err_print_usage_and_exit "Error: Argument -c (proxy count) must be a positive integer number";
  fi;

  if ([ -z $user ] || [ -z $password ]) && is_auth_used && [ $use_random_auth = false ]; then
    log_err_print_usage_and_exit "Error: user and password for proxy with auth is required (specify both '--username' and '--password' startup parameters)";
  fi;

  if ([[ -n $user ]] || [[ -n $password ]]) && [ $use_random_auth = true ]; then
    log_err_print_usage_and_exit "Error: don't provide user or password as arguments, if '--random' flag is set.";
  fi;

  # Wave HTTP.A — 'dual' adds an http listener alongside socks5 on a
  # paired port (http = socks - 10000) for every IP. 'http'/'socks5'
  # single modes are unchanged (default socks5).
  if [ $proxies_type != "http" ] && [ $proxies_type != "socks5" ] && [ $proxies_type != "dual" ]; then
    log_err_print_usage_and_exit "Error: invalid value of '-t' (proxy type) parameter (http|socks5|dual)";
  fi;

  # Wave CAPACITY-18K — one listener floor for every mode (replaces the old
  # dual "start >= 15000 -> http >= 5000" rule and the generic ">= 5000"). Every
  # port this batch binds — socks/http, plus the dual http = socks - 10000 —
  # must be >= $min_listen_port (default 8100, env NETRUN_MIN_LISTEN_PORT).
  # Below it live the node's own services (node-agent :8085) and, on nodes
  # installed with the capacity tuning, the ephemeral range
  # (ip_local_port_range 1024-8000) whose outbound sockets would race a
  # listener for its port. Dual therefore needs start >= 18100: socks
  # 18100-65535 + http 8100-55535 hold up to 27 436 disjoint pairs on one IPv4.
  if ! [[ $min_listen_port =~ $re ]] || [ "$min_listen_port" -lt 1024 ]; then
    log_err_print_usage_and_exit "Error: NETRUN_MIN_LISTEN_PORT must be an integer >= 1024 (got '$min_listen_port')";
  fi;
  if ! [[ $start_port =~ $re ]]; then
    log_err_print_usage_and_exit "Error: '--start-port' must be a positive integer number";
  fi;
  local lowest_listen_port=$start_port
  if [ "$proxies_type" = "dual" ]; then lowest_listen_port=$((start_port - 10000)); fi
  if [ "$lowest_listen_port" -lt "$min_listen_port" ]; then
    if [ "$proxies_type" = "dual" ]; then
      log_err_print_usage_and_exit "Error: for '--proxies-type dual' '--start-port' must be >= $((min_listen_port + 10000)) (http port = socks port - 10000 must stay >= $min_listen_port)";
    fi;
    log_err_print_usage_and_exit "Error: '--start-port' must be >= $min_listen_port (lowest port a proxy listener may bind)";
  fi;
  # Dual: the socks range [start, start+count) and its http range shifted by
  # -10000 overlap once count > 10000 — the batch would collide with itself.
  if [ "$proxies_type" = "dual" ] && [ "$proxy_count" -gt 10000 ]; then
    log_err_print_usage_and_exit "Error: for '--proxies-type dual' '--proxy-count' must be <= 10000 (socks and paired http ranges would overlap)";
  fi;

  if [ "$ipv6_policy" != "strict_dual_stack" ] && [ "$ipv6_policy" != "ipv6_required" ] && [ "$ipv6_policy" != "ipv6_only" ]; then
    log_err_print_usage_and_exit "Error: '--ipv6-policy' must be one of: strict_dual_stack, ipv6_required, ipv6_only";
  fi;

  if [ "$ipv6_policy" = "ipv6_only" ]; then
    mode_flag="-6"
    ip_preference_mode="strict_ipv6_only"
  else
    mode_flag="-64"
    ip_preference_mode="compat_ipv6_first"
  fi;

  if [ $(expr $subnet % 4) != 0 ]; then
    log_err_print_usage_and_exit "Error: invalid value of '-s' (subnet) parameter, must be divisible by 4";
  fi;

  if [ $rotating_interval -lt 0 ] || [ $rotating_interval -gt 59 ]; then
    log_err_print_usage_and_exit "Error: invalid value of '-r' (proxy external ip rotating interval) parameter";
  fi;

  if [ $start_port -lt $min_listen_port ] || (($start_port + $proxy_count > 65536)); then
    log_err_print_usage_and_exit "Wrong '--start-port' parameter value, it must be at least $min_listen_port and '--start-port' + '--proxy-count' must be lower than 65536";
  fi;

  if [ ! -z $backconnect_ipv4 ]; then
    if ! is_valid_ip $backconnect_ipv4; then
      log_err_and_exit "Error: ip provided in 'backconnect-ip' argument is invalid. Provide valid IP or don't use this argument"
    fi;
  fi;

  if [ -n "$allowed_hosts" ] && [ -n "$denied_hosts" ]; then
    log_err_print_usage_and_exit "Error: if '--allow-hosts' is specified, you cannot use '--deny-hosts'";
  fi;

  if ! [[ $proxy_maxconn =~ $re ]]; then
    log_err_print_usage_and_exit "Error: '--maxconn' must be a positive integer number";
  fi;
  if [ "$proxy_maxconn" -lt 1 ]; then
    log_err_print_usage_and_exit "Error: '--maxconn' must be >= 1";
  fi;

  if cat /sys/class/net/$interface_name/operstate 2>&1 | grep -q "No such file or directory"; then
    log_err_print_usage_and_exit "Incorrect ethernet interface name \"$interface_name\", provide correct name using parameter '--interface'";
  fi;
}

bash_location="$(which bash)"
cd ~
user_home_dir="$(pwd)"
proxy_dir="$user_home_dir/proxyserver"
bootstrap_marker_file="$proxy_dir/.netrun_bootstrap.json"

# === MULTI-INSTANCE SUPPORT ===
# Each generation gets unique files based on start_port to avoid conflicts
instance_id="$start_port"
proxyserver_config_path="$proxy_dir/3proxy/3proxy_${instance_id}.cfg"
proxyserver_info_file="$proxy_dir/running_server_${instance_id}.info"
random_ipv6_list_file="$proxy_dir/ipv6_${instance_id}.list"
random_users_list_file="$proxy_dir/random_users_${instance_id}.list"
if [[ $backconnect_proxies_file == "default" ]]; then backconnect_proxies_file="$proxy_dir/backconnect_proxies_${instance_id}.list"; fi;
if [[ $port_ipv6_map_file == "default" ]]; then port_ipv6_map_file="$proxy_dir/port_ipv6_map_${instance_id}.csv"; fi;
startup_script_path="$proxy_dir/proxy-startup_${instance_id}.sh"
cron_script_path="$proxy_dir/proxy-server_${instance_id}.cron"
last_port=$(($start_port + $proxy_count - 1));
credentials=$(is_auth_used && [[ $use_random_auth == false ]] && echo -n ":$user:$password" || echo -n "");

function is_proxyserver_installed() {
  if [ -d $proxy_dir ] && [ "$(ls -A $proxy_dir)" ]; then return 0; fi;
  return 1;
}

function is_proxyserver_running() {
  # Check if THIS specific instance is running (by config path)
  if ps aux | grep -v grep | grep -q "$proxyserver_config_path"; then return 0; else return 1; fi;
}

function check_bootstrap_ready() {
  local print_report="${1:-false}"
  local ready=true

  if [ ! -x "$proxy_dir/3proxy/bin/3proxy" ]; then
    ready=false
    if [ "$print_report" = true ]; then echo " - missing 3proxy binary: $proxy_dir/3proxy/bin/3proxy"; fi;
  fi;

  if [ ! -f "$bootstrap_marker_file" ]; then
    ready=false
    if [ "$print_report" = true ]; then echo " - missing bootstrap marker: $bootstrap_marker_file"; fi;
  fi;

  if [ "$(cat /proc/sys/net/ipv6/ip_nonlocal_bind 2>/dev/null)" != "1" ]; then
    ready=false
    if [ "$print_report" = true ]; then echo " - net.ipv6.ip_nonlocal_bind is not 1"; fi;
  fi;

  if [ "$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null)" != "1" ]; then
    ready=false
    if [ "$print_report" = true ]; then echo " - net.ipv6.conf.all.forwarding is not 1"; fi;
  fi;

  if ! command -v nft &> /dev/null; then
    ready=false
    if [ "$print_report" = true ]; then echo " - nft command is not available"; fi;
  else
    if ! nft list table inet proxy_accounting > /dev/null 2>&1; then
      ready=false
      if [ "$print_report" = true ]; then echo " - nft table inet proxy_accounting is missing"; fi;
    fi;
  fi;

  if [ "$ready" = true ]; then return 0; fi;
  return 1
}

function write_bootstrap_marker() {
  mkdir -p "$proxy_dir"
  cat > "$bootstrap_marker_file" <<-EOF
{
  "bootstrapped_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "interface_name": "$interface_name",
  "script": "proxyyy_automated.sh"
}
EOF
}

function verify_bootstrap_or_exit() {
  if check_bootstrap_ready false; then
    echo "BOOTSTRAP_READY"
    return 0
  fi;
  echo "BOOTSTRAP_NOT_READY"
  echo "Missing prerequisites:"
  check_bootstrap_ready true || true
  log_err_and_exit "Runtime generation requires bootstrap. Run with --bootstrap-only first."
}

function is_package_installed() {
  if [ $(dpkg-query -W -f='${Status}' $1 2>/dev/null | grep -c "ok installed") -eq 0 ]; then return 1; else return 0; fi;
}

function create_random_string() {
  tr -dc A-Za-z0-9 </dev/urandom | head -c $1; echo ''
}

function kill_3proxy() {
  ps -ef | awk '/[3]proxy/{print $2}' | while read -r pid; do
    kill $pid
  done;
}

function remove_ipv6_addresses_from_iface() {
  if test -f $random_ipv6_list_file; then
    for ipv6_address in $(cat $random_ipv6_list_file); do ip -6 addr del $ipv6_address dev $interface_name; done;
    rm $random_ipv6_list_file;
  fi;
}

function get_subnet_mask() {
  if [ -z $subnet_mask ]; then
    # NOTE: We do NOT kill 3proxy or remove IPv6 addresses anymore!
    # Each instance is independent and should not affect others.

    full_blocks_count=$(($subnet / 16));
    ipv6=$(ip -6 addr | awk '{print $2}' | grep -m1 -oP '^(?!fe80)([0-9a-fA-F]{1,4}:)+[0-9a-fA-F]{1,4}' | cut -d '/' -f1);

    subnet_mask=$(echo $ipv6 | grep -m1 -oP '^(?!fe80)([0-9a-fA-F]{1,4}:){'$(($full_blocks_count - 1))'}[0-9a-fA-F]{1,4}');
    if [ $(expr $subnet % 16) -ne 0 ]; then
      block_part=$(echo $ipv6 | awk -v block=$(($full_blocks_count + 1)) -F ':' '{print $block}' | tr -d ' ');
      while ((${#block_part} < 4)); do block_part="0$block_part"; done;
      symbols_to_include=$(echo $block_part | head -c $(($(expr $subnet % 16) / 4)));
      subnet_mask="$subnet_mask:$symbols_to_include";
    fi;
  fi;

  echo $subnet_mask;
}

function delete_file_if_exists() {
  if test -f $1; then rm $1; fi;
}

function install_package() {
  if ! is_package_installed $1; then
    if [ "$bootstrap_side_effects_allowed" != true ]; then
      log_err_and_exit "Package '$1' is missing. Run bootstrap-only mode first."
    fi;
    apt install $1 -y &>> $script_log_file;
    if ! is_package_installed $1; then
      log_err_and_exit "Error: cannot install \"$1\" package";
    fi;
  fi;
}

function configure_dns_servers() {
  # --- Manual override (accepts IPv4 OR IPv6 for each of the two slots) ---
  if [ -n "$dns_servers_override" ]; then
    IFS=',' read -r dns_override_1 dns_override_2 _ <<< "$dns_servers_override"
    dns_override_1=$(echo "$dns_override_1" | tr -d '[:space:]')
    dns_override_2=$(echo "$dns_override_2" | tr -d '[:space:]')
    if { is_valid_ip "$dns_override_1" || looks_like_ipv6 "$dns_override_1"; } \
       && { is_valid_ip "$dns_override_2" || looks_like_ipv6 "$dns_override_2"; }; then
      dns_nserver_lines="  nserver ${dns_override_1}"$'\n'"  nserver ${dns_override_2}"
      dns_selected_servers_csv="${dns_override_1},${dns_override_2}"
      dns_selection_strategy="manual_override"
      echo "   DNS selected (manual_override): ${dns_selected_servers_csv}"
      return
    else
      log_err_print_usage_and_exit "Error: '--dns-servers' must contain two valid IPv4 or IPv6 resolvers as 'ip1,ip2'";
    fi;
  fi;

  # --- Default: local recursive resolver (unbound on 127.0.0.1) ---
  # The bundled 3proxy 0.9.3 HONOURS the cfg `nserver` (h_nserver sets
  # resolvfunc = myresolver -> udpresolve), and every node runs a local unbound
  # (install_node_v2 -> configure_unbound). Pointing nserver at it keeps customer
  # lookups on the node — no Cloudflare / third-party resolver sees them. The
  # recursion leaves from the node's PRIMARY address (proxy anchors are
  # deprecated, never picked as a source), so a DNS-leak test shows the node,
  # not the proxy's exit IP: same network/ASN, not the same address.
  # Override with --dns-servers if needed.
  dns_nserver_lines="  nserver 127.0.0.1"$'\n'"  nserver ::1"
  dns_selected_servers_csv="127.0.0.1,::1"
  dns_selection_strategy="local_unbound"
  echo "   DNS selected (local_unbound): 127.0.0.1, ::1"
}

function get_backconnect_ipv4() {
  if [ $use_localhost == true ]; then echo "127.0.0.1"; return; fi;
  if [ ! -z "$backconnect_ipv4" -a "$backconnect_ipv4" != " " ]; then echo $backconnect_ipv4; return; fi;

  local maybe_ipv4=$(ip addr show $interface_name | awk '$1 == "inet" {gsub(/\/.*$/, "", $2); print $2}')
  if is_valid_ip $maybe_ipv4; then echo $maybe_ipv4; return; fi;

  if ! is_package_installed "curl"; then install_package "curl"; fi;

  (maybe_ipv4=$(curl https://ipinfo.io/ip)) &> /dev/null
  if is_valid_ip $maybe_ipv4; then echo $maybe_ipv4; return; fi;

  log_err_and_exit "Error: curl package not installed and cannot parse valid IP from interface info";
}

# HTTPS frontend (scripts/netrun-https.sh): when the node has it, HTTP proxy
# listeners bind 127.0.0.1 and haproxy owns the public HTTP ports.
function http_listen_ip_for_node() {
  if [ -d /etc/haproxy/netrun.d ]; then echo "127.0.0.1"; else echo "$backconnect_ipv4"; fi;
}

# Wave CAPACITY-18K — pure filter over ONE `ss -Hltn` (or `ss -ltn`) snapshot
# read on stdin. Prints "<port> <address>" for every LISTEN socket that would
# collide with this batch: a port in [lo1,hi1] (socks, or the single-mode
# range) on an address that clashes with bind address $3, or a port in
# [lo2,hi2] (the paired dual http range; pass 0 -1 to disable) clashing with $6.
# An address clashes when it is the very address we bind, or a wildcard
# (0.0.0.0, `*` = dual-stack [::], [::] / [::ffff:<ip>] — treated as clashing
# to stay conservative). A listener on a DIFFERENT specific address (e.g.
# haproxy on <public-ip>:<http-port> while 3proxy http binds 127.0.0.1) does
# not collide. POSIX awk only (mawk on Ubuntu, BSD awk in tests).
function select_listen_conflicts() {
  awk -v lo1="$1" -v hi1="$2" -v ip1="$3" -v lo2="${4:-0}" -v hi2="${5:--1}" -v ip2="${6:-}" '
    function clash(a, ip) {
      return (a == ip || a == "0.0.0.0" || a == "*" || a == "::" || a == ("::ffff:" ip))
    }
    $1 != "LISTEN" { next }
    {
      la = ""
      for (i = 2; i <= NF; i++) if ($i ~ /:[0-9]+$/) { la = $i; break }
      if (la == "") next
      port = la; sub(/.*:/, "", port); port += 0
      addr = la; sub(/:[0-9]+$/, "", addr); sub(/^\[/, "", addr); sub(/\]$/, "", addr); sub(/%.*$/, "", addr)
      if (port >= lo1 + 0 && port <= hi1 + 0 && clash(addr, ip1)) print port, addr
      else if (port >= lo2 + 0 && port <= hi2 + 0 && clash(addr, ip2)) print port, addr
    }'
}

# Number of distinct ports in [lo,hi] listening on any address, from ONE ss
# snapshot on stdin (replaces the old one-`ss`-per-port loop: O(batch x all
# listeners) — ~1500 full dumps of ~36k sockets per batch on an 18k node).
function count_listening_in_range() {
  awk -v lo="$1" -v hi="$2" '
    $1 != "LISTEN" { next }
    {
      for (i = 2; i <= NF; i++) if ($i ~ /:[0-9]+$/) {
        port = $i; sub(/.*:/, "", port); port += 0
        if (port >= lo + 0 && port <= hi + 0 && !(port in seen)) { seen[port] = 1; n++ }
        break
      }
    }
    END { print n + 0 }'
}

function ss_listen_snapshot() {
  ss -Hltn 2>/dev/null || ss -ltn 2>/dev/null
}

# Wave CAPACITY-18K — refuse a batch whose ports are already bound, BEFORE any
# side effect (cron, nft, startup script, 3proxy). One ss snapshot per batch.
# Without it a second 3proxy (SO_REUSEPORT, same uid) silently shares the port
# with a stale one (~50% refused connects), and a port held by another uid
# (haproxy, unbound, the agent) leaves the new listener dead while the old
# post-start check still counted the port as "listening".
# NETRUN_SKIP_PORT_PRECHECK=1 disables it (operator escape hatch).
function check_ports_not_listening() {
  if [ "${NETRUN_SKIP_PORT_PRECHECK:-0}" = "1" ]; then
    echo "   Port pre-check skipped (NETRUN_SKIP_PORT_PRECHECK=1)";
    return 0;
  fi;
  local snapshot main_ip http_lo=0 http_hi=-1 http_ip="" conflicts n
  if ! snapshot="$(ss_listen_snapshot)"; then
    echo "   Warning: ss failed - port pre-check skipped";
    return 0;
  fi;
  main_ip="$backconnect_ipv4"
  if [ "$proxies_type" = "http" ]; then main_ip="$(http_listen_ip_for_node)"; fi;
  if [ "$proxies_type" = "dual" ]; then
    http_lo=$((start_port - 10000)); http_hi=$((last_port - 10000)); http_ip="$(http_listen_ip_for_node)";
  fi;
  conflicts="$(printf '%s\n' "$snapshot" | select_listen_conflicts "$start_port" "$last_port" "$main_ip" "$http_lo" "$http_hi" "$http_ip")"
  if [ -n "$conflicts" ]; then
    n=$(printf '%s\n' "$conflicts" | wc -l | tr -d ' ')
    log_err_and_exit "Error: ports_already_listening: $n port(s) of batch $start_port-$last_port are already bound by another listener ($(printf '%s\n' "$conflicts" | head -n 5 | tr '\n' ';')) - refusing to generate";
  fi;
  echo "   Port pre-check OK: no listener on ports $start_port-$last_port$(if [ "$proxies_type" = "dual" ]; then echo " / $http_lo-$http_hi"; fi)";
}

function check_ipv6() {
  if test -f /proc/net/if_inet6; then
    echo "РІСљвЂ¦ IPv6 interface is enabled";
  else
    log_err_and_exit "Error: inet6 (ipv6) interface is not enabled. Enable IP v6 on your system.";
  fi;

  if [[ $(ip -6 addr show scope global) ]]; then
    echo "РІСљвЂ¦ IPv6 global address is allocated on server successfully";
  else
    log_err_and_exit "Error: IPv6 global address is not allocated on server, allocate it or contact your VPS/VDS support.";
  fi;

  local ifaces_config="/etc/network/interfaces";
  if [ $inet6_network_interfaces_configuration_check = true ]; then
    if [ -f $ifaces_config ]; then
      if grep 'inet6' $ifaces_config > /dev/null; then
        echo "РІСљвЂ¦ Network interfaces for IPv6 configured correctly";
      else
        log_err_and_exit "Error: $ifaces_config has no inet6 (IPv6) configuration.";
      fi;
    else
      echo "РІС™В РїС‘РЏ Warning: $ifaces_config doesn't exist. Skipping interface configuration check.";
    fi;
  fi;

  if [[ $(ping6 -c 1 google.com) != *"Network is unreachable"* ]] &> /dev/null; then
    echo "РІСљвЂ¦ Test ping google.com using IPv6 successfully";
  else
    log_err_and_exit "Error: test ping google.com through IPv6 failed, network is unreachable.";
  fi;
}

function add_to_cron() {
  # Get existing crontab, add THIS instance's startup script
  # Do NOT remove other instances' scripts!
  
  local temp_cron="/tmp/cron_temp_$$"
  
  # Get existing crontab (excluding THIS specific startup script if already there)
  crontab -l 2>/dev/null | grep -v "$startup_script_path" > "$temp_cron" || true
  
  # Add this instance's reboot entry
  echo "@reboot $bash_location $startup_script_path" >> "$temp_cron"
  
  # Add rotation if needed
  if [ $rotating_interval -ne 0 ]; then 
    echo "*/$rotating_interval * * * * $bash_location $startup_script_path" >> "$temp_cron"
  fi;

  crontab "$temp_cron"
  rm -f "$temp_cron"
  systemctl restart cron 2>/dev/null || true

  if crontab -l | grep -q "$startup_script_path"; then
    echo "РІСљвЂ¦ Proxy startup script added to cron autorun successfully";
  else
    log_err "РІС™В РїС‘РЏ Warning: adding script to cron autorun failed.";
  fi;
}

function remove_from_cron() {
  crontab -l | grep -v $startup_script_path > $cron_script_path 2>/dev/null || true;
  crontab $cron_script_path;
  systemctl restart cron;

  if crontab -l | grep -q $startup_script_path; then
    log_err "РІС™В РїС‘РЏ Warning: cannot delete proxy script from crontab";
  else
    echo "РІСљвЂ¦ Proxy script deleted from crontab successfully";
  fi;
}

function generate_random_users_if_needed() {
  if [ $use_random_auth != true ]; then return; fi;
  
  # Only generate new credentials if file doesn't exist
  # This preserves credentials across restarts
  if [ -f "$random_users_list_file" ]; then
    echo "   Using existing credentials from $random_users_list_file"
    return
  fi

  for i in $(seq 1 $proxy_count); do
    echo $(create_random_string 8):$(create_random_string 8) >> $random_users_list_file;
  done;
}

# Speed audit — COUNT random addresses for a /BITS under MASK, one per line,
# unique among themselves and against the lines of SEEN_FILE: ONE od + ONE awk
# for the whole batch. The old loop forked ~17 subshells per address AND, via
# $(get_subnet_mask) in a subshell (its cache never reached the parent), dumped
# every address on the NIC (`ip -6 addr`, ~17k lines on a full node) per
# address. Same layout as before: the mask, then one random hex digit per 4
# bits with a ':' at every 16-bit boundary (each digit = one urandom byte mod 16,
# uniform). Exit 1 if the random bytes ran out first (practically never: 2x).
function random_ipv6_suffixes() {
  local mask="$1" bits="$2" count="$3" seen="${4:-/dev/null}" digits
  digits=$(( (128 - bits) / 4 ))
  od -An -v -tu1 -N "$(( count * digits * 2 + 64 ))" /dev/urandom | awk \
    -v mask="$mask" -v bits="$bits" -v count="$count" -v seenf="$seen" '
    BEGIN {
      while ((getline l < seenf) > 0) seen[l] = 1
      hex = "0123456789abcdef"; n = 0; addr = ""
    }
    {
      for (i = 1; i <= NF && n < count; i++) {
        if (addr == "") { addr = mask; sym = bits }
        if (sym % 16 == 0) addr = addr ":"
        addr = addr substr(hex, ($i % 16) + 1, 1)
        sym += 4
        if (sym >= 128) {
          if (!(addr in seen)) { seen[addr] = 1; print addr; n++ }
          addr = ""
        }
      }
    }
    END { if (n < count) exit 1 }'
}

function generate_ipv6_addresses_if_needed() {
  # Generate IPv6 addresses early if they don't exist yet
  # This is needed for nftables counter setup
  if [ -f "$random_ipv6_list_file" ]; then
    echo "   Using existing IPv6 addresses from $random_ipv6_list_file"
    return
  fi

  echo "   Generating $proxy_count unique IPv6 addresses..."
  # In THIS shell (not $(...)), so subnet_mask is derived once per batch (it
  # was re-derived, with an `ip -6 addr` dump, for every address).
  get_subnet_mask > /dev/null
  if [ -z "$subnet_mask" ]; then
    log_err_and_exit "Error: cannot derive the IPv6 /$subnet prefix (no global IPv6 address on the server)";
  fi

  # Wave PERGB-IPV6-FAST: never hand out an address the NIC already carries —
  # one snapshot of the existing addresses, checked inside the awk pass.
  local seen_file
  seen_file="$(mktemp 2>/dev/null)" || log_err_and_exit "Error: mktemp failed"
  ip -6 addr show 2>/dev/null | grep -oE 'inet6 [0-9a-f:]+' | sed -E 's/inet6 //' > "$seen_file"
  if ! random_ipv6_suffixes "$subnet_mask" "$subnet" "$proxy_count" "$seen_file" > "${random_ipv6_list_file}.tmp"; then
    rm -f "$seen_file" "${random_ipv6_list_file}.tmp"
    log_err_and_exit "Error: could not generate $proxy_count unique IPv6 addresses"
  fi
  rm -f "$seen_file"
  mv -f "${random_ipv6_list_file}.tmp" "$random_ipv6_list_file"

  echo "   РІСљвЂ¦ Generated $proxy_count IPv6 addresses"
}

function create_startup_script() {
  # Don't delete - we want to keep old scripts for other instances
  # delete_file_if_exists $startup_script_path;

  is_auth_used;
  local use_auth=$?;

  # HTTPS frontend (scripts/netrun-https.sh): when the node has it, HTTP proxy
  # listeners bind 127.0.0.1 and haproxy owns the public HTTP ports, answering
  # both plain HTTP and HTTPS (TLS) proxy clients on the same port. SOCKS
  # listeners stay on the public IPv4.
  local http_listen_ip
  http_listen_ip="$(http_listen_ip_for_node)"
  local main_listen_ip="$backconnect_ipv4"
  if [ "$proxies_type" = "http" ]; then main_listen_ip="$http_listen_ip"; fi
  # Audit FP-01 — anchors are added deprecated (see the ip -batch below).
  local anchor_lft=" preferred_lft 0"
  if [ "$(netrun_setting NETRUN_ANCHOR_DEPRECATE 1)" = 0 ]; then anchor_lft=""; fi

  # Wave CAPACITY-18K — the batch header no longer carries
  # `nscache 65536` / `nscache6 65536`. In the bundled 3proxy 0.9.3 they make
  # inithashtable() malloc+memset+thread a free-list through every entry, i.e.
  # ~6 MiB RESIDENT per process (2.62 + 3.38 MiB), for a cache the node does
  # not need: names are resolved through `nserver 127.0.0.1` / `::1` (h_nserver
  # sets resolvfunc=myresolver -> udpresolve), i.e. the node's own caching
  # unbound. Without nscache dns_table.hashtable stays NULL and hashresolv()
  # (0xfe16) / hashadd() (0xfcda) return early — every lookup simply goes to
  # unbound, nothing else in 3proxy reads that cache (dnspr is unused). Do NOT
  # "shrink" it instead: h_nscache rejects sizes <= 255 ("Invalid NS cache
  # size") and 3proxy then refuses the whole config. Existing batches keep
  # their header until regenerated.
  cat > $startup_script_path <<-EOF
	#!$bash_location

	# === MULTI-INSTANCE STARTUP SCRIPT ===
	# This script starts ONLY this specific proxy instance (ports $start_port-$last_port)
	# It does NOT touch other instances!

	function dedent() {
	  local -n reference="\$1"
	  reference="\$(echo "\$reference" | sed 's/^[[:space:]]*//')"
	}

	# NOTE: We do NOT kill old 3proxy processes - each instance runs independently!

	# The generator writes $random_ipv6_list_file BEFORE this script. Without it
	# this batch would get brand-new random exit addresses (every customer's IP
	# silently changed) — refuse instead (audit speed/CLN: the old in-script
	# generator was O(addresses on the NIC) per address).
	if [ ! -s "$random_ipv6_list_file" ]; then
	  echo "proxy-startup_${instance_id}: missing $random_ipv6_list_file — not starting (regenerate the batch)" >&2
	  exit 1
	fi

	immutable_config_part="daemon
$dns_nserver_lines
	  maxconn $proxy_maxconn
	  timeouts 1 5 30 60 180 1800 15 60
	  setgid 65535
	  setuid 65535"

	auth_part="auth iponly"
	if [ $use_auth -eq 0 ]; then
	  auth_part="
	    auth strong"
	  # Security fix 2026-10-02 (A1): with per-proxy random auth \$user is EMPTY,
	  # and "users :CL:" registered a user with an empty login AND password —
	  # every proxy accepted empty credentials. Only declare a real user.
	  if [ -n "$user" ]; then
	    auth_part="\$auth_part
	    users $user:CL:$password"
	  fi;
	fi;

	if [ -n "$denied_hosts" ]; then
	  access_rules_part="
	    deny * * $denied_hosts
	    allow *"
	else
	  access_rules_part="
	    allow * * $allowed_hosts
	    deny *"
	fi;

	dedent immutable_config_part;
	dedent auth_part;
	dedent access_rules_part;

	echo "\$immutable_config_part"\$'\n'"\$auth_part"\$'\n'"\$access_rules_part"  > $proxyserver_config_path;

	port=$start_port
	count=0
	if [ "$proxies_type" = "http" ]; then proxy_startup_depending_on_type="proxy $mode_flag -n -a"; else proxy_startup_depending_on_type="socks $mode_flag -a"; fi;
	if [ $use_random_auth = true ]; then readarray -t proxy_random_credentials < $random_users_list_file; fi;
	for random_ipv6_address in \$(cat $random_ipv6_list_file); do
	    if [ $use_random_auth = true ]; then
	      IFS=":";
	      read -r username password <<< "\${proxy_random_credentials[\$count]}";
	      echo "flush" >> $proxyserver_config_path;
	      echo "users \$username:CL:\$password" >> $proxyserver_config_path;
	      # Security fix 2026-10-02 (A2): 3proxy's user list is GLOBAL (flush
	      # resets ACLs, not users), so "allow * *" let EVERY login of the batch
	      # in on EVERY port. Each port admits only its own login.
	      if [ -n "$denied_hosts" ]; then
	        echo "deny * * $denied_hosts" >> $proxyserver_config_path;
	        echo "allow \$username" >> $proxyserver_config_path;
	      else
	        echo "allow \$username * $allowed_hosts" >> $proxyserver_config_path;
	        echo "deny *" >> $proxyserver_config_path;
	      fi;
	      IFS=\$' \t\n';
	    fi;
	    echo "\$proxy_startup_depending_on_type -p\$port -i$main_listen_ip -e\$random_ipv6_address" >> $proxyserver_config_path;
	    # Wave HTTP.A — dual mode: also emit a paired http listener on
	    # port-10000 for the SAME IPv6. The "$proxies_type" literal is
	    # baked at generation time, so for socks5/http this branch is a
	    # dead no-op (backward-compatible).
	    if [ "$proxies_type" = "dual" ]; then
	      echo "proxy $mode_flag -n -a -p\$((port - 10000)) -i$http_listen_ip -e\$random_ipv6_address" >> $proxyserver_config_path;
	    fi;
	    ((port+=1))
	    ((count+=1))
	done

	ulimit -n 600000
	ulimit -u 600000
	
	# Add IPv6 addresses (Wave CAPACITY-18K): ONE ip process per batch (ip -batch)
	# instead of a fork per address, and nodad so an address is never left
	# tentative (unusable as the -e egress source) even where accept_dad is still
	# on for the interface. -force keeps going past "File exists" on re-runs.
	# Audit FP-01: /128 and preferred_lft 0 — a deprecated anchor is never the
	# kernel's choice of source for the node's OWN traffic (RFC 6724 rule 3),
	# while 3proxy's explicit -e bind still uses it (NETRUN_ANCHOR_DEPRECATE=0: off).
	ipv6_batch_file=\$(mktemp 2>/dev/null || echo "${random_ipv6_list_file}.ipbatch")
	awk 'NF { print "address add " \$1 "/128 dev $interface_name nodad$anchor_lft" }' ${random_ipv6_list_file} > "\$ipv6_batch_file"
	ip -6 -force -batch "\$ipv6_batch_file" >/dev/null 2>&1 || true
	rm -f "\$ipv6_batch_file"

	# NOTE: We do NOT kill old proxy processes - each instance is independent!

	# Start THIS 3proxy instance. Audit RES-11: through the node's one spawn
	# helper (its own systemd scope — never inside the agent's or a cron/ssh
	# cgroup; idempotent, never a duplicate); a plain nohup where it is absent.
	spawn_helper="\${NETRUN_3PROXY_SPAWN:-/opt/netrun/scripts/netrun-3proxy-spawn.sh}"
	if [ -f "\$spawn_helper" ]; then
	  NETRUN_3PROXY_BIN=${user_home_dir}/proxyserver/3proxy/bin/3proxy bash "\$spawn_helper" ${proxyserver_config_path} >/dev/null 2>&1 || true
	else
	  nohup ${user_home_dir}/proxyserver/3proxy/bin/3proxy ${proxyserver_config_path} >/dev/null 2>&1 &
	  sleep 2  # Wait for daemon to initialize
	fi

	# HTTPS frontend: put this instance's HTTP ports behind haproxy right away
	# (the netrun-https-sync timer would otherwise pick them up within 5 min).
	if [ -x /usr/local/sbin/netrun-https ]; then /usr/local/sbin/netrun-https sync >/dev/null 2>&1 || true; fi

	# NOTE: We do NOT delete old IPv6 addresses - they belong to other instances!

	exit 0;
EOF

}

function close_ufw_backconnect_ports() {
  if ! is_package_installed "ufw" || [ $use_localhost = true ] || ! test -f $backconnect_proxies_file; then return; fi;

  # Wave HTTP.A — strip an optional "scheme://login:pass@" prefix first so
  # this works for BOTH the legacy "ipv4:port:login:pass" lines and the
  # dual "scheme://login:pass@ipv4:port" URI lines; then field 2 (by ':')
  # is the port in either case.
  local first_opened_port=$(head -n 1 $backconnect_proxies_file | sed -E 's#^[a-zA-Z0-9]+://[^@]*@##' | awk -F ':' '{print $2}');
  local last_opened_port=$(tail -n 1 $backconnect_proxies_file | sed -E 's#^[a-zA-Z0-9]+://[^@]*@##' | awk -F ':' '{print $2}');

  ufw delete allow $first_opened_port:$last_opened_port/tcp >> $script_log_file 2>&1 || true;
  ufw delete allow $first_opened_port:$last_opened_port/udp >> $script_log_file 2>&1 || true;

  if ufw status | grep -qw $first_opened_port:$last_opened_port; then
    log_err "РІС™В РїС‘РЏ Cannot delete UFW rules for backconnect proxies";
  else
    echo "РІСљвЂ¦ UFW rules for backconnect proxies cleared successfully";
  fi;
}

function open_ufw_backconnect_ports() {
  # NOTE: We do NOT close old ports anymore! Each instance has its own ports.
  # close_ufw_backconnect_ports;

  if [ $use_localhost = true ]; then return; fi;

  if ! is_package_installed "ufw"; then echo "РІСљвЂ¦ Firewall not installed, ports for backconnect proxy opened successfully"; return; fi;

  if ufw status | grep -qw active; then
    # Р вЂќР В»РЎРЏ Р С•Р Т‘Р Р…Р С•Р С–Р С• Р С—Р С•РЎР‚РЎвЂљР В° Р С‘РЎРѓР С—Р С•Р В»РЎРЉР В·РЎС“Р ВµР С РЎвЂћР С•РЎР‚Р СР В°РЎвЂљ "PORT", Р Т‘Р В»РЎРЏ Р Т‘Р С‘Р В°Р С—Р В°Р В·Р С•Р Р…Р В° "START:END"
    if [ $start_port -eq $last_port ]; then
      # Р С›Р Т‘Р С‘Р Р… Р С—Р С•РЎР‚РЎвЂљ
      ufw allow $start_port/tcp >> $script_log_file 2>&1 || true;
      ufw allow $start_port/udp >> $script_log_file 2>&1 || true;
      port_range="$start_port"
    else
      # Р вЂќР С‘Р В°Р С—Р В°Р В·Р С•Р Р… Р С—Р С•РЎР‚РЎвЂљР С•Р Р†
      ufw allow $start_port:$last_port/tcp >> $script_log_file 2>&1 || true;
      ufw allow $start_port:$last_port/udp >> $script_log_file 2>&1 || true;
      port_range="$start_port:$last_port"
    fi;

    # Wave HTTP.A — dual mode also listens on the paired http range
    # (socks range shifted down by 10000); open it too.
    if [ "$proxies_type" = "dual" ]; then
      local http_start=$((start_port - 10000));
      local http_last=$((last_port - 10000));
      ufw allow $http_start:$http_last/tcp >> $script_log_file 2>&1 || true;
      ufw allow $http_start:$http_last/udp >> $script_log_file 2>&1 || true;
      echo "UFW http ports $http_start:$http_last (dual) opened";
    fi;

    # Р СџРЎР‚Р С•Р Р†Р ВµРЎР‚РЎРЏР ВµР С Р Р…Р В°Р В»Р С‘РЎвЂЎР С‘Р Вµ Р С—РЎР‚Р В°Р Р†Р С‘Р В»Р В° (РЎС“Р В»РЎС“РЎвЂЎРЎв‚¬Р ВµР Р…Р Р…Р В°РЎРЏ Р С—РЎР‚Р С•Р Р†Р ВµРЎР‚Р С”Р В°)
    if ufw status | grep -E "(^|[^0-9])${start_port}(/| |:|$)" > /dev/null; then
      echo "РІСљвЂ¦ UFW ports $port_range for backconnect proxies opened successfully";
    else
      log_err $(ufw status);
      log_err "РІС™В РїС‘РЏ Warning: Cannot verify ports $port_range in ufw automatically";
      echo "РІС™В РїС‘РЏ Warning: Ports may not be accessible if firewall is blocking them";
      echo "   To fix manually: Run 'ufw allow $port_range/tcp' on the server";
      echo "   Continuing anyway - proxies will be created but may not work until ports are opened";
    fi;

  else
    echo "РІСљвЂ¦ UFW protection disabled, ports for backconnect proxy opened successfully";
  fi;
}

function ensure_nftables_ready() {
  if ! command -v nft &> /dev/null; then
    if [ "$bootstrap_side_effects_allowed" = true ]; then
      echo "   Installing nftables..."
      apt-get update > /dev/null 2>&1
      DEBIAN_FRONTEND=noninteractive apt-get install -y nftables > /dev/null 2>&1
    else
      log_err_and_exit "nftables is not installed. Run bootstrap-only mode first."
    fi
  fi
  if [ "$bootstrap_side_effects_allowed" = true ]; then
    systemctl enable nftables > /dev/null 2>&1 || true
    systemctl start nftables > /dev/null 2>&1 || true
  fi
}

# Wave FLEET-HEALTH (SPD-05) — the counter maps are keyed by PORT only, so an
# upstream leg whose ephemeral port equals a proxy port is metered to that
# proxy (its _out = billable download) whenever ip_local_port_range overlaps
# the listeners (old nodes: 10000-65000). Clients only ever reach the public
# IPv4 (socks -i<ipv4>, http through haproxy on it; loopback legs excluded), so
# with NETRUN_ACCOUNTING_MATCH_IPV4=1 the two map rules match only packets to /
# from that address. Prints the extra match for chain $1 (input|output) and
# address $2, or nothing (= today's port-only rule). Existing nodes migrate with
# `netrun-https accounting` (same setting).
function accounting_client_match() {
  local chain="$1" ip="$2"
  [ "$(netrun_setting NETRUN_ACCOUNTING_MATCH_IPV4 0)" = 1 ] || return 0
  is_valid_ip "$ip" || return 0
  [ "$ip" != "127.0.0.1" ] || return 0
  if [ "$chain" = input ]; then echo "iifname != lo ip daddr $ip"; else echo "oifname != lo ip saddr $ip"; fi
}

function setup_nftables_counters() {
  echo "   Setting up nftables traffic counters for all proxies"
  echo "   Using nftables for better performance and scalability"
  echo "   РІСљвЂ¦ IPv4 INPUT (dport): client -> proxy (bytesIn)"
  echo "   РІСљвЂ¦ IPv6 OUTPUT (saddr): proxy -> internet (bytesOut) - counted by IPv6 address!"
  echo "   РІСљвЂ¦ IPv6 INPUT (daddr): internet -> proxy (responses)"
  ensure_nftables_ready
  
  # Check if table exists
  if ! nft list table inet proxy_accounting 2>/dev/null >/dev/null; then
    echo "   СЂСџвЂњВ¦ Creating new proxy_accounting table..."
    if [ "$bootstrap_side_effects_allowed" = true ]; then
      nft add table inet proxy_accounting
    else
      log_err_and_exit "nft table inet proxy_accounting is missing. Run bootstrap-only mode first."
    fi
  fi
  
  # Ensure chains exist with correct priority (idempotent operations)
  # We do NOT delete the table to avoid killing other instances' counters
  
  # Try to create chains (will fail if exist, that's fine)
  if [ "$bootstrap_side_effects_allowed" = true ]; then
    nft add chain inet proxy_accounting input '{ type filter hook input priority 0; policy accept; }' 2>/dev/null || true
    nft add chain inet proxy_accounting output '{ type filter hook output priority 0; policy accept; }' 2>/dev/null || true
  else
    if ! nft list chain inet proxy_accounting input > /dev/null 2>&1; then
      log_err_and_exit "nft chain inet proxy_accounting input is missing. Run bootstrap-only mode first."
    fi;
    if ! nft list chain inet proxy_accounting output > /dev/null 2>&1; then
      log_err_and_exit "nft chain inet proxy_accounting output is missing. Run bootstrap-only mode first."
    fi;
  fi
  
  # Check priority just for info
  if nft list table inet proxy_accounting | grep -q "priority filter"; then
     echo "   РІС™В РїС‘РЏ  WARNING: Table seems to have 'priority filter' (default). 'priority 0' is recommended."
     echo "       If counters don't work, run: nft delete table inet proxy_accounting"
     echo "       (This will clear ALL existing counters!)"
  else
     echo "   РІСљвЂ¦ Table priority check passed"
  fi
  
  # Wave PERGB-METER-MAP: O(1) per-packet accounting. The legacy path added one
  # linear chain rule per port (`tcp dport <port> counter ...`), so EVERY packet
  # scanned up to N rules -> at ~5k ports the node collapsed under real traffic.
  # Replace that with ONE rule per chain that selects the per-port counter through
  # a map (single hash lookup, O(1) regardless of port count). Maps + the two
  # map-rules are ensured once here; the per-port loop below only adds map ELEMENTS.
  nft add map inet proxy_accounting cmap_in  '{ type inet_service : counter ; }' 2>/dev/null || true
  nft add map inet proxy_accounting cmap_out '{ type inet_service : counter ; }' 2>/dev/null || true
  local _acct_in_match _acct_out_match
  _acct_in_match="$(accounting_client_match input "$backconnect_ipv4")"
  _acct_out_match="$(accounting_client_match output "$backconnect_ipv4")"
  # shellcheck disable=SC2086 # the match is a list of nft tokens
  nft list chain inet proxy_accounting input  2>/dev/null | grep -q 'map @cmap_in'  || nft add rule inet proxy_accounting input  $_acct_in_match counter name tcp dport map @cmap_in
  # shellcheck disable=SC2086
  nft list chain inet proxy_accounting output 2>/dev/null | grep -q 'map @cmap_out' || nft add rule inet proxy_accounting output $_acct_out_match counter name tcp sport map @cmap_out

  echo "   Adding counter rules for $proxy_count proxies..."
  
  # Read IPv6 addresses from the list file
  if [ ! -f "$random_ipv6_list_file" ]; then
    echo "   РІС™В РїС‘РЏ IPv6 list file not found, will be created on first run"
    return
  fi
  
  readarray -t ipv6_addresses < "$random_ipv6_list_file"
  local added_count=0
  local failed_count=0

  # PERGB-NFT-BATCH (2026-06-27): the per-port loop below spawns ~10 nft
  # processes per port (~5000 for 500 ports = minutes at 100% CPU). On a small
  # node that starves the box mid-generation -> the orchestrator can't reach it
  # (node_unavailable) and the freshly-spawned 3proxy binds its 500 listeners too
  # slowly (ports_not_listening). For a FRESH range, collect every add into ONE
  # atomic `nft -f` (single process, ~1s). Re-account / partial ranges make an add
  # collide so the batch aborts atomically -> we fall through to the robust
  # per-port path below (which deletes-then-adds, preserving counter values).
  local _bok=1 _batch_file
  _batch_file=$(mktemp 2>/dev/null) || _batch_file=""
  if [ -n "$_batch_file" ]; then
    {
      for ((i=0; i<proxy_count; i++)); do
        local _p=$((start_port + i))
        if [ -z "${ipv6_addresses[$i]}" ]; then _bok=0; break; fi
        echo "add counter inet proxy_accounting proxy_${_p}_in"
        echo "add counter inet proxy_accounting proxy_${_p}_out"
        echo "add element inet proxy_accounting cmap_in { ${_p} : \"proxy_${_p}_in\" }"
        echo "add element inet proxy_accounting cmap_out { ${_p} : \"proxy_${_p}_out\" }"
        if [ "$proxies_type" = "dual" ]; then
          local _hp=$((_p - 10000))
          echo "add element inet proxy_accounting cmap_in { ${_hp} : \"proxy_${_p}_in\" }"
          echo "add element inet proxy_accounting cmap_out { ${_hp} : \"proxy_${_p}_out\" }"
        fi
      done
    } > "$_batch_file"
    if [ "$_bok" = "1" ] && nft -f "$_batch_file" 2>/dev/null; then
      added_count=$proxy_count
      rm -f "$_batch_file"
      echo "   [PROGRESS] Setup $proxy_count/$proxy_count counters (fast batch)..."
      echo "   Setup $added_count nftables counters (client-port based, batched)"
      echo "   Saving nftables rules for persistence..."
      nft list ruleset > /etc/nftables.conf 2>/dev/null || true
      return 0
    fi
    rm -f "$_batch_file"
  fi
  
  for ((i=0; i<proxy_count; i++)); do
    local port=$((start_port + i))
    local ipv6="${ipv6_addresses[$i]}"
    
    # Skip if no IPv6 address (shouldn't happen)
    if [ -z "$ipv6" ]; then
      echo "   РІСњРЉ ERROR: No IPv6 address for port $port (index $i)"
      failed_count=$((failed_count + 1))
      continue
    fi
    
    # Wave PERGB-METER-FIX (2026-06-13): meter on the CLIENT-FACING port, NOT the
    # egress IPv6. The old _out/_in6 rules matched a single fixed egress IPv6
    # (-e<ipv6>), but strict_dual_stack egresses over IPv4 / a rotated IPv6 -> the
    # download matched no rule -> ~0% captured. The listening port is fixed and, in
    # an `inet` table, a bare `tcp dport/sport` rule counts BOTH v4 and v6 clients.
    #   proxy_<port>_in  = client -> proxy  (upload, both families)
    #   proxy_<port>_out = proxy  -> client (DOWNLOAD delivered to client = BILLABLE)
    # DUAL: the paired http listener (socks port - 10000) folds into the SAME
    # counters so http traffic bills the same pool (http port is not its own polled
    # proxy_inventory row). This whole block is idempotent => also the live-reaccount path.
    local http_port=$((port - 10000))

    # Cleanup: legacy egress-IPv6 rules + retired _in6 counter, and any prior
    # client-port rules (so re-running on a live port is a clean swap).
    nft delete rule inet proxy_accounting output ip6 saddr "$ipv6" 2>/dev/null || true
    nft delete rule inet proxy_accounting input  ip6 daddr "$ipv6" 2>/dev/null || true
    nft delete counter inet proxy_accounting "proxy_${port}_in6" 2>/dev/null || true
    while nft delete rule inet proxy_accounting input  tcp dport "$port" 2>/dev/null; do :; done
    while nft delete rule inet proxy_accounting output tcp sport "$port" 2>/dev/null; do :; done
    if [ "$proxies_type" = "dual" ]; then
      while nft delete rule inet proxy_accounting input  tcp dport "$http_port" 2>/dev/null; do :; done
      while nft delete rule inet proxy_accounting output tcp sport "$http_port" 2>/dev/null; do :; done
    fi
    # Wave PERGB-METER-MAP: NEVER delete the counters on re-account -> their
    # cumulative byte values (billing) must survive. Drop only the old map elements
    # so the re-add below is a clean, value-safe swap.
    nft delete element inet proxy_accounting cmap_in  "{ $port }" 2>/dev/null || true
    nft delete element inet proxy_accounting cmap_out "{ $port }" 2>/dev/null || true
    if [ "$proxies_type" = "dual" ]; then
      nft delete element inet proxy_accounting cmap_in  "{ $http_port }" 2>/dev/null || true
      nft delete element inet proxy_accounting cmap_out "{ $http_port }" 2>/dev/null || true
    fi

    # Two named counters per port (idempotent -> value preserved on re-account).
    nft add counter inet proxy_accounting "proxy_${port}_in"  2>/dev/null || true
    nft add counter inet proxy_accounting "proxy_${port}_out" 2>/dev/null || true
    
    # Wave PERGB-METER-MAP: register port -> counter in the maps. The chain's single
    # map-rule then bills every packet via an O(1) hash lookup (was an O(N) linear
    # per-port rule scan that collapsed the node at scale). A bare port match in an
    # inet table counts BOTH IPv4 and IPv6 clients.
    #   proxy_<port>_in  = client -> proxy  (upload)
    #   proxy_<port>_out = proxy  -> client (DOWNLOAD = BILLABLE)
    local err_msg=$(nft add element inet proxy_accounting cmap_in "{ $port : \"proxy_${port}_in\" }" 2>&1)
    if [ $? -eq 0 ]; then
      added_count=$((added_count + 1))
    else
      echo "   [ERR] Failed IN element for port $port: $err_msg"
      failed_count=$((failed_count + 1))
    fi

    err_msg=$(nft add element inet proxy_accounting cmap_out "{ $port : \"proxy_${port}_out\" }" 2>&1)
    if [ $? -ne 0 ]; then
      echo "   [ERR] Failed OUT element for port $port: $err_msg"
      failed_count=$((failed_count + 1))
    fi

    # DUAL: fold the paired http listener (socks port - 10000) into the SAME counters,
    # so http-proxy traffic bills the same pool (http port is not its own polled row).
    if [ "$proxies_type" = "dual" ]; then
      nft add element inet proxy_accounting cmap_in  "{ $http_port : \"proxy_${port}_in\" }"  2>/dev/null || true
      nft add element inet proxy_accounting cmap_out "{ $http_port : \"proxy_${port}_out\" }" 2>/dev/null || true
    fi
    
    # Show progress every 100
    if [ $((i % 100)) -eq 0 ] && [ "$i" -gt 0 ]; then
      echo "   [PROGRESS] Setup $i/$proxy_count counters..."
    fi
  done
  
  if [ $failed_count -gt 0 ]; then
    echo "РІС™В РїС‘РЏ  Setup $added_count nftables counters (client-port based) with $failed_count failures"
  else
    echo "РІСљвЂ¦ Setup $added_count nftables counters (client-port based)"
  fi
  
  # Save nftables rules for persistence
  echo "СЂСџвЂ™С• Saving nftables rules for persistence..."
  nft list ruleset > /etc/nftables.conf 2>/dev/null || true
  echo "   РІСљвЂ¦ nftables rules saved to /etc/nftables.conf"
  
  # Show sample counter for verification
  if [ $added_count -gt 0 ]; then
    echo ""
    echo "СЂСџвЂќРЊ Sample counter verification (port $start_port):"
    nft list ruleset | grep -A1 "proxy_${start_port}" | head -6 || true
    echo ""
  fi
}

function run_proxy_server() {
  if [ ! -f $startup_script_path ]; then log_err_and_exit "Error: proxy startup script doesn't exist."; fi;

  chmod +x $startup_script_path;
  $bash_location $startup_script_path
  
  # Wait for THIS proxy instance to start (give it up to 5 seconds)
  for i in {1..5}; do
    sleep 1
    # Check if THIS specific config is running
    if ps aux | grep -v grep | grep -q "$proxyserver_config_path"; then
      echo -e "\nРІСљвЂ¦ IPv6 proxy server process started!"
      
      # Verify ports are actually listening — Wave CAPACITY-18K: ONE ss
      # snapshot per poll (was one full `ss` dump PER PORT: O(batch x all
      # listeners)). Informational, as before; the agent's own validation
      # waits for the exact ports. Poll a few times while 3proxy binds.
      local ports_ok=0
      local ports_fail=0
      local poll
      echo "   Checking ports..."
      for poll in 1 2 3 4 5; do
        ports_ok=$(ss_listen_snapshot | count_listening_in_range "$start_port" "$last_port")
        ports_fail=$((proxy_count - ports_ok))
        if [ "$ports_fail" -le 0 ]; then break; fi
        sleep 1
      done
      
      if [ $ports_fail -eq 0 ]; then
        echo "   РІСљвЂ¦ All $ports_ok ports are listening"
      else
        echo "   РІС™В РїС‘РЏ $ports_ok ports OK, $ports_fail ports NOT listening"
      fi
      
      echo "СЂСџРЉС’ Backconnect IPv4: $backconnect_ipv4:$start_port$credentials to $backconnect_ipv4:$last_port$credentials"
      echo "СЂСџвЂќвЂ™ Protocol: $proxies_type"
      echo "СЂСџвЂњРѓ Proxy list file: $backconnect_proxies_file"
      echo "СЂСџвЂњвЂ№ Instance ID: $instance_id (config: 3proxy_${instance_id}.cfg)"
      return 0
    fi
  done
  
  log_err_and_exit "Error: cannot run proxy server - timeout waiting for startup";
}

function write_backconnect_proxies_to_file() {
  # Р СџРЎР‚Р С‘Р Р…РЎС“Р Т‘Р С‘РЎвЂљР ВµР В»РЎРЉР Р…Р С• РЎС“Р Т‘Р В°Р В»РЎРЏР ВµР С Р С‘ Р С—Р ВµРЎР‚Р ВµР В·Р В°Р С—Р С‘РЎРѓРЎвЂ№Р Р†Р В°Р ВµР С РЎвЂћР В°Р в„–Р В»
  rm -f $backconnect_proxies_file;

  local proxy_credentials=$credentials;
  if ! touch $backconnect_proxies_file &> $script_log_file; then
    echo "Backconnect proxies list file path: $backconnect_proxies_file" >> $script_log_file;
    log_err "РІС™В РїС‘РЏ Warning: provided invalid path to backconnect proxies list file";
    return;
  fi;

  if [ $use_random_auth = true ]; then
    local proxy_random_credentials;
    local count=0;
    readarray -t proxy_random_credentials < $random_users_list_file;
  fi;

  local first_line=true;
  for port in $(eval echo "{$start_port..$last_port}"); do
    if [ $use_random_auth = true ]; then
      proxy_credentials=":${proxy_random_credentials[$count]}";
      ((count+=1))
    fi;
    # Р СџР ВµРЎР‚Р Р†Р В°РЎРЏ Р В·Р В°Р С—Р С‘РЎРѓРЎРЉ Р С—Р ВµРЎР‚Р ВµР В·Р В°Р С—Р С‘РЎРѓРЎвЂ№Р Р†Р В°Р ВµРЎвЂљ РЎвЂћР В°Р в„–Р В» (>), Р С•РЎРѓРЎвЂљР В°Р В»РЎРЉР Р…РЎвЂ№Р Вµ Р Т‘Р С•Р В±Р В°Р Р†Р В»РЎРЏРЎР‹РЎвЂљ (>>)
    if [ "$proxies_type" = "dual" ]; then
      # Wave HTTP.A — dual emits TWO self-describing URI lines per IP so
      # the node-agent reports both with an explicit protocol tag:
      #   socks5://login:pass@ipv4:<socks_port>
      #   http://login:pass@ipv4:<http_port>   (http_port = socks_port - 10000)
      # proxy_credentials is ":login:pass" → strip the leading ':'.
      local creds="${proxy_credentials#:}";
      local http_port=$((port - 10000));
      if [ "$first_line" = true ]; then
        echo "socks5://${creds}@$backconnect_ipv4:$port" > $backconnect_proxies_file;
        first_line=false;
      else
        echo "socks5://${creds}@$backconnect_ipv4:$port" >> $backconnect_proxies_file;
      fi;
      echo "http://${creds}@$backconnect_ipv4:$http_port" >> $backconnect_proxies_file;
    elif [ "$first_line" = true ]; then
      echo "$backconnect_ipv4:$port$proxy_credentials" > $backconnect_proxies_file;
      first_line=false;
    else
      echo "$backconnect_ipv4:$port$proxy_credentials" >> $backconnect_proxies_file;
    fi;
  done;
}

function write_port_ipv6_map_file() {
  rm -f $port_ipv6_map_file;

  if ! test -f $random_ipv6_list_file; then
    log_err "РІС™В РїС‘РЏ Warning: cannot create port-to-IPv6 map file, IPv6 list file not found";
    return;
  fi;

  if ! touch $port_ipv6_map_file &> $script_log_file; then
    log_err "РІС™В РїС‘РЏ Warning: provided invalid path to port-to-IPv6 map file";
    return;
  fi;

  echo "port,ipv6,backconnect_ipv4,instance_id" > $port_ipv6_map_file;

  local port=$start_port;
  while IFS= read -r ipv6_address; do
    if [ -z "$ipv6_address" ]; then continue; fi;
    echo "$port,$ipv6_address,$backconnect_ipv4,$instance_id" >> $port_ipv6_map_file;
    # Wave HTTP.A — dual: persist the paired http port (socks - 10000) for
    # the SAME IPv6 so a reboot/restore rebuilds BOTH listeners.
    if [ "$proxies_type" = "dual" ]; then
      echo "$((port - 10000)),$ipv6_address,$backconnect_ipv4,$instance_id" >> $port_ipv6_map_file;
    fi;
    ((port+=1))
    if [ $port -gt $last_port ]; then break; fi;
  done < $random_ipv6_list_file
}

function write_proxyserver_info() {
  delete_file_if_exists $proxyserver_info_file;

  cat > $proxyserver_info_file <<-EOF
Proxy Server Information:
  Proxy count: $proxy_count
  Proxy type: $proxies_type
  IPv6 policy: $ipv6_policy
  IP preference mode: $ip_preference_mode
  Maxconn: $proxy_maxconn (listen backlog $((proxy_maxconn / 16 + 1)))
  DNS selection strategy: $dns_selection_strategy
  DNS servers: $dns_selected_servers_csv
  Proxy IP: $(get_backconnect_ipv4)
  Proxy ports: $start_port - $last_port
  Auth: $(if is_auth_used; then if [ $use_random_auth = true ]; then echo "random user/password for each proxy"; else echo "user - $user, password - $password"; fi; else echo "disabled"; fi;)
  Rules: $(if ([ -n "$denied_hosts" ] || [ -n "$allowed_hosts" ]); then if [ -n "$denied_hosts" ]; then echo "denied hosts - $denied_hosts, all others are allowed"; else echo "allowed hosts - $allowed_hosts, all others are denied"; fi; else echo "no rules specified, all hosts are allowed"; fi;)
  File with backconnect proxy list: $backconnect_proxies_file
  File with port-to-IPv6 map: $port_ipv6_map_file

Technical Information:
  Subnet: /$subnet
  Subnet mask: $subnet_mask
  File with generated IPv6 gateway addresses: $random_ipv6_list_file
  $(if [ $rotating_interval -ne 0 ]; then echo "Rotating interval: every $rotating_interval minutes"; else echo "Rotating: disabled"; fi;)
EOF
}

function cleanup_nftables_rules() {
  echo "СЂСџВ§в„– Cleaning up nftables rules for ports $start_port-$last_port..."
  
  if ! command -v nft &> /dev/null; then
    echo "   РІС™В РїС‘РЏ nftables not installed, skipping cleanup"
    return
  fi
  
  # Read IPv6 addresses if file exists
  local ipv6_addresses=()
  if [ -f "$random_ipv6_list_file" ]; then
    readarray -t ipv6_addresses < "$random_ipv6_list_file"
  fi
  
  local cleaned_count=0
  
  for ((i=0; i<proxy_count; i++)); do
    local port=$((start_port + i))
    local ipv6="${ipv6_addresses[$i]}"
    
    # Delete IPv4 INPUT rules (by port)
    nft delete rule inet proxy_accounting input tcp dport "$port" 2>/dev/null && cleaned_count=$((cleaned_count + 1)) || true
    
    # Delete IPv6 rules (by address, not port!)
    if [ -n "$ipv6" ]; then
      nft delete rule inet proxy_accounting output ip6 saddr "$ipv6" 2>/dev/null && cleaned_count=$((cleaned_count + 1)) || true
      nft delete rule inet proxy_accounting input ip6 daddr "$ipv6" 2>/dev/null && cleaned_count=$((cleaned_count + 1)) || true
    fi
    
    # Show progress
    if [ $((i % 100)) -eq 0 ] && [ "$i" -gt 0 ]; then
      echo "   [PROGRESS] Cleaned $i/$proxy_count proxies..."
    fi
  done
  
  echo "РІСљвЂ¦ Cleaned $cleaned_count nftables rules"
  
  # Save nftables state
  nft list ruleset > /etc/nftables.conf 2>/dev/null || true
}

function cleanup_iptables_rules() {
  echo "СЂСџВ§в„– Cleaning up iptables rules for ports $start_port-$last_port..."
  
  local cleaned_count=0
  
  for ((i=0; i<proxy_count; i++)); do
    local port=$((start_port + i))
    
    # Delete iptables rules
    iptables -w 2 -D INPUT -p tcp --dport "$port" -j PROXY_ACCOUNTING 2>/dev/null && cleaned_count=$((cleaned_count + 1)) || true
    iptables -w 2 -D OUTPUT -p tcp --sport "$port" -j PROXY_ACCOUNTING 2>/dev/null && cleaned_count=$((cleaned_count + 1)) || true
    iptables -w 2 -D PROXY_ACCOUNTING -p tcp --dport "$port" -j RETURN 2>/dev/null && cleaned_count=$((cleaned_count + 1)) || true
    iptables -w 2 -D PROXY_ACCOUNTING -p tcp --sport "$port" -j RETURN 2>/dev/null && cleaned_count=$((cleaned_count + 1)) || true
    
    # IPv6
    ip6tables -w 2 -D INPUT -p tcp --dport "$port" -j PROXY_ACCOUNTING 2>/dev/null && cleaned_count=$((cleaned_count + 1)) || true
    ip6tables -w 2 -D OUTPUT -p tcp --sport "$port" -j PROXY_ACCOUNTING 2>/dev/null && cleaned_count=$((cleaned_count + 1)) || true
    ip6tables -w 2 -D PROXY_ACCOUNTING -p tcp --dport "$port" -j RETURN 2>/dev/null && cleaned_count=$((cleaned_count + 1)) || true
    ip6tables -w 2 -D PROXY_ACCOUNTING -p tcp --sport "$port" -j RETURN 2>/dev/null && cleaned_count=$((cleaned_count + 1)) || true
    
    # Show progress
    if [ $((i % 100)) -eq 0 ] && [ "$i" -gt 0 ]; then
      echo "   [PROGRESS] Cleaned $i/$proxy_count ports..."
    fi
  done
  
  echo "РІСљвЂ¦ Cleaned $cleaned_count iptables rules"
  
  # Save iptables state
  iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
  ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
}

# Handle uninstall command
if [ $uninstall = true ]; then
  if ! is_proxyserver_installed; then log_err_and_exit "Proxy server is not installed"; fi;

  remove_from_cron;
  kill_3proxy;
  remove_ipv6_addresses_from_iface;
  close_ufw_backconnect_ports;
  
  # Cleanup traffic counters (both nftables and iptables for compatibility)
  cleanup_nftables_rules;
  cleanup_iptables_rules;
  
  rm -rf $proxy_dir;
  delete_file_if_exists $backconnect_proxies_file;
  echo -e "\nРІСљвЂ¦ IPv6 proxy server successfully uninstalled. If you want to reinstall, just run this script again.";
  exit 0;
fi;

# Handle info command
if [ $print_info = true ]; then
  if ! is_proxyserver_installed; then log_err_and_exit "Proxy server isn't installed"; fi;
  if ! is_proxyserver_running; then log_err_and_exit "Proxy server isn't running. You can check log of previous run attempt in $script_log_file"; fi;
  if ! test -f $proxyserver_info_file; then log_err_and_exit "File with information about running proxy server not found"; fi;

  cat $proxyserver_info_file;
  exit 0;
fi;

# === MAIN INSTALLATION ===
echo "РІвЂўвЂќРІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўвЂ”"
echo "РІвЂўвЂ          IPv6 Proxy Server Installer (Automated)             РІвЂўвЂ"
echo "РІвЂўвЂ              Using 3proxy Backend (MULTI-INSTANCE)           РІвЂўвЂ"
echo "РІвЂўвЂ           Old proxies are preserved on new generation!       РІвЂўвЂ"
echo "РІвЂўС™РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўСњ"
echo ""
echo "СЂСџвЂњРЉ Instance ID: $instance_id (based on start_port)"
echo ""

delete_file_if_exists $script_log_file;

echo "СЂСџвЂќРЊ Checking startup parameters..."
check_startup_parameters;

if [ "$verify_bootstrap" = true ]; then
  verify_bootstrap_or_exit;
  exit 0;
fi;

if [ "$runtime_only" = true ]; then
  bootstrap_side_effects_allowed=false
  echo "Runtime-only mode enabled: bootstrap side-effects are disabled."
  verify_bootstrap_or_exit;
else
  if ! grep -Eq '^\* hard nofile 999999$' /etc/security/limits.conf; then echo "* hard nofile 999999" >> /etc/security/limits.conf; fi;
  if ! grep -Eq '^\* soft nofile 999999$' /etc/security/limits.conf; then echo "* soft nofile 999999" >> /etc/security/limits.conf; fi;
  # Disable firewalld if present
  systemctl stop firewalld 2>/dev/null || true
  systemctl disable firewalld 2>/dev/null || true
fi;

# Audit CLN-03 — no TCP/IP profile here any more: the generator used to write
# /etc/sysctl.conf (applied AFTER /etc/sysctl.d, so its tcp_timestamps=0 default
# silently beat the production value) outside --runtime-only. The TCP stack is
# set ONLY by install_node_v2.sh (deploy/node/99-zz-netrun-tcp.conf).

echo "СЂСџвЂќРЊ Checking IPv6 configuration..."
check_ipv6;

if is_proxyserver_installed; then
  echo -e "РІС™В РїС‘РЏ Proxy server already installed, reconfiguring:\n";
else
  # Audit CLN-03 — the generator no longer downloads and builds 3proxy (the
  # GitHub path built 0.9.4; nodes run the audited bundled 0.9.3).
  log_err_and_exit "3proxy is not installed in $proxy_dir. Install the node with install_node_v2.sh (it ships the bundled 3proxy 0.9.3).";
fi;
if [ ! -x "$proxy_dir/3proxy/bin/3proxy" ]; then
  log_err_and_exit "Error: bundled 3proxy binary missing at $proxy_dir/3proxy/bin/3proxy (install_node_v2.sh installs deploy/node/bin/3proxy).";
fi;

echo "СЂСџРЉС’ Getting backconnect IPv4 address..."
if [ "$bootstrap_only" = true ]; then
  echo "Bootstrap-only mode: applying nftables baseline..."
  ensure_nftables_ready;
  nft add table inet proxy_accounting 2>/dev/null || true
  nft add chain inet proxy_accounting input '{ type filter hook input priority 0; policy accept; }' 2>/dev/null || true
  nft add chain inet proxy_accounting output '{ type filter hook output priority 0; policy accept; }' 2>/dev/null || true
  write_bootstrap_marker;
  verify_bootstrap_or_exit;
  echo "Bootstrap-only mode completed."
  exit 0;
fi;

backconnect_ipv4=$(get_backconnect_ipv4);
echo "   Using: $backconnect_ipv4"

echo "Checking that the batch ports are free (one ss snapshot)..."
check_ports_not_listening;

echo "СЂСџВ§В­ Selecting DNS resolvers..."
configure_dns_servers;

echo "СЂСџвЂќС’ Generating authentication credentials..."
generate_random_users_if_needed;

echo "СЂСџРЉС’ Generating IPv6 addresses..."
generate_ipv6_addresses_if_needed;

echo "СЂСџвЂњСњ Creating startup script..."
create_startup_script;

echo "РІРЏВ° Adding to cron..."
add_to_cron;

echo "СЂСџвЂќТђ Opening firewall ports..."
open_ufw_backconnect_ports;

if [ "$runtime_only" != true ]; then
  write_bootstrap_marker;
fi;

echo "СЂСџвЂњР‰ Setting up nftables traffic counters (client-port based)..."
setup_nftables_counters;

echo "СЂСџС™Р‚ Starting proxy server..."
run_proxy_server;

echo "СЂСџвЂ™С• Writing proxy list to file..."
write_backconnect_proxies_to_file;

echo "СЂСџвЂ”С”РїС‘РЏ Writing port-to-IPv6 map file..."
write_port_ipv6_map_file;

echo "СЂСџвЂњвЂ№ Writing server info..."
write_proxyserver_info;

# Output proxies in API-compatible format
echo ""
echo "--- Generated Proxies ---"
cat $backconnect_proxies_file

echo ""
echo "РІвЂўвЂќРІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўвЂ”"
echo "РІвЂўвЂ                  РІСљвЂ¦ Installation Complete!                   РІвЂўвЂ"
echo "РІвЂўС™РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўС’РІвЂўСњ"
echo "РІР‚Сћ Proxy Type: $proxies_type"
echo "РІР‚Сћ IPv6 Policy: $ipv6_policy"
echo "РІР‚Сћ IP Preference Mode: $ip_preference_mode"
echo "РІР‚Сћ DNS Selection Strategy: $dns_selection_strategy"
echo "РІР‚Сћ DNS Servers: $dns_selected_servers_csv"
echo "РІР‚Сћ Maxconn: $proxy_maxconn (listen backlog $((proxy_maxconn / 16 + 1)))"
echo "РІР‚Сћ Proxy Count: $proxy_count"
echo "РІР‚Сћ Port Range: $start_port-$last_port"
echo "РІР‚Сћ Backconnect IP: $backconnect_ipv4"
echo "РІР‚Сћ Proxy List File: $backconnect_proxies_file"
echo "РІР‚Сћ PortРІвЂ вЂќIPv6 Map File: $port_ipv6_map_file"
echo "РІР‚Сћ Instance ID: $instance_id"
echo "РІР‚Сћ Config File: 3proxy_${instance_id}.cfg"
echo "РІР‚Сћ Mode: MULTI-INSTANCE (old proxies preserved)"
echo ""

exit 0
