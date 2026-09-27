#!/bin/bash

# AUTOMATED IPv6 Proxy Server Installer (Non-Interactive)
# Based on proxyyy.sh but adapted for API usage

# Script must be running from root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Program help info for users
function usage() { echo "Usage: $0 [-s | --subnet <16|32|48|64|80|96|112> proxy subnet (default 64)] 
                          [-c | --proxy-count <number> count of proxies] 
                          [-u | --username <string> proxy auth username] 
                          [-p | --password <string> proxy password]
                          [--random <bool> generate random username/password for each IPv4 backconnect proxy instead of predefined (default false)] 
                          [-t | --proxies-type <http|socks5|dual> result proxies type (default socks5; 'dual' = socks5 + paired http on port-10000)]
                          [-r | --rotating-interval <0-59> proxies external address rotating time in minutes (default 0, disabled)]
                          [--start-port <5000-65536> start port for backconnect ipv4 (default 30000)]
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
                           [--dns-country <auto|ISO2> DNS region for upstream resolvers (default auto by backconnect IP)]
                          [--dns-servers <ip1,ip2> explicit upstream DNS resolvers override]
                           [--network-profile <standard_nat|residential_like|high_compatibility> edge TCP/IP profile (default standard_nat)]
                           [--tcp-timestamps-mode <auto|on|off> explicit TCP timestamps mode override (default auto)]
                           [--maxconn <number> 3proxy maxconn for this instance (default 200)]
                           [--ipv6-policy <strict_dual_stack|ipv6_required|ipv6_only> egress family policy (default strict_dual_stack)]
                            [--skip-self-check <bool> disable post-start dual-stack self-check (default false)]
                           [--self-check-samples <number> number of first proxies to test for policy self-check (default 1)]
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
run_self_check=true
self_check_samples=1
ip_preference_mode="compat_ipv6_first"
dns_country="auto"
dns_servers_override=""
network_profile="standard_nat"
tcp_timestamps_mode="auto"
ipv6_policy="strict_dual_stack"
proxy_maxconn=200
proxy_count=1
dns_selected_country="fallback"
dns_selected_servers_csv="127.0.0.1,::1"
dns_selection_strategy="local_unbound"
dns_nserver_lines=$'  nserver 127.0.0.1\n  nserver ::1'
tls_clienthello_mode="passthrough"
bootstrap_only=false
runtime_only=false
verify_bootstrap=false
bootstrap_side_effects_allowed=true

profile_ttl=64
profile_mss_mode="set"
profile_mss_value=1460
profile_mtu_hint=1500
profile_tcp_timestamps=0
profile_tcp_syn_retries=3
profile_tcp_retries2=10
profile_tcp_fin_timeout=30
profile_tcp_keepalive_time=7200

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
    --dns-country ) dns_country="$2"; shift 2 ;;
    --dns-servers ) dns_servers_override="$2"; shift 2 ;;
    --network-profile ) network_profile="$2"; shift 2 ;;
    --tcp-timestamps-mode ) tcp_timestamps_mode="$2"; shift 2 ;;
    --ipv6-policy ) ipv6_policy="$2"; shift 2 ;;
    --maxconn ) proxy_maxconn="$2"; shift 2 ;;
    --skip-self-check ) run_self_check=false; shift ;;
    --self-check-samples ) self_check_samples="$2"; shift 2 ;;
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

if [ "$bootstrap_only" = true ] || [ "$verify_bootstrap" = true ]; then
  run_self_check=false
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

  if ! [[ $self_check_samples =~ $re ]]; then
    log_err_print_usage_and_exit "Error: '--self-check-samples' must be a non-negative integer number";
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

  # Wave HTTP.A — for dual the http port = socks port - 10000, so the
  # socks start_port must leave room above 5000 for the http range.
  if [ $proxies_type = "dual" ] && [ $start_port -lt 15000 ]; then
    log_err_print_usage_and_exit "Error: for '--proxies-type dual' '--start-port' must be >= 15000 (http port = socks port - 10000, must stay >= 5000)";
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

  if [ $start_port -lt 5000 ] || (($start_port + $proxy_count > 65536)); then
    log_err_print_usage_and_exit "Wrong '--start-port' parameter value, it must be more than 5000 and '--start-port' + '--proxy-count' must be lower than 65536";
  fi;

  if [ ! -z $backconnect_ipv4 ]; then
    if ! is_valid_ip $backconnect_ipv4; then
      log_err_and_exit "Error: ip provided in 'backconnect-ip' argument is invalid. Provide valid IP or don't use this argument"
    fi;
  fi;

  if [ -n "$allowed_hosts" ] && [ -n "$denied_hosts" ]; then
    log_err_print_usage_and_exit "Error: if '--allow-hosts' is specified, you cannot use '--deny-hosts'";
  fi;

  if [ "$dns_country" != "auto" ] && ! [[ "$dns_country" =~ ^[A-Za-z]{2}$ ]]; then
    log_err_print_usage_and_exit "Error: '--dns-country' must be 'auto' or 2-letter ISO country code (example: US)";
  fi;

  if [ "$network_profile" != "standard_nat" ] && [ "$network_profile" != "residential_like" ] && [ "$network_profile" != "high_compatibility" ]; then
    log_err_print_usage_and_exit "Error: '--network-profile' must be one of: standard_nat, residential_like, high_compatibility";
  fi;

  if [ "$tcp_timestamps_mode" != "auto" ] && [ "$tcp_timestamps_mode" != "on" ] && [ "$tcp_timestamps_mode" != "off" ]; then
    log_err_print_usage_and_exit "Error: '--tcp-timestamps-mode' must be one of: auto, on, off";
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

function resolve_network_profile_settings() {
  case "$network_profile" in
    standard_nat)
      profile_ttl=64
      profile_mss_mode="set"
      profile_mss_value=1460
      profile_mtu_hint=1500
      profile_tcp_timestamps=0
      profile_tcp_syn_retries=3
      profile_tcp_retries2=10
      profile_tcp_fin_timeout=30
      profile_tcp_keepalive_time=7200
      ;;
    residential_like)
      profile_ttl=64
      profile_mss_mode="clamp_pmtu"
      profile_mss_value=1460
      profile_mtu_hint=1500
      profile_tcp_timestamps=1
      profile_tcp_syn_retries=4
      profile_tcp_retries2=12
      profile_tcp_fin_timeout=40
      profile_tcp_keepalive_time=5400
      ;;
    high_compatibility)
      profile_ttl=64
      profile_mss_mode="clamp_pmtu"
      profile_mss_value=1460
      profile_mtu_hint=1500
      profile_tcp_timestamps=1
      profile_tcp_syn_retries=5
      profile_tcp_retries2=15
      profile_tcp_fin_timeout=45
      profile_tcp_keepalive_time=3600
      ;;
  esac

  if [ "$tcp_timestamps_mode" = "on" ]; then
    profile_tcp_timestamps=1
  elif [ "$tcp_timestamps_mode" = "off" ]; then
    profile_tcp_timestamps=0
  fi
}

function set_sysctl_option() {
  local key="$1"
  local value="$2"
  local escaped_key="${key//./\\.}"

  if grep -Eq "^[[:space:]]*${escaped_key}[[:space:]]*=" /etc/sysctl.conf; then
    sed -i -E "s|^[[:space:]]*${escaped_key}[[:space:]]*=.*$|${key} = ${value}|g" /etc/sysctl.conf
  else
    echo "${key} = ${value}" >> /etc/sysctl.conf
  fi
}

function apply_network_profile_sysctl() {
  local sysctl_options=(
    "net.ipv4.route.min_adv_mss=${profile_mss_value}"
    "net.ipv4.tcp_mtu_probing=1"
    "net.ipv4.tcp_timestamps=${profile_tcp_timestamps}"
    "net.ipv4.tcp_window_scaling=1"
    "net.ipv4.tcp_sack=1"
    "net.ipv4.icmp_echo_ignore_all=1"
    "net.ipv4.tcp_max_syn_backlog=4096"
    "net.ipv4.conf.all.forwarding=1"
    "net.ipv4.ip_nonlocal_bind=1"
    "net.ipv6.conf.all.proxy_ndp=1"
    "net.ipv6.conf.default.forwarding=1"
    "net.ipv6.conf.all.forwarding=1"
    "net.ipv6.ip_nonlocal_bind=1"
    "net.ipv4.ip_default_ttl=${profile_ttl}"
    "net.ipv4.tcp_syn_retries=${profile_tcp_syn_retries}"
    "net.ipv4.tcp_retries2=${profile_tcp_retries2}"
    "net.ipv4.tcp_fin_timeout=${profile_tcp_fin_timeout}"
    "net.ipv4.tcp_keepalive_time=${profile_tcp_keepalive_time}"
    "net.ipv4.tcp_rmem=4096 87380 6291456"
    "net.ipv4.tcp_wmem=4096 16384 6291456"
  )

  for option in "${sysctl_options[@]}"; do
    local key="${option%%=*}"
    local value="${option#*=}"
    set_sysctl_option "$key" "$value"
  done

  if ! sysctl -p &>> $script_log_file; then
    log_err_and_exit "Error: cannot apply TCP/IP sysctl profile";
  fi
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

function is_any_proxyserver_running() {
  # Check if ANY 3proxy instance is running
  if ps aux | grep -v grep | grep -q "3proxy"; then return 0; else return 1; fi;
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
    if ! nft list table inet proxy_normalization > /dev/null 2>&1; then
      ready=false
      if [ "$print_report" = true ]; then echo " - nft table inet proxy_normalization is missing"; fi;
    fi;
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
  "network_profile": "$network_profile",
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

function detect_country_code_by_ip() {
  local ip="$1"
  local detected=""

  if ! command -v curl &> /dev/null; then install_package "curl"; fi;

  detected=$(curl -4 -sS --max-time 8 "https://ipapi.co/${ip}/country/" 2>/dev/null | tr -d '\r\n[:space:]')
  if [[ "$detected" =~ ^[A-Za-z]{2}$ ]]; then
    echo "${detected^^}"
    return 0
  fi;

  detected=$(curl -4 -sS --max-time 8 "https://ipwho.is/${ip}" 2>/dev/null | grep -m1 -oP '"country_code":"\K[A-Z]{2}' || true)
  if [[ "$detected" =~ ^[A-Z]{2}$ ]]; then
    echo "$detected"
    return 0
  fi;

  detected=$(curl -4 -sS --max-time 8 "https://ipinfo.io/${ip}/country" 2>/dev/null | tr -d '\r\n[:space:]')
  if [[ "$detected" =~ ^[A-Za-z]{2}$ ]]; then
    echo "${detected^^}"
    return 0
  fi;

  return 1
}

function source_dns_selector_or_die() {
  # Locate dns/select_dns.sh (shared with scripts/migrate_dns_inplace.sh).
  local gen_dir=""
  gen_dir=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")" 2>/dev/null && pwd -P 2>/dev/null) || gen_dir=""
  local candidates=(
    "${NETRUN_HOME:-/opt/netrun}/dns/select_dns.sh"
    "/opt/netrun/dns/select_dns.sh"
    "${gen_dir}/../../dns/select_dns.sh"
    "${gen_dir}/../../../dns/select_dns.sh"
  )
  local p=""
  for p in "${candidates[@]}"; do
    if [ -n "$p" ] && [ -f "$p" ]; then
      # shellcheck disable=SC1090
      source "$p"
      return 0
    fi;
  done
  return 1
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
      dns_selected_country="manual"
      dns_selected_servers_csv="${dns_override_1},${dns_override_2}"
      dns_selection_strategy="manual_override"
      echo "   DNS selected (manual_override): ${dns_selected_servers_csv}"
      return
    else
      log_err_print_usage_and_exit "Error: '--dns-servers' must contain two valid IPv4 or IPv6 resolvers as 'ip1,ip2'";
    fi;
  fi;

  # --- Default: local recursive resolver (unbound on 127.0.0.1) ---
  # This 3proxy build honors the cfg `nserver`, and every node runs a local
  # unbound (install_node_v2 → configure_unbound). Pointing nserver at it makes
  # DNS egress from the node itself (resolver IP == exit IP) — no Cloudflare /
  # third-party leak, geo/ASN-consistent. Override with --dns-servers if needed.
  dns_nserver_lines="  nserver 127.0.0.1"$'\n'"  nserver ::1"
  dns_selected_country="local"
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

function install_requred_packages() {
  apt update &>> $script_log_file;

  requred_packages=("make" "g++" "wget" "curl" "cron");
  for package in ${requred_packages[@]}; do install_package $package; done;

  echo -e "\nРІСљвЂ¦ All required packages installed successfully";
}

function install_3proxy() {
  mkdir $proxy_dir && cd $proxy_dir

  echo -e "\nСЂСџвЂњТђ Downloading proxy server source...";
  (
  wget https://github.com/3proxy/3proxy/archive/refs/tags/0.9.4.tar.gz &> /dev/null
  tar -xf 0.9.4.tar.gz
  rm 0.9.4.tar.gz
  mv 3proxy-0.9.4 3proxy) &>> $script_log_file
  echo "РІСљвЂ¦ Proxy server source code downloaded successfully";

  echo -e "\nСЂСџвЂќРЃ Start building proxy server execution file from source...";
  cd 3proxy
  make -f Makefile.Linux &>> $script_log_file;
  if test -f "$proxy_dir/3proxy/bin/3proxy"; then
    echo "РІСљвЂ¦ Proxy server built successfully"
  else
    log_err_and_exit "Error: proxy server build from source code failed."
  fi;
  cd ..
}

function configure_ipv6() {
  required_options=("conf.$interface_name.proxy_ndp" "conf.all.proxy_ndp" "conf.default.forwarding" "conf.all.forwarding" "ip_nonlocal_bind");
  for option in ${required_options[@]}; do
    set_sysctl_option "net.ipv6.$option" "1";
  done;
  sysctl -p &>> $script_log_file;

  if [[ $(cat /proc/sys/net/ipv6/conf/$interface_name/proxy_ndp) == 1 ]] && [[ $(cat /proc/sys/net/ipv6/ip_nonlocal_bind) == 1 ]]; then
    echo "РІСљвЂ¦ IPv6 network sysctl data configured successfully";
  else
    cat /etc/sysctl.conf &>> $script_log_file;
    log_err_and_exit "Error: cannot configure IPv6 config";
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

function generate_ipv6_addresses_if_needed() {
  # Generate IPv6 addresses early if they don't exist yet
  # This is needed for nftables counter setup
  if [ -f "$random_ipv6_list_file" ]; then
    echo "   Using existing IPv6 addresses from $random_ipv6_list_file"
    return
  fi
  
  echo "   Generating $proxy_count unique IPv6 addresses..."
  
  array=( 1 2 3 4 5 6 7 8 9 0 a b c d e f )
  
  function rh () { echo ${array[$RANDOM%16]}; }
  
  rnd_subnet_ip () {
    echo -n $(get_subnet_mask);
    symbol=$subnet
    while (( $symbol < 128)); do
      if (($symbol % 16 == 0)); then echo -n :; fi;
      echo -n $(rh);
      let "symbol += 4";
    done;
    echo ;
  }
  
  # Wave PERGB-IPV6-FAST: the legacy uniqueness check ran `ip -6 addr show | grep`
  # (O(addresses-on-interface)) for EVERY candidate. With thousands of addresses
  # already bound (a node full of pay-per-GB ports), that is O(N^2) and the
  # generation job timed out partway -> an incomplete IPv6 list ("No IPv6 address
  # for port X"), a broken proxies.list, and a wedged genlock. Snapshot the
  # existing addresses into an associative array ONCE, then check membership O(1).
  declare -A _ip6seen
  while read -r _a; do [ -n "$_a" ] && _ip6seen[$_a]=1; done < <(ip -6 addr show 2>/dev/null | grep -oE 'inet6 [0-9a-f:]+' | sed -E 's/inet6 //')
  count=1
  while [ "$count" -le $proxy_count ]; do
    # Generate unique IPv6 - check it's not already in use (O(1) set lookup)
    new_ipv6=$(rnd_subnet_ip)
    while [ -n "${_ip6seen[$new_ipv6]:-}" ]; do
      new_ipv6=$(rnd_subnet_ip)
    done
    _ip6seen[$new_ipv6]=1
    echo "$new_ipv6" >> $random_ipv6_list_file;
    ((count+=1))
  done
  
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
  local http_listen_ip="$backconnect_ipv4"
  if [ -d /etc/haproxy/netrun.d ]; then http_listen_ip="127.0.0.1"; fi
  local main_listen_ip="$backconnect_ipv4"
  if [ "$proxies_type" = "http" ]; then main_listen_ip="$http_listen_ip"; fi

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

	# Generate IPv6 addresses for THIS instance only
	# NOTE: We do NOT delete old IPv6 list - keep it for persistence
	
	array=( 1 2 3 4 5 6 7 8 9 0 a b c d e f )

	function rh () { echo \${array[\$RANDOM%16]}; }

	rnd_subnet_ip () {
	  echo -n $(get_subnet_mask);
	  symbol=$subnet
	  while (( \$symbol < 128)); do
	    if ((\$symbol % 16 == 0)); then echo -n :; fi;
	    echo -n \$(rh);
	    let "symbol += 4";
	  done;
	  echo ;
	}

	# Only generate new IPv6 if list doesn't exist yet
	if [ ! -f "$random_ipv6_list_file" ]; then
	  count=1
	  while [ "\$count" -le $proxy_count ]
	  do
	    # Generate unique IPv6 - check it's not already in use
	    new_ipv6=\$(rnd_subnet_ip)
	    while ip -6 addr show 2>/dev/null | grep -q "\$new_ipv6"; do
	      new_ipv6=\$(rnd_subnet_ip)
	    done
	    echo "\$new_ipv6" >> $random_ipv6_list_file;
	    ((count+=1))
	  done;
	fi

	immutable_config_part="daemon
$dns_nserver_lines
	  maxconn $proxy_maxconn
	  nscache 65536
	  nscache6 65536
	  timeouts 1 5 30 60 180 1800 15 60
	  setgid 65535
	  setuid 65535"

	auth_part="auth iponly"
	if [ $use_auth -eq 0 ]; then
	  auth_part="
	    auth strong
	    users $user:CL:$password"
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
	      echo "\$access_rules_part" >> $proxyserver_config_path;
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
	
	# Add IPv6 addresses (ignore errors if already exist)
	for ipv6_address in \$(cat ${random_ipv6_list_file}); do 
	  ip -6 addr add \$ipv6_address dev $interface_name 2>/dev/null || true
	done;

	# NOTE: We do NOT kill old proxy processes - each instance is independent!
	
	# Start THIS 3proxy instance as a detached daemon
	nohup ${user_home_dir}/proxyserver/3proxy/bin/3proxy ${proxyserver_config_path} >/dev/null 2>&1 &
	sleep 2  # Wait for daemon to initialize

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

function setup_nftables_edge_normalization() {
  echo "   Applying edge normalization profile: $network_profile"
  echo "   Target TTL/HopLimit: $profile_ttl"
  echo "   MSS mode: $profile_mss_mode (target MSS: $profile_mss_value)"
  echo "   MTU hint: $profile_mtu_hint"

  ensure_nftables_ready

  if [ "$bootstrap_side_effects_allowed" = true ]; then
    nft add table inet proxy_normalization 2>/dev/null || true
    nft add chain inet proxy_normalization output '{ type filter hook output priority -150; policy accept; }' 2>/dev/null || true
    nft add chain inet proxy_normalization postrouting '{ type filter hook postrouting priority -150; policy accept; }' 2>/dev/null || true
  elif ! nft list table inet proxy_normalization > /dev/null 2>&1; then
    log_err_and_exit "nft table inet proxy_normalization is missing. Run bootstrap-only mode first."
  fi;

  nft flush chain inet proxy_normalization output 2>/dev/null || true
  nft flush chain inet proxy_normalization postrouting 2>/dev/null || true

  # Drop clearly invalid combinations before packets leave the node.
  nft add rule inet proxy_normalization output ct state invalid drop 2>/dev/null || true
  nft add rule inet proxy_normalization output 'tcp flags & (fin|syn) == (fin|syn) drop' 2>/dev/null || true
  nft add rule inet proxy_normalization output 'tcp flags & (syn|rst) == (syn|rst) drop' 2>/dev/null || true

  # Suppress fragmented egress traffic for a cleaner NAT signature.
  nft add rule inet proxy_normalization output 'ip frag-off & 0x1fff != 0 drop' 2>/dev/null || true
  nft add rule inet proxy_normalization output 'ip6 nexthdr frag drop' 2>/dev/null || true

  # Normalize outgoing TTL / hop-limit.
  nft add rule inet proxy_normalization postrouting meta l4proto tcp ip ttl set "$profile_ttl" 2>/dev/null || true
  nft add rule inet proxy_normalization postrouting meta l4proto tcp ip6 hoplimit set "$profile_ttl" 2>/dev/null || true

  # Normalize MSS for SYN packets (fixed or PMTU-clamped depending on profile).
  if [ "$profile_mss_mode" = "clamp_pmtu" ]; then
    nft add rule inet proxy_normalization output tcp flags syn tcp option maxseg size set rt mtu 2>/dev/null || true
  else
    nft add rule inet proxy_normalization output tcp flags syn tcp option maxseg size set "$profile_mss_value" 2>/dev/null || true
  fi

  nft list ruleset > /etc/nftables.conf 2>/dev/null || true
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
  nft list chain inet proxy_accounting input  2>/dev/null | grep -q 'map @cmap_in'  || nft add rule inet proxy_accounting input  counter name tcp dport map @cmap_in
  nft list chain inet proxy_accounting output 2>/dev/null | grep -q 'map @cmap_out' || nft add rule inet proxy_accounting output counter name tcp sport map @cmap_out

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

function setup_iptables_counters() {
  # Legacy iptables function - kept for backward compatibility
  # Create PROXY_ACCOUNTING chain if not exists
  iptables -w 2 -N PROXY_ACCOUNTING 2>/dev/null || true
  ip6tables -w 2 -N PROXY_ACCOUNTING 2>/dev/null || true

  # Р СњР Вµ РЎвЂћР В»РЎРЊРЎв‚¬Р С‘РЎР‚РЎС“Р ВµР С Р Р†РЎРѓРЎР‹ РЎвЂ Р ВµР С—Р С•РЎвЂЎР С”РЎС“, РЎвЂЎРЎвЂљР С•Р В±РЎвЂ№ Р Р…Р Вµ Р В»Р С•Р СР В°РЎвЂљРЎРЉ РЎРѓРЎвЂЎРЎвЂРЎвЂљРЎвЂЎР С‘Р С”Р С‘ Р Т‘РЎР‚РЎС“Р С–Р С‘РЎвЂ¦ Р С–Р ВµР Р…Р ВµРЎР‚Р В°РЎвЂ Р С‘Р в„–.
  # Р вЂќР В»РЎРЏ РЎвЂљР ВµР С”РЎС“РЎвЂ°Р ВµР С–Р С• Р Р…Р В°Р В±Р С•РЎР‚Р В° Р С—Р С•РЎР‚РЎвЂљР С•Р Р† РЎРѓР Р…Р В°РЎвЂЎР В°Р В»Р В° Р Р†РЎвЂ№РЎвЂЎР С‘РЎвЂ°Р В°Р ВµР С Р В»РЎР‹Р В±РЎвЂ№Р Вµ Р С—РЎР‚Р В°Р Р†Р С‘Р В»Р В° Р Р…Р В° РЎРЊРЎвЂљР С‘ Р С—Р С•РЎР‚РЎвЂљРЎвЂ№
  # (Р Р†Р С”Р В»РЎР‹РЎвЂЎР В°РЎРЏ РЎРѓРЎвЂљР В°РЎР‚РЎвЂ№Р Вµ ACCEPT/RETURN Р В±Р ВµР В· Р С”Р С•Р СР СР ВµР Р…РЎвЂљР В°РЎР‚Р С‘Р ВµР Р†), Р С—Р С•РЎвЂљР С•Р С РЎРѓРЎвЂљР В°Р Р†Р С‘Р С Р С—РЎР‚Р В°Р Р†Р С‘Р В»РЎРЉР Р…РЎвЂ№Р Вµ.

  echo "   Setting up traffic counters for all proxy ports (iptables - LEGACY)"
  echo "   Strategy: INSERT rules at position 1 (before ufw/firewall rules)"
  echo "   IPv4 INPUT (--dport): client -> proxy (bytesIn)"
  echo "   IPv6 INPUT (--dport): client -> proxy (if IPv6 clients)"
  echo "   IPv6 OUTPUT (--sport): proxy -> internet (bytesOut)"
  
  local added_count=0
  local skipped_count=0
  
  for ((i=0; i<proxy_count; i++)); do
    local port=$((start_port + i))
    
    # Р СџР С•Р В»Р Р…Р С•Р Вµ РЎС“Р Т‘Р В°Р В»Р ВµР Р…Р С‘Р Вµ Р В»РЎР‹Р В±РЎвЂ№РЎвЂ¦ РЎРѓРЎвЂљР В°РЎР‚РЎвЂ№РЎвЂ¦ Р С—РЎР‚Р В°Р Р†Р С‘Р В» Р С—Р С•Р Т‘ РЎРЊРЎвЂљР С•РЎвЂљ Р С—Р С•РЎР‚РЎвЂљ (v4/v6, dport/sport, Р В»РЎР‹Р В±РЎвЂ№Р Вµ РЎвЂљР В°РЎР‚Р С–Р ВµРЎвЂљРЎвЂ№)
    while iptables  -w 2 -D PROXY_ACCOUNTING -p tcp --dport "$port"  -j RETURN 2>/dev/null; do :; done
    while iptables  -w 2 -D PROXY_ACCOUNTING -p tcp --sport "$port"  -j RETURN 2>/dev/null; do :; done
    while iptables  -w 2 -D PROXY_ACCOUNTING -p tcp --dport "$port"  2>/dev/null; do :; done
    while iptables  -w 2 -D PROXY_ACCOUNTING -p tcp --sport "$port"  2>/dev/null; do :; done

    while ip6tables -w 2 -D PROXY_ACCOUNTING -p tcp --dport "$port" -j RETURN 2>/dev/null; do :; done
    while ip6tables -w 2 -D PROXY_ACCOUNTING -p tcp --sport "$port" -j RETURN 2>/dev/null; do :; done
    while ip6tables -w 2 -D PROXY_ACCOUNTING -p tcp --dport "$port" 2>/dev/null; do :; done
    while ip6tables -w 2 -D PROXY_ACCOUNTING -p tcp --sport "$port" 2>/dev/null; do :; done

    # Р вЂќР С•Р В±Р В°Р Р†Р В»РЎРЏР ВµР С Р С”Р С•РЎР‚РЎР‚Р ВµР С”РЎвЂљР Р…РЎвЂ№Р Вµ RETURN РЎРѓ Р С”Р С•Р СР СР ВµР Р…РЎвЂљР В°РЎР‚Р С‘РЎРЏР СР С‘ (РЎвЂљР С•, РЎвЂЎРЎвЂљР С• РЎвЂЎР С‘РЎвЂљР В°Р ВµРЎвЂљ Р С—Р В°Р Р…Р ВµР В»РЎРЉ)
    iptables  -w 2 -A PROXY_ACCOUNTING -p tcp --dport "$port" -m comment --comment "proxy_$port"       -j RETURN 2>/dev/null || true
    iptables  -w 2 -A PROXY_ACCOUNTING -p tcp --sport "$port" -m comment --comment "proxy_${port}_out" -j RETURN 2>/dev/null || true
    ip6tables -w 2 -A PROXY_ACCOUNTING -p tcp --sport "$port" -m comment --comment "proxy_${port}_out" -j RETURN 2>/dev/null || true
    
    # CRITICAL: APPEND jump rules (avoid conflicts with multiple proxy instances)
    # Use APPEND instead of INSERT to avoid position conflicts
    
    # IPv4 INPUT: Delete old rule (if exists), then APPEND (bytesIn)
    iptables -w 2 -D INPUT -p tcp --dport "$port" -j PROXY_ACCOUNTING 2>/dev/null || true
    iptables -w 2 -A INPUT -p tcp --dport "$port" -j PROXY_ACCOUNTING 2>/dev/null || true

    # IPv4 OUTPUT (fallback): Delete old rule (if exists), then APPEND
    iptables -w 2 -D OUTPUT -p tcp --sport "$port" -j PROXY_ACCOUNTING 2>/dev/null || true
    iptables -w 2 -A OUTPUT -p tcp --sport "$port" -j PROXY_ACCOUNTING 2>/dev/null || true
    
    # IPv6 INPUT: Delete old rule (if exists), then APPEND
    ip6tables -w 2 -D INPUT -p tcp --dport "$port" -j PROXY_ACCOUNTING 2>/dev/null || true
    ip6tables -w 2 -A INPUT -p tcp --dport "$port" -j PROXY_ACCOUNTING 2>/dev/null || true
    
    # IPv6 OUTPUT (primary): Delete old rule (if exists), then APPEND
    ip6tables -w 2 -D OUTPUT -p tcp --sport "$port" -j PROXY_ACCOUNTING 2>/dev/null || true
    ip6tables -w 2 -A OUTPUT -p tcp --sport "$port" -j PROXY_ACCOUNTING 2>/dev/null || true
    
    # Show progress every 100
    if [ $((i % 100)) -eq 0 ] && [ "$i" -gt 0 ]; then
      echo "   [PROGRESS] Setup $i/$proxy_count counters..."
    fi
  done
  
  echo "РІСљвЂ¦ Setup $added_count new iptables counters (skipped $skipped_count existing)"
  echo "   Rules inserted at position 1 (before firewall rules)"
  
  # === SAVE IPTABLES RULES (persistent across reboots) ===
  echo "СЂСџвЂ™С• Saving iptables rules for persistence..."
  
  # Create directories if they don't exist
  mkdir -p /etc/iptables 2>/dev/null || true
  
  if command -v iptables-save &> /dev/null; then
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || iptables-save > /etc/iptables.rules 2>/dev/null || true
    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || ip6tables-save > /etc/ip6tables.rules 2>/dev/null || true
    echo "   РІСљвЂ¦ iptables rules saved"
    
    # Install iptables-persistent if not already installed (for auto-restore on reboot)
    if ! dpkg -l 2>/dev/null | grep -q iptables-persistent; then
      echo "   СЂСџвЂњВ¦ Installing iptables-persistent for auto-restore on reboot..."
      DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent > /dev/null 2>&1 || true
    fi
  else
    echo "   РІС™В РїС‘РЏ  iptables-save not found, rules may not persist after reboot"
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
      
      # Verify ports are actually listening
      local ports_ok=0
      local ports_fail=0
      echo "   Checking ports..."
      
      for ((p=$start_port; p<=$last_port; p++)); do
        if ss -ltn 2>/dev/null | grep -qE ":${p}(\s|$|:)"; then
          ((ports_ok++))
        else
          ((ports_fail++))
        fi
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

function run_dualstack_self_check() {
  if [ $run_self_check != true ]; then
    echo "Skipping policy self-check (--skip-self-check)";
    return;
  fi;

  if [ $self_check_samples -eq 0 ]; then
    echo "Skipping policy self-check (samples=0)";
    return;
  fi;

  if ! test -f $random_ipv6_list_file; then
    log_err_and_exit "Error: cannot run self-check, IPv6 list file not found";
  fi;

  if ! command -v curl &> /dev/null; then install_package "curl"; fi;

  local samples_to_test=$self_check_samples;
  if [ $samples_to_test -gt $proxy_count ]; then samples_to_test=$proxy_count; fi;

  local use_auth_for_checks=false;
  is_auth_used;
  if [ $? -eq 0 ]; then use_auth_for_checks=true; fi;

  local proxy_scheme="socks5h";
  if [ "$proxies_type" = "http" ]; then proxy_scheme="http"; fi;

  local require_ipv4_fallback=true
  if [ "$ipv6_policy" = "ipv6_only" ]; then
    require_ipv4_fallback=false
  fi;

  readarray -t expected_ipv6_addresses < $random_ipv6_list_file;
  if [ $use_random_auth = true ] && [ $use_auth_for_checks = true ]; then
    readarray -t proxy_random_credentials < $random_users_list_file;
  fi;

  echo "Running $ipv6_policy self-check for $samples_to_test proxy(s)..."

  local passed_count=0;
  for ((idx=0; idx<samples_to_test; idx++)); do
    local test_port=$((start_port + idx));
    local expected_ipv6="${expected_ipv6_addresses[$idx]}";
    local test_user="$user";
    local test_password="$password";

    if [ $use_random_auth = true ] && [ $use_auth_for_checks = true ]; then
      IFS=':' read -r test_user test_password <<< "${proxy_random_credentials[$idx]}";
      IFS=$' \t\n';
    fi;

    local proxy_url="${proxy_scheme}://${backconnect_ipv4}:${test_port}";
    local ipv6_result="";
    local ipv4_result="";

    if [ $use_auth_for_checks = true ]; then
      ipv6_result=$(curl --max-time 20 -sS --proxy "$proxy_url" --proxy-user "${test_user}:${test_password}" https://api64.ipify.org 2>/dev/null || true);
      ipv4_result=$(curl --max-time 20 -sS --proxy "$proxy_url" --proxy-user "${test_user}:${test_password}" https://api.ipify.org 2>/dev/null || true);
    else
      ipv6_result=$(curl --max-time 20 -sS --proxy "$proxy_url" https://api64.ipify.org 2>/dev/null || true);
      ipv4_result=$(curl --max-time 20 -sS --proxy "$proxy_url" https://api.ipify.org 2>/dev/null || true);
    fi;

    if ! looks_like_ipv6 "$ipv6_result"; then
      log_err "Self-check failed on port $test_port: expected IPv6 on IPv6 endpoint, got \"$ipv6_result\"";
      log_err_and_exit "Error: policy self-check failed (IPv6 egress is not working)";
    fi;

    if [ "$require_ipv4_fallback" = true ] && ! is_valid_ip "$ipv4_result"; then
      log_err "Self-check failed on port $test_port: expected IPv4 fallback on IPv4 endpoint, got \"$ipv4_result\"";
      log_err_and_exit "Error: policy self-check failed (IPv4 fallback is required but unavailable)";
    fi;

    if [ "$require_ipv4_fallback" = false ] && is_valid_ip "$ipv4_result"; then
      log_err "Self-check failed on port $test_port: IPv4 fallback must be blocked for ipv6_only, got \"$ipv4_result\"";
      log_err_and_exit "Error: policy self-check failed (IPv4 fallback is unexpectedly allowed)";
    fi;

    if [ -n "$expected_ipv6" ] && [ "$ipv6_result" != "$expected_ipv6" ]; then
      echo "   Warning: port $test_port returned IPv6 $ipv6_result (expected bind $expected_ipv6)";
      echo "   Continuing because formatting/normalization can differ.";
    fi;

    if [ "$require_ipv4_fallback" = true ]; then
      echo "   OK port $test_port: IPv6 egress OK ($ipv6_result), IPv4 fallback OK ($ipv4_result)"
    else
      echo "   OK port $test_port: IPv6 egress OK ($ipv6_result), IPv4 fallback blocked (expected)"
    fi;
    passed_count=$((passed_count + 1));
  done

  echo "$ipv6_policy self-check passed for $passed_count/$samples_to_test proxy(s)"
}

function write_proxyserver_info() {
  delete_file_if_exists $proxyserver_info_file;

  cat > $proxyserver_info_file <<-EOF
Proxy Server Information:
  Proxy count: $proxy_count
  Proxy type: $proxies_type
  IPv6 policy: $ipv6_policy
  IP preference mode: $ip_preference_mode
  Network profile: $network_profile
  TCP timestamps mode: $tcp_timestamps_mode (effective: $profile_tcp_timestamps)
  TCP ttl target: $profile_ttl
  TCP MSS mode: $profile_mss_mode (target: $profile_mss_value)
  TLS client handshake mode: $tls_clienthello_mode
  DNS country mode: $dns_country
  DNS selected country: $dns_selected_country
  DNS selection strategy: $dns_selection_strategy
  DNS servers: $dns_selected_servers_csv
  Proxy IP: $(get_backconnect_ipv4)
  Proxy ports: $start_port - $last_port
  Auth: $(if is_auth_used; then if [ $use_random_auth = true ]; then echo "random user/password for each proxy"; else echo "user - $user, password - $password"; fi; else echo "disabled"; fi;)
  Rules: $(if ([ -n "$denied_hosts" ] || [ -n "$allowed_hosts" ]); then if [ -n "$denied_hosts" ]; then echo "denied hosts - $denied_hosts, all others are allowed"; else echo "allowed hosts - $allowed_hosts, all others are denied"; fi; else echo "no rules specified, all hosts are allowed"; fi;)
  File with backconnect proxy list: $backconnect_proxies_file
  File with port-to-IPv6 map: $port_ipv6_map_file
  Self-check: $(if [ $run_self_check = true ]; then echo "enabled (samples: $self_check_samples, policy: $ipv6_policy)"; else echo "disabled"; fi;)

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
resolve_network_profile_settings;

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

echo "СЂСџвЂєВ  Applying TCP/IP profile..."
if [ "$runtime_only" = true ]; then
  echo "Runtime-only mode: skipping TCP/IP profile writes."
else
  echo "Applying TCP/IP profile..."
  apply_network_profile_sysctl;
  echo "   Profile: $network_profile (TTL=$profile_ttl, MSS mode=$profile_mss_mode, timestamps=$profile_tcp_timestamps)"
  echo "   TLS client handshake mode: $tls_clienthello_mode (CONNECT/SOCKS passthrough)"
fi;

echo "СЂСџвЂќРЊ Checking IPv6 configuration..."
check_ipv6;

if is_proxyserver_installed; then
  echo -e "РІС™В РїС‘РЏ Proxy server already installed, reconfiguring:\n";
else
  if [ "$runtime_only" = true ]; then
    log_err_and_exit "3proxy is not installed. Run bootstrap-only mode first.";
  fi;
  configure_ipv6;
  install_requred_packages;
  install_3proxy;
fi;

echo "СЂСџРЉС’ Getting backconnect IPv4 address..."
if [ "$bootstrap_only" = true ]; then
  echo "Bootstrap-only mode: applying nftables baseline..."
  setup_nftables_edge_normalization;
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

echo "СЂСџВ§В± Applying edge TCP/IP normalization..."
if [ "$runtime_only" = true ]; then
  echo "Runtime-only mode: skipping edge TCP/IP normalization bootstrap step."
else
  setup_nftables_edge_normalization;
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

echo "СЂСџвЂќР‹ Verifying IPv6 policy..."
run_dualstack_self_check;

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
echo "РІР‚Сћ Network Profile: $network_profile"
echo "РІР‚Сћ TCP timestamps: $tcp_timestamps_mode (effective: $profile_tcp_timestamps)"
echo "РІР‚Сћ TCP TTL target: $profile_ttl"
echo "РІР‚Сћ TCP MSS mode: $profile_mss_mode (target: $profile_mss_value)"
echo "РІР‚Сћ TLS handshake mode: $tls_clienthello_mode"
echo "РІР‚Сћ DNS Country Mode: $dns_country"
echo "РІР‚Сћ DNS Selected Country: $dns_selected_country"
echo "РІР‚Сћ DNS Selection Strategy: $dns_selection_strategy"
echo "РІР‚Сћ DNS Servers: $dns_selected_servers_csv"
echo "РІР‚Сћ Maxconn: $proxy_maxconn"
echo "РІР‚Сћ Proxy Count: $proxy_count"
echo "РІР‚Сћ Port Range: $start_port-$last_port"
echo "РІР‚Сћ Backconnect IP: $backconnect_ipv4"
echo "РІР‚Сћ Proxy List File: $backconnect_proxies_file"
echo "РІР‚Сћ PortРІвЂ вЂќIPv6 Map File: $port_ipv6_map_file"
echo "РІР‚Сћ Instance ID: $instance_id"
echo "РІР‚Сћ Config File: 3proxy_${instance_id}.cfg"
echo "РІР‚Сћ Mode: MULTI-INSTANCE (old proxies preserved)"
echo "РІР‚Сћ Policy self-check: $(if [ $run_self_check = true ]; then echo "enabled"; else echo "disabled"; fi;)"
echo ""

exit 0
