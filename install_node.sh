#!/usr/bin/env bash
#
# install_node.sh — THIN SHIM. The real installer is install_node_v2.sh.
#
# Wave NODE-GENLOCK-HARDENING (installer consolidation):
# v1 and v2 had diverged. v2 carries the real fixes and is a superset of v1 for
# a FRESH node:
#   - sysctl: kernel.pid_max + threads-max = 4M (v1 left the 65536 default,
#     which trips fork EAGAIN when restore-3proxy respawns 4000+ instances);
#   - DAD/MLD off (98-netrun-ipv6.conf) for thousands of /64 egress addrs;
#   - bounded parallel 3proxy restore (xargs -P 4 + setsid) vs v1's fork-bomb;
#   - no MSS clamp (v1's 1340 read as OpenVPN; v2's later 1460 was a no-op —
#     the TCP signature is pinned by deploy/node/99-zz-netrun-tcp.conf) +
#     `nft flush ruleset` to survive UFW xt-compat residue on fresh Ubuntu;
#   - raised systemd limits (TasksMax/LimitNOFILE/LimitNPROC) via drop-in;
#   - local recursive resolver (unbound), trend monitor, IPv6 egress restore.
# All install_node.sh entrypoints (bootstrap_new_node.sh, quick-install.sh,
# README) now call v2 directly; this shim keeps the historic filename working.
#
# CAVEAT — v2 is NOT a byte-identical drop-in on a NON-FRESH node:
#   ensure_legacy_root_proxyserver_symlink() differs. If /root/proxyserver
#   already exists as a REAL DIRECTORY (not a symlink):
#     - v1 logged a warning and LEFT IT ALONE;
#     - v2 does `rm -rf /root/proxyserver` before symlinking.
#   On a fresh node /root/proxyserver does not exist, so v2 is safe. On a
#   legacy node that still keeps real proxy data under /root/proxyserver, run
#   v2 deliberately (the rm -rf is intended cleanup there) or migrate that data
#   first. The original v1 behavior remains in git history if ever needed.
#
# All CLI args (--clean, --remove-legacy-root, -h/--help) pass straight through.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
V2="$SCRIPT_DIR/install_node_v2.sh"

if [ ! -f "$V2" ]; then
  printf '[install_node] ERROR: install_node_v2.sh not found at %s\n' "$V2" >&2
  exit 1
fi

printf '[install_node] redirecting to install_node_v2.sh (the maintained installer)\n'
exec bash "$V2" "$@"
