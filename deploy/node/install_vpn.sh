#!/usr/bin/env bash
# install_vpn.sh — the VPN runtime on a node (owner 2026-10-15): Xray-core for
# VLESS + REALITY. Standalone and idempotent; installs everything and leaves it
# DISABLED — the agent's POST /vpn/enable (vpn_runtime.js) adds the entry
# addresses, writes /etc/netrun-vpn/xray.json and the nft table, starts it.
# Never touches a proxy process, cfg, port, haproxy, BGP or another nft table.
#
#   bash deploy/node/install_vpn.sh       (root; from the repo, e.g. /opt/netrun)
#
# What it does (each step only when something differs):
#   preflight: uid/gid 65532 free or already netrun-vpn's ("uid_taken").
#   user: netrun-vpn (system, uid/gid 65532) — the Xray process; the agent's
#     table inet netrun_vpn gates its traffic by this uid.
#   directories: /opt/netrun/vpn/{bin,share} (0755), /etc/netrun-vpn (0750
#     root:netrun-vpn: xray.json 0640, the rest 0600 root), /var/lib/netrun-vpn (0700).
#   binary: Xray $XRAY_VERSION from the official release zip (GitHub), the zip's
#     SHA-256 checked against ZIP_SHA256, the binary's against
#     deploy/node/bin/xray.sha256 (the unit's ExecStartPre checks it again);
#     geoip.dat / geosite.dat to /opt/netrun/vpn/share (not used by our config).
#   units (installed, daemon-reload, NOT enabled or started): netrun-vpn.slice,
#     netrun-vpn-xray.service.
#
# Test hooks: NETRUN_VPN_ROOT=<dir> prefixes every path written;
# NETRUN_VPN_SRC=<dir> the repo; NETRUN_VPN_ZIP=<file> a local release zip
# (no download); NETRUN_VPN_NO_CHOWN=1 skips users and chown.
set -euo pipefail

SRC="${NETRUN_VPN_SRC:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)}"
ROOT="${NETRUN_VPN_ROOT:-}"
NO_CHOWN="${NETRUN_VPN_NO_CHOWN:-0}"
VPN_USER="netrun-vpn"
VPN_UID="${NETRUN_VPN_UID:-65532}"
XRAY_VERSION="v26.3.27"
ZIP_SHA256="23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae"
ZIP_URL="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip"
PIN="$SRC/deploy/node/bin/xray.sha256"
BIN_SHA256="$(awk 'NR == 1 { print $1 }' "$PIN")"
BIN_DIR="$ROOT/opt/netrun/vpn/bin"
SHARE_DIR="$ROOT/opt/netrun/vpn/share"
ETC_DIR="$ROOT/etc/netrun-vpn"
LIB_DIR="$ROOT/var/lib/netrun-vpn"
UNIT_DIR="$ROOT/etc/systemd/system"
changes=0
say() { printf '[install_vpn] %s\n' "$*"; }
change() { changes=$((changes + 1)); say "$*"; }
die() { say "ERROR: $*" >&2; exit 1; }

[ -n "$BIN_SHA256" ] || die "no pinned binary hash in $PIN"

# ── preflight ──
if [ "$NO_CHOWN" != 1 ]; then
  owner="$(getent passwd "$VPN_UID" | cut -d: -f1 || true)"
  [ -z "$owner" ] || [ "$owner" = "$VPN_USER" ] || die "uid_taken: uid $VPN_UID belongs to $owner"
  gowner="$(getent group "$VPN_UID" | cut -d: -f1 || true)"
  [ -z "$gowner" ] || [ "$gowner" = "$VPN_USER" ] || die "uid_taken: gid $VPN_UID belongs to $gowner"
  cur="$(id -u "$VPN_USER" 2>/dev/null || true)"
  [ -z "$cur" ] || [ "$cur" = "$VPN_UID" ] || die "uid_taken: $VPN_USER has uid $cur, not $VPN_UID"
fi

# ── user ──
if [ "$NO_CHOWN" != 1 ] && ! id -u "$VPN_USER" >/dev/null 2>&1; then
  getent group "$VPN_USER" >/dev/null || groupadd --system --gid "$VPN_UID" "$VPN_USER"
  useradd --system --uid "$VPN_UID" --gid "$VPN_USER" --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$VPN_USER"
  change "user $VPN_USER ($VPN_UID)"
fi

# ── directories ──
mkd() { # path mode owner
  if [ ! -d "$1" ]; then mkdir -p "$1"; change "dir $1"; fi
  chmod "$2" "$1"
  if [ "$NO_CHOWN" != 1 ]; then chown "$3" "$1"; fi
}
# the parent too: under a deploy's `umask 077` mkdir -p leaves it 0700 and
# netrun-vpn could not reach its binary (Chicago 2026-10-15)
mkd "$ROOT/opt/netrun/vpn" 0755 root:root
mkd "$BIN_DIR" 0755 root:root
mkd "$SHARE_DIR" 0755 root:root
mkd "$ETC_DIR" 0750 "root:$VPN_USER"
mkd "$LIB_DIR" 0700 root:root

# ── binary ──
have=""
[ -f "$BIN_DIR/xray" ] && have="$(sha256sum "$BIN_DIR/xray" | cut -c1-64)"
if [ "$have" != "$BIN_SHA256" ]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  if [ -n "${NETRUN_VPN_ZIP:-}" ]; then cp "$NETRUN_VPN_ZIP" "$tmp/x.zip"; else
    curl -fsSL --retry 4 --retry-delay 5 -o "$tmp/x.zip" "$ZIP_URL" || die "download failed: $ZIP_URL"
  fi
  got="$(sha256sum "$tmp/x.zip" | cut -c1-64)"
  [ "$got" = "$ZIP_SHA256" ] || die "release zip sha256 $got != pinned $ZIP_SHA256"
  python3 - "$tmp/x.zip" "$tmp" <<'PY'
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
for name in ("xray", "geoip.dat", "geosite.dat"):
    z.extract(name, sys.argv[2])
PY
  got="$(sha256sum "$tmp/xray" | cut -c1-64)"
  [ "$got" = "$BIN_SHA256" ] || die "xray sha256 $got != pinned $BIN_SHA256 ($PIN)"
  install -m 0755 "$tmp/xray" "$BIN_DIR/xray.new" && mv -f "$BIN_DIR/xray.new" "$BIN_DIR/xray"
  install -m 0644 "$tmp/geoip.dat" "$SHARE_DIR/geoip.dat"
  install -m 0644 "$tmp/geosite.dat" "$SHARE_DIR/geosite.dat"
  change "xray $XRAY_VERSION -> $BIN_DIR/xray"
fi
want_sha="$BIN_SHA256  xray"
if [ "$(cat "$BIN_DIR/xray.sha256" 2>/dev/null || true)" != "$want_sha" ]; then
  printf '%s\n' "$want_sha" > "$BIN_DIR/xray.sha256"; chmod 0644 "$BIN_DIR/xray.sha256"
  change "$BIN_DIR/xray.sha256"
fi

# ── units ──
reload=0
for u in netrun-vpn.slice netrun-vpn-xray.service; do
  mkdir -p "$UNIT_DIR"
  if ! cmp -s "$SRC/deploy/node/$u" "$UNIT_DIR/$u"; then
    install -m 0644 "$SRC/deploy/node/$u" "$UNIT_DIR/$u"; reload=1; change "unit $u"
  fi
done
if [ "$reload" = 1 ] && [ -z "$ROOT" ]; then systemctl daemon-reload; fi

say "$changes change(s); Xray $("$BIN_DIR/xray" version 2>/dev/null | head -1 | awk '{print $2}' || echo '?') installed, VPN stays as it was (POST /vpn/enable starts it)"
