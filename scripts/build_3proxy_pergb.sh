#!/usr/bin/env bash
# build_3proxy_pergb.sh — reproducible build of the per-GB 3proxy
# (deploy/node/bin/3proxy-pergb): upstream 3proxy 0.9.3 +
# deploy/node/3proxy-pergb/netrun-pergb.patch, built in Docker exactly as
# pinned below, so anyone can rebuild it and get the same sha256.
#
#   bash scripts/build_3proxy_pergb.sh            build, write deploy/node/bin/3proxy-pergb + .sha256
#   bash scripts/build_3proxy_pergb.sh --check    build into a temp dir; exit 0 only when the result
#                                                  equals the committed binary and its pinned sha256
#   bash scripts/build_3proxy_pergb.sh --out DIR  build into DIR (3proxy-pergb + toolchain.txt)
#
# Pinned inputs (change one = a new binary, a new sha256 and a review):
#   - the upstream tarball (GitHub tag 0.9.3) by sha256;
#   - the build image ubuntu:24.04 (the nodes' OS) by digest;
#   - the compiler and libc headers: the Ubuntu archive snapshot of
#     $SNAPSHOT (snapshot.ubuntu.com), so apt installs the same versions forever;
#   - the build: Makefile.Linux unchanged (the flags of the stock binary:
#     -g -O2 -fPIC -fno-strict-aliasing -DWITHSPLICE -DWITH_STD_MALLOC
#     -DFD_SETSIZE=4096 -DWITH_POLL -DWITH_NETFILTER ...), only the 3proxy
#     target, in /build/3proxy-0.9.3 (the path lands in the debug info).
# Needs: docker, curl, sha256sum (or shasum).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TARBALL_URL="https://github.com/3proxy/3proxy/archive/refs/tags/0.9.3.tar.gz"
TARBALL_SHA256="84861f4a7879468728c6a4ddd6ca2a8334a5249831282e70d059dc0e09304c72"
IMAGE="ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55"
SNAPSHOT="20261001T000000Z"
PATCH="$ROOT/deploy/node/3proxy-pergb/netrun-pergb.patch"
BIN="$ROOT/deploy/node/bin/3proxy-pergb"
SUMS="$ROOT/deploy/node/bin/3proxy-pergb.sha256"
TOOLCHAIN="$ROOT/deploy/node/3proxy-pergb/toolchain.txt"

log() { echo "[build-3proxy-pergb] $*"; }
die() { echo "[build-3proxy-pergb] ERROR: $*" >&2; exit 1; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

MODE=write
OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --check) MODE=check ;;
    --out) [ $# -ge 2 ] || die "--out needs a directory"; MODE=out; OUT="$2"; shift ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
  shift
done

command -v docker >/dev/null 2>&1 || die "docker not found"
[ -f "$PATCH" ] || die "missing $PATCH"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/in" "$WORK/out"

log "fetching $TARBALL_URL"
curl -fsSL --retry 5 -o "$WORK/in/3proxy-0.9.3.tar.gz" "$TARBALL_URL" || die "download failed"
got="$(sha256_of "$WORK/in/3proxy-0.9.3.tar.gz")"
[ "$got" = "$TARBALL_SHA256" ] || die "tarball sha256 $got != pinned $TARBALL_SHA256"
cp "$PATCH" "$WORK/in/netrun-pergb.patch"

cat > "$WORK/in/build.sh" <<'EOF'
#!/bin/bash
set -euo pipefail
rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*
cat > /etc/apt/sources.list.d/snapshot.sources <<SRC
Types: deb
URIs: http://snapshot.ubuntu.com/ubuntu/${SNAPSHOT}/
Suites: noble noble-updates noble-security
Components: main
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
SRC
export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::Retries=5 -o Acquire::Check-Valid-Until=false update -qq
apt-get -o Acquire::Retries=5 install -y -qq --no-install-recommends gcc make libc6-dev patch >/dev/null
mkdir -p /build
tar -xzf /in/3proxy-0.9.3.tar.gz -C /build
cd /build/3proxy-0.9.3
patch -p1 --no-backup-if-mismatch < /in/netrun-pergb.patch
cat Makefile.Linux > src/Makefile.var
make -C src -j"$(nproc)" ../bin/3proxy > /build/make.log 2>&1 || { tail -n 60 /build/make.log; exit 1; }
cp bin/3proxy /out/3proxy-pergb
{
  echo "image: ${IMAGE}"
  echo "snapshot: ${SNAPSHOT}"
  gcc --version | head -n 1
  dpkg-query -W -f='${Package} ${Version}\n' gcc-13 binutils libc6-dev linux-libc-dev make
} > /out/toolchain.txt
chown "${HOST_UID}:${HOST_GID}" /out/3proxy-pergb /out/toolchain.txt
EOF

log "building in $IMAGE (snapshot $SNAPSHOT)"
docker run --rm --platform linux/amd64 \
  -e SNAPSHOT="$SNAPSHOT" -e IMAGE="$IMAGE" -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  -v "$WORK/in:/in:ro" -v "$WORK/out:/out" "$IMAGE" bash /in/build.sh
[ -s "$WORK/out/3proxy-pergb" ] || die "the build produced no binary"
new="$(sha256_of "$WORK/out/3proxy-pergb")"
log "built: sha256 $new"
sed 's/^/[build-3proxy-pergb]   /' "$WORK/out/toolchain.txt"

case "$MODE" in
  check)
    pinned="$(cut -d' ' -f1 "$SUMS" 2>/dev/null || true)"
    committed="$( [ -f "$BIN" ] && sha256_of "$BIN" || echo none)"
    if [ "$new" = "$pinned" ] && [ "$new" = "$committed" ]; then
      log "reproducible: the rebuild equals deploy/node/bin/3proxy-pergb ($pinned)"
      exit 0
    fi
    die "NOT reproducible: rebuilt $new, pinned ${pinned:-none}, committed $committed"
    ;;
  out)
    mkdir -p "$OUT"
    cp "$WORK/out/3proxy-pergb" "$WORK/out/toolchain.txt" "$OUT/"
    printf '%s  3proxy-pergb\n' "$new" > "$OUT/3proxy-pergb.sha256"
    log "wrote $OUT/3proxy-pergb"
    ;;
  write)
    install -m 0755 "$WORK/out/3proxy-pergb" "$BIN"
    printf '%s  3proxy-pergb\n' "$new" > "$SUMS"
    cp "$WORK/out/toolchain.txt" "$TOOLCHAIN"
    log "wrote $BIN, $SUMS, $TOOLCHAIN"
    ;;
esac
