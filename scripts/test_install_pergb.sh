#!/usr/bin/env bash
# deploy/node/install_pergb.sh — the per-GB runtime installer (lane L2).
#
# Default (no root, any OS): every path under a temp root (NETRUN_PERGB_ROOT),
# a fake checkout (NETRUN_PERGB_SRC) and stubs on PATH for getent / groupadd /
# useradd / df / fallocate / mkfs.ext4 / systemctl / mountpoint:
#   - the first run installs users, directories, binary, RADIUS code, the log
#     image + mount, rsyslog / logrotate and the units — enabling nothing;
#   - the second run changes nothing (0 changes, no file touched, no command
#     with an effect); a changed setting rewrites just that unit;
#   - refusals before any change: uid / gid 65533 taken, netrun-pergb with
#     another uid, low disk for the log image, a binary that does not match
#     its pinned sha256 (or is missing).
# --real (Linux, root, a throwaway machine — CI): the real installer twice on
# this machine (the second run changes nothing), `systemd-analyze verify` of
# every installed unit, nothing enabled; and in ubuntu:24.04 containers the
# uid-clash and low-disk refusals.
#   bash scripts/test_install_pergb.sh [--real]
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd -P)"
INSTALLER="$ROOT_DIR/deploy/node/install_pergb.sh"
TMP="$(mktemp -d)"
trap '[ -n "${KEEP_TMP:-}" ] || rm -rf "$TMP"' EXIT

PASS=0
fail() { echo "FAIL: $1"; exit 1; }
ok() { PASS=$((PASS + 1)); echo "ok: $1"; }
sha256_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }

bash -n "$INSTALLER" || fail "bash -n install_pergb.sh"

# ── --real: on this (throwaway) Linux machine ─────────────────────
if [ "${1:-}" = "--real" ]; then
  [ "$(uname -s)" = Linux ] && [ "$(id -u)" = 0 ] || fail "--real needs Linux and root"
  [ -f "$ROOT_DIR/deploy/node/bin/3proxy-pergb" ] || fail "--real needs deploy/node/bin/3proxy-pergb (build it first)"
  snap() {
    find /opt/netrun/pergb /opt/netrun/radius /etc/netrun-pergb /var/lib/netrun-pergb /var/log/netrun-pergb \
         /etc/systemd/system/netrun-pergb* /etc/systemd/system/netrun.slice /etc/systemd/system/netrun-radius.* \
         '/etc/systemd/system/var-log-netrun\x2dpergb.mount' /etc/rsyslog.d/30-netrun-pergb-haproxy.conf \
         /etc/logrotate.d/netrun-pergb-haproxy -xdev 2>/dev/null \
      | sort | while read -r f; do
          if [ -f "$f" ] && [ "$f" != /var/lib/netrun-pergb/log.img ]; then echo "$f $(stat -c '%a %U %G %Y %i' "$f") $(sha256sum < "$f" | cut -c1-16)";
          else echo "$f $(stat -c '%a %U %G' "$f")"; fi
        done
    getent passwd netrun-pergb netrun-radius; getent group netrun-pergb netrun-radius
    findmnt -n -o SOURCE,FSTYPE /var/log/netrun-pergb
  }
  export NETRUN_PERGB_LOG_SIZE=512M
  out="$(bash "$INSTALLER" 2>&1)" || fail "first run: $out"
  echo "$out" | tail -n 3
  echo "$out" | grep -q 'done: 0 change(s)' && fail "the first run changed nothing"
  [ "$(id -u netrun-pergb)" = 65533 ] && [ "$(id -g netrun-pergb)" = 65533 ] || fail "netrun-pergb is not 65533:65533"
  findmnt -n /var/log/netrun-pergb >/dev/null || fail "the log filesystem is not mounted"
  [ "$(stat -c '%a %U' /var/log/netrun-pergb)" = "751 netrun-pergb" ] || fail "log fs root: $(stat -c '%a %U' /var/log/netrun-pergb)"
  for u in netrun-pergb.target netrun-pergb-haproxy.service netrun-pergb-certs.path; do
    [ "$(systemctl is-enabled "$u" 2>/dev/null || true)" != enabled ] || fail "$u was enabled"
    systemctl is-active --quiet "$u" && fail "$u was started"
  done
  before="$(snap)"
  out="$(bash "$INSTALLER" 2>&1)" || fail "second run: $out"
  echo "$out" | grep -q 'done: 0 change(s)' || fail "the second run changed something: $out"
  [ "$(snap)" = "$before" ] || fail "the second run touched files: $(diff <(echo "$before") <(snap))"
  ok "real: installed (users, dirs, binary, log fs mounted, units disabled); the second run changes nothing"
  # every unit verifies (netrun-radius.* stubs when the checkout has none: lane L1)
  vdir="$(mktemp -d)"
  for u in netrun-radius.socket netrun-radius.service; do
    if [ ! -f "/etc/systemd/system/$u" ]; then
      case "$u" in
        *.socket) printf '[Unit]\nDescription=stub\n[Socket]\nListenDatagram=127.0.0.1:1812\n' > "/etc/systemd/system/$u" ;;
        *) printf '[Unit]\nDescription=stub\n[Service]\nExecStart=/bin/true\n' > "/etc/systemd/system/$u" ;;
      esac
      echo "$u" >> "$vdir/stubs"
    fi
  done
  systemctl daemon-reload
  # the certs service runs the repo script from /opt/netrun: verify needs it there
  mkdir -p /opt/netrun/deploy/node && cp "$ROOT_DIR/deploy/node/netrun-pergb-certs-reload.sh" /opt/netrun/deploy/node/
  command -v haproxy >/dev/null 2>&1 || fail "haproxy must be installed for systemd-analyze verify"
  vout="$(cd /etc/systemd/system && systemd-analyze verify --man=no netrun-pergb.target netrun.slice netrun-pergb.slice \
    netrun-pergb-3proxy@31000.service netrun-pergb-haproxy.service netrun-pergb-certs.path netrun-pergb-certs.service \
    'var-log-netrun\x2dpergb.mount' 2>&1)" || fail "systemd-analyze verify: $vout"
  [ -z "$(printf '%s\n' "$vout" | grep -v '^$')" ] || fail "systemd-analyze verify reported: $vout"
  [ -f "$vdir/stubs" ] && while read -r u; do rm -f "/etc/systemd/system/$u"; done < "$vdir/stubs"
  systemctl daemon-reload
  ok "real: systemd-analyze verify passes for every per-GB unit"
  if command -v docker >/dev/null 2>&1; then
    out="$(docker run --rm -v "$ROOT_DIR:/src:ro" ubuntu:24.04 bash -c \
      'useradd -u 65533 -M intruder && bash /src/deploy/node/install_pergb.sh; echo "rc=$?"; ls -d /etc/netrun-pergb /opt/netrun/pergb 2>&1; getent passwd netrun-pergb || echo no-user' 2>&1)"
    echo "$out" | grep -q 'uid_taken: uid 65533 belongs to intruder' || fail "container uid clash: $out"
    echo "$out" | grep -q 'rc=1' || fail "container uid clash exit: $out"
    echo "$out" | grep -q 'no-user' && echo "$out" | grep -q "cannot access '/etc/netrun-pergb'" || fail "container uid clash changed something: $out"
    out="$(docker run --rm -e NETRUN_PERGB_LOG_SIZE=100T -v "$ROOT_DIR:/src:ro" ubuntu:24.04 bash -c \
      'bash /src/deploy/node/install_pergb.sh; echo "rc=$?"; getent passwd netrun-pergb || echo no-user' 2>&1)"
    echo "$out" | grep -q 'low_disk' || fail "container low disk: $out"
    echo "$out" | grep -q 'no-user' || fail "container low disk changed something: $out"
    ok "real (containers): refused on a uid clash and on low disk, nothing changed"
  else
    fail "--real needs docker for the container refusals"
  fi
  echo "PASS ($PASS)"
  exit 0
fi

# ── stubbed runs under a temp root ────────────────────────────────
STUB="$TMP/bin"; mkdir -p "$STUB"
export CALLS="$TMP/calls.log" FAKE_ETC="$TMP/fake-etc" MOUNTED_FLAG="$TMP/mounted" DF_AVAIL_KB=104857600
cat > "$STUB/getent" <<'EOF'
#!/usr/bin/env bash
db="$FAKE_ETC/$1"; key="$2"
[ -f "$db" ] || exit 2
awk -F: -v k="$key" '$1 == k || $3 == k { print; found = 1; exit } END { exit found ? 0 : 2 }' "$db"
EOF
cat > "$STUB/groupadd" <<'EOF'
#!/usr/bin/env bash
echo "groupadd $*" >> "$CALLS"
gid=""; name=""
while [ $# -gt 0 ]; do case "$1" in -g) gid="$2"; shift ;; --system) ;; *) name="$1" ;; esac; shift; done
echo "$name:x:$gid:" >> "$FAKE_ETC/group"
EOF
cat > "$STUB/useradd" <<'EOF'
#!/usr/bin/env bash
echo "useradd $*" >> "$CALLS"
uid=""; grp=""; ug=0; name=""
while [ $# -gt 0 ]; do
  case "$1" in -u) uid="$2"; shift ;; -g) grp="$2"; shift ;; -U) ug=1 ;; -d|-s|-c) shift ;; --system|-M) ;; *) name="$1" ;; esac
  shift
done
[ -n "$uid" ] || uid=$((990 + $(wc -l < "$FAKE_ETC/passwd")))
if [ "$ug" = 1 ]; then echo "$name:x:$uid:" >> "$FAKE_ETC/group"; gid="$uid"; else gid="$(awk -F: -v g="$grp" '$1 == g { print $3 }' "$FAKE_ETC/group")"; fi
echo "$name:x:$uid:$gid::/nonexistent:/usr/sbin/nologin" >> "$FAKE_ETC/passwd"
EOF
cat > "$STUB/df" <<'EOF'
#!/usr/bin/env bash
echo "Filesystem 1024-blocks Used Available Capacity Mounted on"
echo "/dev/vda1 209715200 1 $DF_AVAIL_KB 1% /"
EOF
cat > "$STUB/fallocate" <<'EOF'
#!/usr/bin/env bash
echo "fallocate $*" >> "$CALLS"
echo "image of $2 bytes" > "$3"
EOF
cat > "$STUB/mkfs.ext4" <<'EOF'
#!/usr/bin/env bash
echo "mkfs.ext4 $*" >> "$CALLS"
EOF
cat > "$STUB/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "systemctl $*" >> "$CALLS"
case "$1" in
  start) case "$2" in var-log-netrun*pergb.mount) touch "$MOUNTED_FLAG" ;; esac ;;
  is-active) [ "${3:-$2}" = rsyslog ] && exit 0; exit 3 ;;
esac
exit 0
EOF
cat > "$STUB/mountpoint" <<'EOF'
#!/usr/bin/env bash
[ -e "$MOUNTED_FLAG" ]
EOF
chmod +x "$STUB"/*
export PATH="$STUB:$PATH"

# A fake checkout: the repo's deploy/node files, a fake binary + its pin, a
# RADIUS package with tests and caches that must not be installed.
SRC="$TMP/src"
mkdir -p "$SRC/deploy/node/bin" "$SRC/node_runtime/radius/tests" "$SRC/node_runtime/radius/__pycache__"
cp "$ROOT_DIR"/deploy/node/netrun-pergb* "$ROOT_DIR"/deploy/node/netrun.slice "$SRC/deploy/node/"
printf 'fake 3proxy-pergb\n' > "$SRC/deploy/node/bin/3proxy-pergb"
printf '%s  3proxy-pergb\n' "$(sha256_of "$SRC/deploy/node/bin/3proxy-pergb")" > "$SRC/deploy/node/bin/3proxy-pergb.sha256"
printf 'print("radius")\n' > "$SRC/node_runtime/radius/netrun_radius.py"
printf 'x\n' > "$SRC/node_runtime/radius/tests/test_x.py"
printf 'x\n' > "$SRC/node_runtime/radius/__pycache__/x.pyc"
printf '[Socket]\nListenDatagram=127.0.0.1:1812\n' > "$SRC/deploy/node/netrun-radius.socket"

new_root() {
  R="$TMP/root-$1"; rm -rf "$R" "$FAKE_ETC" "$MOUNTED_FLAG"; mkdir -p "$R" "$FAKE_ETC"
  printf 'root:x:0:0::/root:/bin/bash\nsyslog:x:104:110::/home/syslog:/usr/sbin/nologin\n' > "$FAKE_ETC/passwd"
  printf 'root:x:0:\nadm:x:4:syslog\nsyslog:x:110:\n' > "$FAKE_ETC/group"
  : > "$CALLS"
}
install_run() { NETRUN_PERGB_ROOT="$R" NETRUN_PERGB_SRC="$SRC" NETRUN_PERGB_NO_CHOWN=1 bash "$INSTALLER" "$@"; }
snapshot() {
  find "$R" | sort | while read -r f; do
    if [ -f "$f" ]; then echo "$f $(mode_of "$f") $(sha256_of "$f") $(stat -c %Y "$f" 2>/dev/null || stat -f %m "$f")";
    else echo "$f $(mode_of "$f")"; fi
  done
}

# ── 1. first run ──────────────────────────────────────────────────
new_root a
out="$(NETRUN_PERGB_CPU_WEIGHT=40 NETRUN_PERGB_MEM_MAX=2G NETRUN_PERGB_MAX_CONNS=6000 install_run 2>&1)" || fail "first run: $out"
echo "$out" | grep -Eq 'done: [1-9][0-9]* change\(s\)' || fail "first run summary: $out"
grep -qx 'netrun-pergb:x:65533:65533::/nonexistent:/usr/sbin/nologin' "$FAKE_ETC/passwd" || fail "netrun-pergb 65533: $(cat "$FAKE_ETC/passwd")"
grep -qx 'netrun-pergb:x:65533:' "$FAKE_ETC/group" || fail "group netrun-pergb 65533"
grep -q '^netrun-radius:' "$FAKE_ETC/passwd" || fail "netrun-radius user"
for d in "opt/netrun/pergb 755" "opt/netrun/pergb/bin 755" "opt/netrun/pergb/cfg 750" "opt/netrun/pergb/haproxy 755" \
         "etc/netrun-pergb 750" "var/lib/netrun-pergb 700" "var/log/netrun-pergb 751" "var/log/netrun-pergb/archive 750"; do
  set -- $d
  [ -d "$R/$1" ] && [ "$(mode_of "$R/$1")" = "$2" ] || fail "$1 mode $(mode_of "$R/$1" 2>/dev/null), want $2"
done
cmp -s "$R/opt/netrun/pergb/bin/3proxy-pergb" "$SRC/deploy/node/bin/3proxy-pergb" || fail "binary installed"
[ "$(mode_of "$R/opt/netrun/pergb/bin/3proxy-pergb")" = 755 ] || fail "binary mode"
cmp -s "$R/opt/netrun/pergb/bin/3proxy-pergb.sha256" "$SRC/deploy/node/bin/3proxy-pergb.sha256" || fail "installed .sha256 = the pin"
[ -f "$R/opt/netrun/radius/netrun_radius.py" ] || fail "RADIUS code copied"
[ -e "$R/opt/netrun/radius/tests" ] || [ -e "$R/opt/netrun/radius/__pycache__" ] && fail "RADIUS tests / caches must not be installed"
[ "$(mode_of "$R/opt/netrun/radius/netrun_radius.py")" = 644 ] || fail "RADIUS file mode"
grep -q "^fallocate -l 17179869184 $R/var/lib/netrun-pergb/log.img$" "$CALLS" || fail "16G image allocated: $(cat "$CALLS")"
[ "$(grep -c '^mkfs.ext4 ' "$CALLS")" = 1 ] || fail "mkfs once"
grep -q "^mkfs.ext4 -q -F -m 0 -L netrun-pergb-log $R/var/lib/netrun-pergb/log.img$" "$CALLS" || fail "mkfs args"
U="$R/etc/systemd/system"
for u in netrun-pergb.target netrun.slice netrun-pergb.slice netrun-pergb-3proxy@.service netrun-pergb-haproxy.service \
         netrun-pergb-certs.path netrun-pergb-certs.service 'var-log-netrun\x2dpergb.mount' netrun-radius.socket; do
  [ -f "$U/$u" ] && [ "$(mode_of "$U/$u")" = 644 ] || fail "unit $u installed 0644"
done
grep -qx 'CPUWeight=40' "$U/netrun-pergb.slice" && grep -qx 'MemoryMax=2048M' "$U/netrun-pergb.slice" \
  && grep -qx 'MemoryHigh=1740M' "$U/netrun-pergb.slice" && grep -qx 'TasksMax=8500' "$U/netrun-pergb.slice" \
  || fail "slice values: $(grep = "$U/netrun-pergb.slice")"
grep -qx 'CPUWeight=40' "$U/netrun.slice" || fail "netrun.slice CPU weight"
grep -qx 'What=/var/lib/netrun-pergb/log.img' "$U/var-log-netrun\x2dpergb.mount" && grep -qx 'Where=/var/log/netrun-pergb' "$U/var-log-netrun\x2dpergb.mount" \
  && grep -qx 'RequiresMountsFor=/var/lib/netrun-pergb' "$U/var-log-netrun\x2dpergb.mount" || fail "mount unit rendered"
grep -q '@' "$U/var-log-netrun\x2dpergb.mount" && fail "placeholders left in the mount unit"
[ "$(grep -c '^systemctl daemon-reload' "$CALLS")" = 1 ] || fail "one daemon-reload"
grep -q '^systemctl start var-log-netrun\\x2dpergb.mount$' "$CALLS" || fail "log fs mounted through its unit: $(cat "$CALLS")"
grep -Eq '^systemctl (enable|start netrun|restart netrun|reload)' "$CALLS" && fail "nothing per-GB may be enabled or started: $(cat "$CALLS")"
grep -qx 'systemctl restart rsyslog' "$CALLS" || fail "rsyslog restarted for the new rule"
cmp -s "$R/etc/rsyslog.d/30-netrun-pergb-haproxy.conf" "$SRC/deploy/node/netrun-pergb-rsyslog.conf" || fail "rsyslog rule"
cmp -s "$R/etc/logrotate.d/netrun-pergb-haproxy" "$SRC/deploy/node/netrun-pergb-logrotate" || fail "logrotate"
[ -f "$R/var/log/netrun-pergb/haproxy.log" ] && [ "$(mode_of "$R/var/log/netrun-pergb/haproxy.log")" = 660 ] || fail "haproxy.log 0660"
ok "first run: users 65533 + radius, dirs and modes, binary + pin, RADIUS code, 16G image + mount, rsyslog/logrotate, units — nothing enabled"

# ── 2. second run: nothing ────────────────────────────────────────
before="$(snapshot)"; : > "$CALLS"
sleep 1
out="$(NETRUN_PERGB_CPU_WEIGHT=40 NETRUN_PERGB_MEM_MAX=2G NETRUN_PERGB_MAX_CONNS=6000 install_run 2>&1)" || fail "second run: $out"
echo "$out" | grep -q 'done: 0 change(s)' || fail "second run changed something: $out"
[ "$(snapshot)" = "$before" ] || fail "second run touched files: $(diff <(echo "$before") <(snapshot))"
[ ! -s "$CALLS" ] || fail "second run ran commands: $(cat "$CALLS")"
ok "second run: 0 changes, no file touched, no command run"

# a changed setting: only the slice, one daemon-reload
out="$(NETRUN_PERGB_CPU_WEIGHT=40 NETRUN_PERGB_MEM_MAX=3G NETRUN_PERGB_MAX_CONNS=6000 install_run 2>&1)" || fail "third run: $out"
echo "$out" | grep -q 'done: 1 change(s)' || fail "third run: $out"
grep -qx 'MemoryMax=3072M' "$U/netrun-pergb.slice" || fail "slice re-rendered"
[ "$(cat "$CALLS")" = "systemctl daemon-reload" ] || fail "third run commands: $(cat "$CALLS")"
ok "a changed setting rewrites only the slice (+ daemon-reload)"

# ── 3. refusals: nothing changes ──────────────────────────────────
refused() { # <label> <expected message>
  local out
  out="$(install_run 2>&1)" && fail "$1: the installer did not refuse"
  echo "$out" | grep -q "$2" || fail "$1: message: $out"
  [ -z "$(find "$R" -mindepth 1 2>/dev/null | head -n 1)" ] || fail "$1: something was created: $(find "$R" | head)"
  [ ! -s "$CALLS" ] || fail "$1: commands ran: $(cat "$CALLS")"
  ok "refused: $1"
}
new_root b; echo 'intruder:x:65533:65533::/:/bin/sh' >> "$FAKE_ETC/passwd"
refused "uid 65533 taken" "uid_taken: uid 65533 belongs to intruder"
new_root c; echo 'intruders:x:65533:' >> "$FAKE_ETC/group"
refused "gid 65533 taken" "uid_taken: gid 65533 belongs to intruders"
new_root d; echo 'netrun-pergb:x:1001:1001::/:/bin/sh' >> "$FAKE_ETC/passwd"
refused "netrun-pergb with another uid" "uid_taken: user netrun-pergb exists with uid 1001"
new_root e; DF_AVAIL_KB=$((20 * 1024 * 1024)) refused "low disk (20 GiB free < 2 x 16G)" "low_disk"
new_root f; mv "$SRC/deploy/node/bin/3proxy-pergb.sha256" "$TMP/sums"; printf '%064d  3proxy-pergb\n' 0 > "$SRC/deploy/node/bin/3proxy-pergb.sha256"
refused "binary does not match its pin" "binary_hash_mismatch"
rm -f "$SRC/deploy/node/bin/3proxy-pergb.sha256"
new_root g; refused "binary missing" "build it on a Linux box with Docker"
mv "$TMP/sums" "$SRC/deploy/node/bin/3proxy-pergb.sha256"

# an existing image: no disk check (the node keeps its image)
new_root h; mkdir -p "$R/var/lib/netrun-pergb"; echo old > "$R/var/lib/netrun-pergb/log.img"
out="$(DF_AVAIL_KB=1 install_run 2>&1)" || fail "existing image + full disk: $out"
grep -q '^fallocate\|^mkfs' "$CALLS" && fail "an existing image is never re-created"
[ "$(cat "$R/var/lib/netrun-pergb/log.img")" = old ] || fail "image kept"
ok "an existing log image is kept (no disk check, no mkfs)"

echo "PASS ($PASS)"
