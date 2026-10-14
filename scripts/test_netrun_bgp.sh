#!/usr/bin/env bash
# netrun-bgp: the :179 guard (only the neighbour may reach BIRD; loaded before
# BIRD starts, boot drop-in, `check` fails without it) and the 3proxy egress
# guard refresh after an apply (audit 2026-10-08);
# prefix canonicalisation, the generated bird.conf (byte-equal in
# its body to the hand-made Chicago config of 2026-10-08), the boot unit and
# the bird drop-in, the order of route / announce changes, idempotence,
# --dry-run touching nothing, settings validation, and `check`. ip / bird /
# birdc / systemctl / apt-get are stubs on PATH; python3 is real. No root.
#   bash scripts/test_netrun_bgp.sh
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd -P)"
BGP="$ROOT_DIR/scripts/netrun-bgp.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
fail() { echo "FAIL: $1"; exit 1; }
ok() { PASS=$((PASS + 1)); echo "ok: $1"; }

command -v python3 >/dev/null 2>&1 || { echo "SKIP: no python3"; exit 0; }
bash -n "$BGP" || fail "bash -n netrun-bgp.sh"

# ── stubs ─────────────────────────────────────────────────────────
STUB="$TMP/bin"; mkdir -p "$STUB"
export MAC_FILE="$TMP/mac" STUB_LOG="$TMP/calls.log" ROUTES="$TMP/routes" BIRD_ACTIVE="$TMP/bird.active" BIRD_REJECT="$TMP/bird.reject" BIRD_SESSION="$TMP/bird.session" \
       BIRD_LOADED="$TMP/bird.loaded" BIRD_CONFIGURE_FAIL="$TMP/bird.configure_fail"
: > "$STUB_LOG"; : > "$ROUTES"; : > "$TMP/bird.loaded"
cat > "$STUB/ip" <<'EOF'
#!/usr/bin/env bash
echo "ip $*" >> "$STUB_LOG"
case "$*" in
  # As on Chicago 2026-10-08: source selection picks a customer anchor, not the main IP.
  "-6 route get 2001:19f0:ffff::1") echo "2001:19f0:ffff::1 from :: via fe80::fc00:6ff:febe:b5cf dev enp1s0 proto ra src 2001:19f0:5c01:cdf:de36:ffce:a778:84c9 metric 100 pref medium" ;;
  "-o link show dev enp1s0") echo "2: enp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq state UP mode DEFAULT group default qlen 1000\    link/ether $(cat "$MAC_FILE" 2>/dev/null || echo 56:00:06:be:b5:cf) brd ff:ff:ff:ff:ff:ff" ;;
  "-6 -o addr show dev enp1s0 scope global")
    echo "2: enp1s0    inet6 2001:19f0:5c01:cdf:de36:ffce:a778:84c9/128 scope global nodad \       valid_lft forever preferred_lft forever"
    echo "2: enp1s0    inet6 2001:19f0:5c01:cdf:5400:6ff:febe:b5cf/64 scope global mngtmpaddr noprefixroute \       valid_lft forever preferred_lft forever"
    echo "2: enp1s0    inet6 2001:19f0:5c01:cdf:1111:2222:3333:4444/128 scope global nodad \       valid_lft forever preferred_lft forever" ;;
  "-4 route get 1.1.1.1") echo "1.1.1.1 via 64.177.12.1 dev enp1s0 src 64.177.12.242 uid 0" ;;
  "-6 route show table local dev lo")
    echo "local ::1 proto kernel metric 0 pref medium"
    sed 's/^/local /; s/$/ metric 1024 pref medium/' "$ROUTES" ;;
  "-6 route replace local "*" dev lo") p="${5}"; grep -qx "$p" "$ROUTES" || echo "$p" >> "$ROUTES" ;;
  "-6 route del local "*" dev lo") p="${5}"; grep -vx "$p" "$ROUTES" > "$ROUTES.tmp"; mv "$ROUTES.tmp" "$ROUTES" ;;
  *) echo "ip stub: unexpected: $*" >&2; exit 2 ;;
esac
EOF
cat > "$STUB/bird" <<'EOF'
#!/usr/bin/env bash
echo "bird $*" >> "$STUB_LOG"
[ -f "$BIRD_REJECT" ] && { echo "bird: syntax error" >&2; exit 1; }
exit 0
EOF
# BIRD's loaded config is $BIRD_LOADED (the static routes it announces): read from
# bird.conf at start / configure; $BIRD_CONFIGURE_FAIL makes the next configure fail.
cat > "$STUB/birdc" <<'EOF'
#!/usr/bin/env bash
echo "birdc $*" >> "$STUB_LOG"
case "$*" in
  configure)
    if [ -f "$BIRD_CONFIGURE_FAIL" ]; then rm -f "$BIRD_CONFIGURE_FAIL"; echo "8002 $NETRUN_BGP_BIRD_CONF: Permission denied"; exit 1; fi
    awk '$1 == "route" {print $2}' "$NETRUN_BGP_BIRD_CONF" > "$BIRD_LOADED"
    echo "Reading configuration from $NETRUN_BGP_BIRD_CONF"; echo "Reconfigured" ;;
  "show route protocol netrun_v6")
    echo "Table master6:"
    while read -r r; do [ -n "$r" ] && echo "$r            unreachable [netrun_v6 13:29:04.000] * (200)"; done < "$BIRD_LOADED" ;;
  "show protocols vultr6")
    echo "Name       Proto      Table      State  Since         Info"
    echo "vultr6     BGP        ---        up     00:48:49.386  $(cat "$BIRD_SESSION" 2>/dev/null || echo Established)" ;;
esac
EOF
cat > "$STUB/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "systemctl $*" >> "$STUB_LOG"
case "$*" in
  "is-active --quiet bird") [ -f "$BIRD_ACTIVE" ] ;;
  "start bird") touch "$BIRD_ACTIVE"; awk '$1 == "route" {print $2}' "$NETRUN_BGP_BIRD_CONF" > "$BIRD_LOADED" ;;
  *) exit 0 ;;
esac
EOF
cat > "$STUB/apt-get" <<'EOF'
#!/usr/bin/env bash
echo "apt-get $*" >> "$STUB_LOG"
EOF
# nft: `-c -f` rejects while $NFT_REJECT exists; `-f` loads the guard table.
export NFT_LOADED="$TMP/nft.loaded" NFT_REJECT="$TMP/nft.reject"
cat > "$STUB/nft" <<'EOF'
#!/usr/bin/env bash
echo "nft $*" >> "$STUB_LOG"
case "$*" in
  "-c -f "*) [ ! -f "$NFT_REJECT" ] ;;
  "-f "*) cp "$2" "$NFT_LOADED" ;;
  "list table inet netrun_bgp_guard") [ -f "$NFT_LOADED" ] && cat "$NFT_LOADED" ;;
  *) exit 1 ;;
esac
EOF
cat > "$STUB/proxy-guard" <<'EOF'
#!/usr/bin/env bash
echo "proxy-guard $*" >> "$STUB_LOG"
EOF
chmod +x "$STUB"/*
export PATH="$STUB:$PATH"

export NETRUN_BGP_ENV_FILE="$TMP/netrun.env" NETRUN_BGP_BIRD_CONF="$TMP/bird/bird.conf" \
       NETRUN_BGP_UNIT_DIR="$TMP/systemd" NETRUN_BGP_LIST_FILE="$TMP/bgp-prefixes" \
       NETRUN_BGP_SELF="$TMP/sbin/netrun-bgp" NETRUN_BGP_WITHDRAW_WAIT=0 \
       NETRUN_BGP_GUARD_FILE="$TMP/netrun/nft-bgp-guard.nft" NETRUN_BGP_PROXY_GUARD="$STUB/proxy-guard"
cat > "$NETRUN_BGP_ENV_FILE" <<'EOF'
NETRUN_IPV6_ROUTED_PREFIX=2602:f2dc:a9::/48
NETRUN_BGP_LOCAL_ASN=4288000384
NETRUN_BGP_PASSWORD="s3cret-Pass"
EOF
run() { bash "$BGP" "$@"; }

# ── part 1: canonical_prefixes ────────────────────────────────────
canon() { NETRUN_BGP_SOURCED=1 bash -c 'source "$1"; shift; canonical_prefixes "$1"' _ "$BGP" "$1"; }
[ "$(canon "2602:F2DC:A9:0::5/48")" = "2602:f2dc:a9::/48" ] || fail "canonical: host bits cleared, lower case"
[ "$(canon "2602:f2dc:b0::/48, 2602:f2dc:a9::/48 2602:f2dc:a9::/48")" = $'2602:f2dc:a9::/48\n2602:f2dc:b0::/48' ] \
  || fail "canonical: sorted, deduplicated"
[ "$(canon "2602:f2dc:a900::/40 2602:f2dc:a9ab::/48")" = "2602:f2dc:a900::/40" ] || fail "canonical: a covered prefix is dropped"
for bad in "2602:f2dc:a9::/49" "2602::/31" "10.0.0.0/24" "nope/48"; do
  canon "$bad" >/dev/null 2>&1 && fail "canonical accepts $bad"
done
ok "canonical_prefixes: canonical, sorted, deduplicated; /32../48 IPv6 only"

# ── part 2: dry run touches nothing ───────────────────────────────
out="$(run apply --dry-run)" || fail "dry run failed: $out"
[ ! -e "$NETRUN_BGP_BIRD_CONF" ] && [ ! -e "$NETRUN_BGP_UNIT_DIR" ] && [ ! -e "$NETRUN_BGP_LIST_FILE" ] || fail "dry run wrote files"
grep -q "route replace" "$STUB_LOG" && fail "dry run added a route"
echo "$out" | grep -q "bird.conf: would be created" || fail "dry run report: $out"
echo "$out" | grep -q "netrun-bgp-prefix.service: would be created" || fail "dry run names the unit: $out"
echo "$out" | grep -q "router id 64.177.12.242, source 2001:19f0:5c01:cdf:5400:6ff:febe:b5cf, AS 4288000384" || fail "dry run shows the session: $out"
[ ! -e "$NETRUN_BGP_SELF" ] || fail "dry run installed the copy"
echo "$out" | grep -q "local route missing now: 2602:f2dc:a9::/48" || fail "dry run names the missing route"
ok "apply --dry-run: reports, writes nothing, adds no route"

# ── part 3: first apply ───────────────────────────────────────────
: > "$STUB_LOG"
out="$(run apply)" || fail "apply failed: $out"
grep -qx "2602:f2dc:a9::/48" "$ROUTES" || fail "local route added"
route_line=$(grep -n "ip -6 route replace local 2602:f2dc:a9::/48 dev lo" "$STUB_LOG" | head -1 | cut -d: -f1)
start_line=$(grep -n "systemctl start bird" "$STUB_LOG" | head -1 | cut -d: -f1)
[ -n "$route_line" ] && [ -n "$start_line" ] && [ "$route_line" -lt "$start_line" ] || fail "the route comes before bird starts"
grep -q "bird -p -c" "$STUB_LOG" || fail "the config is checked with bird -p"
grep -q 'password "s3cret-Pass";' "$NETRUN_BGP_BIRD_CONF" || fail "password in bird.conf"
[ "$(stat -c %a "$NETRUN_BGP_BIRD_CONF" 2>/dev/null || stat -f %Lp "$NETRUN_BGP_BIRD_CONF")" = "640" ] || fail "bird.conf is 0640"
unit="$NETRUN_BGP_UNIT_DIR/netrun-bgp-prefix.service"
grep -qx "ExecStart=/sbin/ip -6 route replace local 2602:f2dc:a9::/48 dev lo" "$unit" || fail "unit ExecStart"
grep -qx "ExecStop=-/sbin/ip -6 route del local 2602:f2dc:a9::/48 dev lo" "$unit" || fail "unit ExecStop"
grep -q "^Before=netrun-3proxy-restore.service bird.service" "$unit" || fail "unit ordering"
dropin="$NETRUN_BGP_UNIT_DIR/bird.service.d/netrun.conf"
grep -qx "Requires=netrun-bgp-prefix.service" "$dropin" && grep -qx "After=netrun-bgp-prefix.service" "$dropin" || fail "bird drop-in"
grep -qx "Restart=always" "$dropin" && grep -qx "RestartSec=5" "$dropin" || fail "bird drop-in restarts BIRD whatever the exit"
[ "$(cat "$NETRUN_BGP_LIST_FILE")" = "2602:f2dc:a9::/48" ] || fail "prefix list file"
cmp -s "$BGP" "$NETRUN_BGP_SELF" && [ -x "$NETRUN_BGP_SELF" ] || fail "netrun-bgp copy installed"
ok "apply: route first, checked config, 0640 bird.conf, boot unit, bird drop-in (+ Restart=always), list file, netrun-bgp copy"

# The :179 guard: only the neighbour, loaded (after nft -c) before BIRD starts,
# re-applied at boot; the 3proxy egress guard refreshed after the apply.
grep -qx "    tcp dport 179 ip6 saddr 2001:19f0:ffff::1 accept" "$NETRUN_BGP_GUARD_FILE" \
  && grep -qx "    tcp dport 179 drop" "$NETRUN_BGP_GUARD_FILE" || fail ":179 guard rules: $(cat "$NETRUN_BGP_GUARD_FILE")"
grep -q "type filter hook input priority filter - 20; policy accept;" "$NETRUN_BGP_GUARD_FILE" || fail ":179 guard hook"
[ "$(sed -n '3,5p' "$NETRUN_BGP_GUARD_FILE" | tr '\n' '|')" = "table inet netrun_bgp_guard|delete table inet netrun_bgp_guard|table inet netrun_bgp_guard {|" ] \
  || fail ":179 guard is one transaction (add + delete + define)"
cmp -s "$NETRUN_BGP_GUARD_FILE" "$NFT_LOADED" || fail ":179 guard loaded"
chk=$(grep -n "nft -c -f" "$STUB_LOG" | head -1 | cut -d: -f1)
load=$(grep -n "nft -f $NETRUN_BGP_GUARD_FILE" "$STUB_LOG" | head -1 | cut -d: -f1)
[ -n "$chk" ] && [ -n "$load" ] && [ "$chk" -lt "$load" ] && [ "$load" -lt "$start_line" ] || fail "order: nft -c ($chk) < guard load ($load) < bird start ($start_line)"
grep -qx "ExecStartPost=-.*nft -f $NETRUN_BGP_GUARD_FILE" "$NETRUN_BGP_UNIT_DIR/nftables.service.d/netrun-bgp-guard.conf" || fail ":179 guard boot drop-in"
grep -qx "proxy-guard apply" "$STUB_LOG" || fail "the 3proxy egress guard is refreshed"
ok ":179 guard: only the neighbour, checked + loaded before BIRD starts, boot drop-in; proxy guard refreshed"

# The body (after the 3 comment lines) equals the hand-made Chicago config of
# 2026-10-08 (password replaced): an apply on Chicago changes nothing BIRD cares about.
expected_body='log syslog all;
router id 64.177.12.242;

protocol device {
  scan time 60;
}

protocol static netrun_v6 {
  ipv6;
  route 2602:f2dc:a9::/48 unreachable;
}

protocol bgp vultr6 {
  description "Vultr IPv6";
  local 2001:19f0:5c01:cdf:5400:6ff:febe:b5cf as 4288000384;
  neighbor 2001:19f0:ffff::1 as 64515;
  multihop 2;
  password "s3cret-Pass";
  graceful restart on;
  ipv6 {
    import none;
    export where proto = "netrun_v6";
  };
}'
[ "$(tail -n +4 "$NETRUN_BGP_BIRD_CONF")" = "$expected_body" ] || { diff <(tail -n +4 "$NETRUN_BGP_BIRD_CONF") <(echo "$expected_body"); fail "bird.conf body differs from Chicago's"; }
ok "bird.conf body = the live Chicago config"

# ── part 4: idempotent ────────────────────────────────────────────
: > "$STUB_LOG"
out="$(run apply)" || fail "second apply failed"
echo "$out" | grep -q "bird.conf unchanged" || fail "second apply rewrote bird.conf"
grep -q "birdc configure" "$STUB_LOG" && fail "second apply reconfigured bird"
grep -q "daemon-reload" "$STUB_LOG" && fail "second apply reloaded systemd"
[ ! -e "$NETRUN_BGP_BIRD_CONF.netrun-prev" ] || fail "no backup when nothing changed"
out="$(run apply --dry-run)" || fail "dry run after apply"
[ "$(echo "$out" | grep -c ": unchanged$")" = 4 ] || fail "dry run after apply: bird.conf, unit, drop-in, :179 guard unchanged: $out"
echo "$out" | grep -q "s3cret" && fail "dry run printed the password"
ok "apply again: nothing rewritten, no reconfigure, no daemon-reload; dry run: 4 × unchanged"

# ── part 5: prefix change — add before announce, withdraw before removal ──
sed -i.bak 's#^NETRUN_IPV6_ROUTED_PREFIX=.*#NETRUN_BGP_PREFIXES=2602:f2dc:b0::/48#' "$NETRUN_BGP_ENV_FILE"
: > "$STUB_LOG"
out="$(run apply)" || fail "apply with a new prefix failed: $out"
add=$(grep -n "route replace local 2602:f2dc:b0::/48" "$STUB_LOG" | head -1 | cut -d: -f1)
conf=$(grep -n "birdc configure" "$STUB_LOG" | head -1 | cut -d: -f1)
del=$(grep -n "route del local 2602:f2dc:a9::/48" "$STUB_LOG" | head -1 | cut -d: -f1)
[ -n "$add" ] && [ -n "$conf" ] && [ -n "$del" ] && [ "$add" -lt "$conf" ] && [ "$conf" -lt "$del" ] \
  || fail "order: new route ($add) < reconfigure ($conf) < old route removed ($del)"
[ "$(cat "$ROUTES")" = "2602:f2dc:b0::/48" ] || fail "routes after the change: $(cat "$ROUTES")"
grep -q "route 2602:f2dc:b0::/48 unreachable;" "$NETRUN_BGP_BIRD_CONF" && ! grep -q "2602:f2dc:a9::" "$NETRUN_BGP_BIRD_CONF" \
  || fail "bird.conf announces only the new prefix"
[ -f "$NETRUN_BGP_BIRD_CONF.netrun-prev" ] || fail "the previous bird.conf is kept"
echo "$out" | grep -q "withdrawn: 2602:f2dc:a9::/48 — local routes go in 0s" || fail "withdraw logged: $out"
grep -qx "ExecStart=/sbin/ip -6 route replace local 2602:f2dc:b0::/48 dev lo" "$unit" && ! grep -q "2602:f2dc:a9::" "$unit" || fail "unit follows the prefix"
ok "prefix change: new route → reconfigure → old route removed; previous config kept"

out="$(NETRUN_BGP_PASSWORD=0ther-Pass run apply --dry-run)" || fail "dry run with a new password"
echo "$out" | grep -q "s3cret\|0ther" && fail "dry run diff printed a password: $out"
echo "$out" | grep -q "bird.conf: only the password changes" || fail "a password-only change is named: $out"

# ── part 6: a config bird rejects changes nothing in BIRD ─────────
touch "$BIRD_REJECT"
sed -i.bak 's#^NETRUN_BGP_PREFIXES=.*#NETRUN_BGP_PREFIXES=2602:f2dc:c0::/48#' "$NETRUN_BGP_ENV_FILE"
before="$(cat "$NETRUN_BGP_BIRD_CONF")"
: > "$STUB_LOG"
run apply >/dev/null 2>&1 && fail "apply succeeded with a rejected config"
[ "$(cat "$NETRUN_BGP_BIRD_CONF")" = "$before" ] || fail "rejected config was written"
grep -q "birdc configure" "$STUB_LOG" && fail "rejected config was loaded"
grep -q "route del" "$STUB_LOG" && fail "an announced prefix lost its route"
grep -q "route replace" "$STUB_LOG" && fail "a rejected apply added a route"
grep -q "2602:f2dc:c0::" "$NETRUN_BGP_UNIT_DIR/netrun-bgp-prefix.service" && fail "a rejected apply rewrote the boot unit"
rm -f "$BIRD_REJECT"
sed -i.bak 's#^NETRUN_BGP_PREFIXES=.*#NETRUN_BGP_PREFIXES=2602:f2dc:b0::/48#' "$NETRUN_BGP_ENV_FILE"
run apply >/dev/null || fail "recovery apply"
ok "bird -p rejects: nothing changes — no route, no unit, no bird.conf, no reconfigure"


# ── part 6b: a failed configure is loud, keeps the old route, and the rerun heals ──
sed -i.bak 's#^NETRUN_BGP_PREFIXES=.*#NETRUN_BGP_PREFIXES=2602:f2dc:d0::/48#' "$NETRUN_BGP_ENV_FILE"
touch "$BIRD_CONFIGURE_FAIL"
: > "$STUB_LOG"
out="$(run apply 2>&1)" && fail "apply passed with a failed configure: $out"
echo "$out" | grep -q "birdc configure failed: .*Permission denied.*keep their local routes" || fail "loud configure failure: $out"
grep -qx "2602:f2dc:b0::/48" "$ROUTES" || fail "the old, still announced prefix lost its route"
[ "$(cat "$NETRUN_BGP_LIST_FILE")" = "2602:f2dc:b0::/48" ] || fail "the list moved on without BIRD"
: > "$STUB_LOG"
out="$(run apply)" || fail "rerun after a failed configure: $out"
echo "$out" | grep -q "bird.conf unchanged" || fail "rerun: bird.conf is already the new one"
grep -q "birdc configure" "$STUB_LOG" || fail "rerun: BIRD still holds the old list → configure again"
[ "$(cat "$ROUTES")" = "2602:f2dc:d0::/48" ] && [ "$(cat "$BIRD_LOADED")" = "2602:f2dc:d0::/48" ] || fail "rerun: routes $(cat "$ROUTES") / BIRD $(cat "$BIRD_LOADED")"
ok "a failed configure: loud, old route kept, list unchanged; the rerun reconfigures (BIRD differs) and then withdraws"

# ── part 6c: none = withdraw everything (a /48 moving to another node) ──
sed -i.bak 's#^NETRUN_BGP_PREFIXES=.*#NETRUN_BGP_PREFIXES=none#' "$NETRUN_BGP_ENV_FILE"
: > "$STUB_LOG"
out="$(run apply)" || fail "apply none: $out"
[ -s "$ROUTES" ] && fail "routes left after none: $(cat "$ROUTES")"
[ -s "$BIRD_LOADED" ] && fail "BIRD still announces: $(cat "$BIRD_LOADED")"
grep -q "unreachable" "$NETRUN_BGP_BIRD_CONF" && fail "bird.conf still has a route"
grep -qx "ExecStart=/bin/true" "$NETRUN_BGP_UNIT_DIR/netrun-bgp-prefix.service" || fail "unit without prefixes needs an ExecStart"
echo "$out" | grep -q "announced: none" || fail "none: $out"
[ "$(run check)" = "ok" ] || fail "check with no prefixes: the session only"
sed -i.bak 's#^NETRUN_BGP_PREFIXES=.*#NETRUN_BGP_PREFIXES=2602:f2dc:b0::/48#' "$NETRUN_BGP_ENV_FILE"
run apply >/dev/null || fail "back from none"
ok "NETRUN_BGP_PREFIXES=none: withdrawn from BIRD, then the routes; unit ExecStart=/bin/true; check = session only"

# ── part 6d: password quoting and netrun.env permissions ──
cp "$NETRUN_BGP_ENV_FILE" "$TMP/env.keep"
printf "NETRUN_BGP_PASSWORD=it's-fine'\n" >> "$NETRUN_BGP_ENV_FILE"
[ "$(NETRUN_BGP_SOURCED=1 bash -c 'source "$1"; setting NETRUN_BGP_PASSWORD' _ "$BGP")" = "it's-fine'" ] || fail "a lone trailing apostrophe was stripped"
printf "NETRUN_BGP_PASSWORD='quoted pw'\n" >> "$NETRUN_BGP_ENV_FILE"
[ "$(NETRUN_BGP_SOURCED=1 bash -c 'source "$1"; setting NETRUN_BGP_PASSWORD' _ "$BGP")" = "quoted pw" ] || fail "a quoted value keeps its quotes"
cp "$TMP/env.keep" "$NETRUN_BGP_ENV_FILE"; chmod 0644 "$NETRUN_BGP_ENV_FILE"
out="$(run apply)" || fail "apply for perms"
[ "$(stat -c %a "$NETRUN_BGP_ENV_FILE" 2>/dev/null || stat -f %Lp "$NETRUN_BGP_ENV_FILE")" = "600" ] || fail "netrun.env with the password is not 0600"
echo "$out" | grep -q "mode 644 -> 600" || fail "the chmod is logged: $out"
ok "setting(): only a matching quote pair is stripped; netrun.env holding the password becomes 0600"

# ── part 6e: a write that fails stops the apply ──
chmod 0555 "$NETRUN_BGP_UNIT_DIR"
sed -i.bak 's#^NETRUN_BGP_PREFIXES=.*#NETRUN_BGP_PREFIXES=2602:f2dc:e0::/48#' "$NETRUN_BGP_ENV_FILE"
out="$(run apply 2>&1)" && fail "apply passed with an unwritable unit dir"
echo "$out" | grep -q "ERROR: cannot create a temp file next to" || fail "write failure message: $out"
grep -q "2602:f2dc:e0::" "$NETRUN_BGP_BIRD_CONF" && fail "bird.conf written after a failed unit write"
chmod 0755 "$NETRUN_BGP_UNIT_DIR"
sed -i.bak 's#^NETRUN_BGP_PREFIXES=.*#NETRUN_BGP_PREFIXES=2602:f2dc:b0::/48#' "$NETRUN_BGP_ENV_FILE"
run apply >/dev/null || fail "recovery after the write failure"
ip -6 route del local 2602:f2dc:e0::/48 dev lo 2>/dev/null || true
ok "a failed write dies before BIRD is touched"

# ── part 7: settings validation ───────────────────────────────────
cp "$NETRUN_BGP_ENV_FILE" "$TMP/env.ok"
for bad in 'NETRUN_BGP_PASSWORD=has"quote' 'NETRUN_BGP_LOCAL_ASN=abc' 'NETRUN_BGP_PREFIXES=2602:f2dc:b0::/56'; do
  cp "$TMP/env.ok" "$NETRUN_BGP_ENV_FILE"; echo "$bad" >> "$NETRUN_BGP_ENV_FILE"
  run apply --dry-run >/dev/null 2>&1 && fail "accepted $bad"
done
cp "$TMP/env.ok" "$NETRUN_BGP_ENV_FILE"
ok "rejects a quote in the password, a non-numeric ASN, a /56"

# ── part 7b: the BGP source is the EUI-64 main IP, never a customer anchor ──
echo "56:00:06:00:00:01" > "$MAC_FILE"
out="$(run apply --dry-run 2>&1)" && fail "apply without an EUI-64 address passed: $out"
echo "$out" | grep -q "set NETRUN_BGP_SOURCE6" || fail "names the setting: $out"
out="$(NETRUN_BGP_SOURCE6=2001:db8::5 run apply --dry-run)" || fail "explicit source"
echo "$out" | grep -q "source 2001:db8::5," || fail "explicit source used: $out"
rm -f "$MAC_FILE"
ok "source: the EUI-64 address (not the anchor route get picks); none → error unless NETRUN_BGP_SOURCE6"

# ── part 7c: a guard nft rejects stops the apply before BIRD ─────────
touch "$NFT_REJECT"; : > "$STUB_LOG"
out="$(run apply 2>&1)" && fail "apply passed with nft rejecting the :179 guard"
echo "$out" | grep -q "nft rejects the :179 guard" || fail "reason: $out"
grep -q "birdc configure\|systemctl start bird" "$STUB_LOG" && fail "BIRD touched after a rejected guard"
rm -f "$NFT_REJECT"
ok "a :179 guard nft rejects: the apply stops before BIRD is touched"

# ── part 8: check ─────────────────────────────────────────────────
[ "$(run check)" = "ok" ] || fail "check ok"
mv "$NFT_LOADED" "$NFT_LOADED.keep"
run check >/dev/null && fail "check passes without the :179 guard"
mv "$NFT_LOADED.keep" "$NFT_LOADED"
echo "Active" > "$BIRD_SESSION"
run check >/dev/null && fail "check passes without an Established session"
echo "Established" > "$BIRD_SESSION"
: > "$ROUTES"
run check >/dev/null && fail "check passes without the local route"
ok "check: ok only with every route and an Established session"

echo "PASS ($PASS)"
