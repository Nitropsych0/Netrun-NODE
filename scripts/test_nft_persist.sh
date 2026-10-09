#!/usr/bin/env bash
# netrun-nft-persist (audit 2026-10-08): `save` = temp 0600 + `nft -c -f` +
# rename (never a torn /etc/nftables.conf), the whole previous file kept as
# .prev, an empty ruleset refused unless --allow-empty, a rejected dump
# changes nothing; `boot-load` falls back to .prev when the main file is empty
# or rejected; `install` writes the nftables.service drop-in once. And no
# writer in the repo still dumps the ruleset straight into the file.
# nft / systemctl are stubs on PATH. No root.
#   bash scripts/test_nft_persist.sh
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd -P)"
P="$ROOT_DIR/scripts/netrun-nft-persist.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
fail() { echo "FAIL: $1"; exit 1; }
ok() { PASS=$((PASS + 1)); echo "ok: $1"; }
mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }

bash -n "$P" || fail "bash -n netrun-nft-persist.sh"

STUB="$TMP/bin"; mkdir -p "$STUB"
export STUB_LOG="$TMP/calls.log" RULESET="$TMP/ruleset.live"
: > "$STUB_LOG"
# `list ruleset` prints $RULESET; `-c -f F` rejects a file containing BAD;
# `-f F` only records which file was loaded.
cat > "$STUB/nft" <<'STUB'
#!/usr/bin/env bash
echo "nft $*" >> "$STUB_LOG"
case "$*" in
  "list ruleset") cat "$RULESET" ;;
  "-c -f "*) ! grep -q BAD "$3" ;;
  "-f "*) echo "LOADED $2" >> "$STUB_LOG" ;;
  *) exit 1 ;;
esac
STUB
cat > "$STUB/systemctl" <<'STUB'
#!/usr/bin/env bash
echo "systemctl $*" >> "$STUB_LOG"
STUB
chmod +x "$STUB"/*
export PATH="$STUB:$PATH"
mkdir -p "$TMP/etc"
export NETRUN_NFT_CONF="$TMP/etc/nftables.conf" NETRUN_NFT_LOCK="$TMP/run/persist.lock" \
       NETRUN_NFT_UNIT_DIR="$TMP/systemd" NETRUN_NFT_SELF="$TMP/sbin/netrun-nft-persist"
C="$NETRUN_NFT_CONF"
ruleset() { printf 'table inet proxy_accounting {\n\tchain input {\n\t\tcounter name "%s"\n\t}\n}\n' "$1" > "$RULESET"; }

# ── 1. save ───────────────────────────────────────────────────────
ruleset gen1
bash "$P" save || fail "first save"
[ "$(cat "$C")" = "$(cat "$RULESET")" ] || fail "saved = live ruleset"
[ "$(mode_of "$C")" = 600 ] || fail "saved 0600 (was 0755 on the nodes)"
[ ! -e "$C.prev" ] || fail "no .prev before there was a file"
grep -q '^nft -c -f ' "$STUB_LOG" || fail "the dump is checked with nft -c"
ruleset gen2
bash "$P" save || fail "second save"
grep -q gen2 "$C" && grep -q gen1 "$C.prev" || fail ".prev = the previous whole file"
[ "$(mode_of "$C.prev")" = 600 ] || fail ".prev 0600"
ls -a "$TMP/etc" | grep -q '^\.nftables\.conf\.' && fail "temp file left behind"
ok "save: live ruleset -> 0600 file via temp + rename; the previous file becomes .prev"

# ── 2. refusals keep the file ─────────────────────────────────────
: > "$RULESET"
bash "$P" save 2>/dev/null && fail "an empty ruleset was saved"
grep -q gen2 "$C" || fail "empty ruleset changed the file"
printf 'table ip x {\n BAD\n}\n' > "$RULESET"
out="$(bash "$P" save 2>&1)" && fail "a dump nft -c rejects was saved"
echo "$out" | grep -q "nft -c rejects" || fail "reason: $out"
grep -q gen2 "$C" && grep -q gen1 "$C.prev" || fail "a rejected dump touched the file or .prev"
: > "$RULESET"
bash "$P" save --allow-empty || fail "--allow-empty"
[ "$(cat "$C")" = "# netrun-nft-persist: empty ruleset" ] || fail "empty marker: $(cat "$C")"
grep -q gen2 "$C.prev" || fail ".prev after --allow-empty"
ok "refused: empty ruleset (unless --allow-empty: a marker line), a dump nft -c rejects"

# ── 3. a torn main file is never promoted to .prev ────────────────
ruleset gen3; bash "$P" save || fail "save gen3"
ruleset gen3b; bash "$P" save || fail "save gen3b"     # .prev = gen3
printf 'table inet proxy_accounting {\n\tchain inp' > "$C"     # torn by an old in-place writer
ruleset gen4; bash "$P" save || fail "save gen4"
grep -q gen3 "$C.prev" || fail "the torn file replaced the whole .prev: $(cat "$C.prev")"
ok "a torn main file is replaced but never becomes .prev"

# ── 4. boot-load ──────────────────────────────────────────────────
boot() { : > "$STUB_LOG"; bash "$P" boot-load 2>/dev/null; grep '^LOADED' "$STUB_LOG" | awk '{print $2}'; }
[ "$(boot)" = "$C" ] || fail "boot: valid main file loaded"
: > "$C"
[ "$(boot)" = "$C.prev" ] || fail "boot: empty main -> .prev"
printf 'table ip x {\n BAD\n}\n' > "$C"
[ "$(boot)" = "$C.prev" ] || fail "boot: rejected main -> .prev"
printf 'BAD\n' > "$C.prev"
[ "$(boot)" = "$C" ] || fail "boot: both bad -> the main file as before (the unit fails like it used to)"
ok "boot-load: main when nft -c accepts it, else .prev, else main as is"

# ── 5. install ────────────────────────────────────────────────────
: > "$STUB_LOG"
bash "$P" install 2>/dev/null || fail "install"
D="$TMP/systemd/nftables.service.d/netrun-boot-fallback.conf"
grep -qx 'ExecStart=' "$D" && grep -q "^ExecStart=/bin/sh -c 'if \[ -x $NETRUN_NFT_SELF \]; then exec $NETRUN_NFT_SELF boot-load" "$D" \
  || fail "drop-in resets ExecStart to boot-load: $(cat "$D")"
cmp -s "$P" "$NETRUN_NFT_SELF" || fail "installed copy"
grep -q "systemctl daemon-reload" "$STUB_LOG" || fail "daemon-reload after a new drop-in"
: > "$STUB_LOG"
bash "$P" install 2>/dev/null || fail "install again"
grep -q "daemon-reload" "$STUB_LOG" && fail "install again reloaded systemd"
ok "install: copy + drop-in (ExecStart= reset, boot-load with a plain nft fallback), idempotent"

# ── 6. every writer goes through the helper ───────────────────────
bad="$(cd "$ROOT_DIR" && grep -rn 'nft list ruleset >' --include='*.sh' --include='*.js' . \
  | grep -v '/docs/' | grep -v 'scripts/test_' | grep -v 'scripts/smoke_' | grep -v '\.test\.js:' | grep -v '^\./scripts/netrun-nft-persist\.sh:' \
  | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(#|//)' \
  | grep -v '> "\$t"' || true)"
[ -z "$bad" ] || fail "writers still dump the ruleset in place:
$bad"
ok "no writer dumps the ruleset straight into /etc/nftables.conf"

echo "PASS ($PASS)"
