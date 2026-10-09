# shellcheck shell=bash
# scripts/lib/pergb_pool.sh — pay-per-GB v2, AMENDMENT A1 (2026-10-09): the
# per-GB address pool as bash per-piece allocators see it. Sourced by the
# generator (node_runtime/soft/generator/proxyyy_automated.sh); bash 4+, no
# `set -e` assumptions, nothing runs at source time.
#
# On a per-GB node the routed /48 is ONE pool owned by netrun-radius. The node
# file ${NETRUN_PERGB_POOL_FILE:-/etc/netrun/pergb-pool.conf} (KEY=VALUE:
# PREFIX=<the /48>, POOL=0000-fffe, ENABLED=1; written by /pergb/enable,
# removed by /pergb/disable) says so. With it, a per-piece allocator takes a
# /64 of the pool ONLY through the agent's POST /pergb/reserve_nets (one /64
# per address) and fails when that call fails — never a blind pick. Without
# it (per-GB off) nothing changes. /64s of the prefix outside POOL (none with
# the default) stay per-piece's own and are picked locally as before.
#
# The agent key reaches curl in a 0600 header file, never on its command line
# (/proc/<pid>/cmdline is readable by every local uid, 3proxy's 65535 too):
# NODE_AGENT_API_KEY when the agent passed its environment on (the generator
# runs under /generate), else the unit drop-in, like watchdog_probe.sh.
#
#   pergb_pool_state            -> "off" | "on" | "unreadable"
#   pergb_pool_value KEY        -> KEY's value in the pool file ("" when absent)
#   pergb_reserve_nets N REF    -> the N lent /64s, one per line (as the agent
#                                  answered: a subnet id or "<net>/64"); fails
#                                  closed (non-zero, nothing on stdout). N above
#                                  5000 (the per-call limit) goes in calls of
#                                  <= 5000 under REF:c1, REF:c2, ... (each
#                                  idempotent: a retry gets the same /64s)
#   pergb_release_nets REF NET… -> hands /64s back (0 = the agent accepted)

pergb_pool_file() {
  printf '%s' "${NETRUN_PERGB_POOL_FILE:-/etc/netrun/pergb-pool.conf}"
}

pergb_pool_value() {
  local f
  f="$(pergb_pool_file)"
  [ -r "$f" ] || return 0
  awk -v k="$1" '
    { sub(/^[ \t]+/, "") }
    /^#/ { next }
    index(toupper($0), k "=") == 1 { v = substr($0, length(k) + 2) }
    END { gsub(/^["\047 \t]+|["\047 \t\r]+$/, "", v); print v }' "$f"
}

pergb_pool_state() {
  local f
  f="$(pergb_pool_file)"
  if [ ! -e "$f" ]; then echo off; return 0; fi
  if [ ! -r "$f" ]; then echo unreadable; return 0; fi
  case "$(pergb_pool_value ENABLED | tr '[:upper:]' '[:lower:]')" in
    0|false|no|off) echo off ;;
    *) echo on ;;
  esac
}

pergb_agent_key() {
  local k="${NODE_AGENT_API_KEY:-}" f="${NETRUN_AGENT_KEY_FILE:-/etc/systemd/system/netrun-node-agent.service.d/20-api-key.conf}"
  if [ -z "$k" ] && [ -r "$f" ]; then
    k="$(sed -n 's/^Environment=NODE_AGENT_API_KEY=//p' "$f" 2>/dev/null | tail -n1)"
    k="${k%\"}"; k="${k#\"}"
  fi
  printf '%s' "$k"
}

# pergb_agent_post ROUTE JSON -> the response body on stdout; 0 on HTTP 2xx.
pergb_agent_post() {
  local route="$1" body="$2" key hdr out code rc=0 tmp="${TMPDIR:-/tmp}"
  key="$(pergb_agent_key)"
  if [ -z "$key" ]; then
    echo "pergb: no agent key (NODE_AGENT_API_KEY / the agent unit drop-in)" >&2
    return 1
  fi
  hdr="$(umask 077; mktemp "$tmp/netrun-pergb-hdr.XXXXXX")" || return 1
  out="$(umask 077; mktemp "$tmp/netrun-pergb-out.XXXXXX")" || { rm -f "$hdr"; return 1; }
  # mktemp creates 0600; the key only ever goes into this file
  printf 'X-API-KEY: %s\nContent-Type: application/json\n' "$key" > "$hdr"
  code="$(printf '%s' "$body" | curl --silent --show-error --output "$out" --write-out '%{http_code}' \
    --max-time "${NETRUN_PERGB_AGENT_TIMEOUT:-60}" -H "@$hdr" --data-binary @- \
    "${NETRUN_PERGB_AGENT_URL:-http://127.0.0.1:8085}$route")" || rc=1
  cat "$out" 2>/dev/null
  rm -f "$hdr" "$out"
  [ "$rc" = 0 ] || return 1
  case "$code" in 2??) return 0 ;; *) return 1 ;; esac
}

pergb_reserve_nets() {
  local count="$1" ref="$2" left i=0 n out
  if ! [[ "$count" =~ ^[0-9]+$ ]] || [ "$count" -lt 1 ] || [ "$count" -gt 65535 ]; then
    echo "pergb: reserve_nets count must be 1..65535 (got $count)" >&2
    return 1
  fi
  if [ "$count" -le 5000 ]; then
    _pergb_reserve_chunk "$count" "$ref"
    return
  fi
  # a batch bigger than one call: chunks of <= 5000 under sub-refs
  ref="${ref:0:120}"
  out="$(umask 077; mktemp "${TMPDIR:-/tmp}/netrun-pergb-nets.XXXXXX")" || return 1
  left="$count"
  while [ "$left" -gt 0 ]; do
    n="$left"; [ "$n" -gt 5000 ] && n=5000
    i=$((i + 1))
    if ! _pergb_reserve_chunk "$n" "$ref:c$i" >> "$out"; then
      rm -f "$out"
      return 1
    fi
    left=$((left - n))
  done
  if [ "$(wc -l < "$out" | tr -d ' ')" != "$count" ] || [ -n "$(sort "$out" | uniq -d | head -n 1)" ]; then
    echo "pergb: reserve_nets chunks lent a /64 twice or not $count in all" >&2
    rm -f "$out"
    return 1
  fi
  cat "$out"
  rm -f "$out"
}

# One reserve_nets call (count 1..5000).
_pergb_reserve_chunk() {
  local count="$1" ref="$2" resp
  if ! [[ "$count" =~ ^[0-9]+$ ]] || [ "$count" -lt 1 ] || [ "$count" -gt 5000 ]; then
    echo "pergb: reserve_nets count must be 1..5000 (got $count)" >&2
    return 1
  fi
  if ! [[ "$ref" =~ ^[A-Za-z0-9:._-]{1,128}$ ]]; then
    echo "pergb: bad reserve_nets ref" >&2
    return 1
  fi
  if ! resp="$(pergb_agent_post /pergb/reserve_nets "{\"count\":$count,\"owner\":\"perpiece\",\"ref\":\"$ref\"}")"; then
    echo "pergb: POST /pergb/reserve_nets failed: $(printf '%s' "$resp" | tr '\n' ' ' | cut -c1-300)" >&2
    return 1
  fi
  # exactly `count` distinct nets, or nothing at all. One per line, typed:
  # a JSON number (a subnet id, the `excluded` form) as decimal digits, a
  # string subnet id as 0x<hex>, an address / "<net>/64" as it came.
  printf '%s' "$resp" | python3 -I -c '
import json, re, sys
want = int(sys.argv[1])
try:
    r = json.load(sys.stdin)
except ValueError:
    sys.exit("pergb: reserve_nets answer is not JSON")
nets = r.get("nets") if isinstance(r, dict) else None
if nets is None and isinstance(r, dict) and isinstance(r.get("result"), dict):
    nets = r["result"].get("nets")
if not isinstance(nets, list) or len(nets) != want:
    sys.exit("pergb: reserve_nets lent %s /64(s) for %d asked" % (len(nets) if isinstance(nets, list) else "no", want))
def norm(n):
    if isinstance(n, int) and not isinstance(n, bool) and n >= 0:
        return str(n)
    if isinstance(n, str):
        t = n.strip()
        if ":" in t and re.fullmatch(r"[0-9a-fA-F:./]+", t):
            return t
        if re.fullmatch(r"(0[xX])?[0-9a-fA-F]{1,16}", t):
            return "0x" + re.sub(r"^0[xX]", "", t).lower()
    sys.exit("pergb: reserve_nets lent %r, not a /64" % (n,))
out = [norm(n) for n in nets]
if len(set(out)) != len(out):
    sys.exit("pergb: reserve_nets lent the same /64 twice")
print("\n".join(out))' "$count"
}

pergb_release_nets() {
  local ref="$1" body
  shift
  [ "$#" -gt 0 ] || return 0
  if ! [[ "$ref" =~ ^[A-Za-z0-9:._-]{1,128}$ ]]; then
    echo "pergb: bad release_nets ref" >&2
    return 1
  fi
  body="$(python3 -I -c '
import json, sys
nets = [int(n) if n.isdigit() else n for n in sys.argv[2:]]
print(json.dumps({"nets": nets, "ref": sys.argv[1]}))' "$ref" "$@")" || return 1
  pergb_agent_post /pergb/release_nets "$body" >/dev/null
}
