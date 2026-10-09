# netrun-radius — per-GB RADIUS of a NETRUN node

Pay-per-GB v2 (plan §3.1–§3.4, interfaces I1, I3, I5, I10). The per-GB 3proxy
(`3proxy-pergb`, `auth radius`) asks this server for every connection; the
answer carries the source address 3proxy binds:

- **Access-Accept** with exactly one `Framed-IPv6-Address` (a tagged host in a
  /64 of the node's /48) or `Framed-IP-Address` (one of the node's per-GB egress
  IPv4s, for an IPv4 destination);
- **Access-Reject** without attributes. The reason is recorded, never sent.

python3 stdlib only, Python ≥ 3.10. Installed to `/opt/netrun/radius/` (root,
0755) by `deploy/node/install_pergb.sh`; units `deploy/node/netrun-radius.socket`
and `netrun-radius.service`.

## Files

| File | What |
|---|---|
| `netrun_radius.py` | the service: socket activation (fd 3), threads A–D, sd_notify |
| `proto.py` | RFC 2865 codec for 3proxy 0.9.3's Access-Request (length-4 Login-Service/Login-TCP-Port) |
| `username.py` | I1 grammar and the mode/slot table |
| `tag.py` | I3 address tag (8-round HMAC-SHA256 Feistel + 16-bit MAC) |
| `alloc.py` | the /64 allocator of the pool (whole /48 minus `ffff`, amendments A1, A6, A8, A10–A12) |
| `psl.py` | A12 site key (eTLD+1 by the vendored `public_suffix_list.dat`, else the destination /24 or /48) |
| `engine.py` | request path, in-memory state, every ctl op |
| `state.py` | sqlite (WAL) state and DB recovery |
| `ctl.py` | `/run/netrun-radius/ctl.sock` server and client |
| `radctl.py` | operator CLI for the ctl socket |
| `radclient.py` | sends 3proxy-shaped Access-Requests (checks, load) |
| `tests/` | unit tests, `feistel_vectors.json` (shared I3 fixture), e2e driver |

## Threads

- **A** UDP loop on fd 3 (`LISTEN_FDS`; `--listen host:port` for tests), `select`
  with a 1 s timeout and a wake-up pipe; never touches the disk.
- **B** ctl server, one connection per request, JSON line in, JSON line out.
- **C** writer: binding changes in batches every 100 ms. ctl ops commit before
  they reply (`{"error": "db_write_failed"}` when they cannot).
- **D** sweeper: sticky expiry (heap), idle timer/link/pause lines, expired
  avoid entries, event pruning (7 days),
  secret reload, `WATCHDOG=1` only while A is alive (< 3 s).

READY is sent after the state is loaded: ~0.5 s with 50k lists, 100k bindings
and 25k accounts (measured on an M-series Mac; RSS ~235 MiB, live ~160 MiB).

## Request path

`NAS-Port` in `[base, base+count)` → username (I1) → probe? → list exists,
password (`sha256(salt‖password)`), list `active` → account `active`, not
expired, not locally blocked → deadman → admission (hard / soft per account) →
IPv4 family (`ipv6_only` rejects) and IPv4 admission → near-limit reservation
(`2·L'`, `L' = logdumpBytes + 64 KiB`) → mode and slot (I1) → address.

Reasons (per node and per list): `bad_login`, `bad_params`, `list_off`,
`account_off`, `quota`, `capacity`; node-only: `not_ready` (no facts yet).
`capacity` comes only from the node guards (admission, IPv4 ports) and an
empty pool — never from per-customer counts (A8).

IPv4 destinations (A7/A9): facts `egressIpv4s` (1..64; default `[egressIpv4]`)
are all egress addresses. A fresh pick takes a random open one; a line (static,
timer, link, sticky, paused) keeps its own (an index derived with its address);
`ipv4_admission {open, addrs: {ip: open}}` closes single addresses (a closed
line address is replaced for that connection) or all of them.

Probe login `netrun-svcprobe`: probe password, destination in the canary set,
≤ 2 Accepts/s, always rotation (tag list id 0), ignores admission and deadman.

Deadman: when the last heartbeat is older than `PERGB_DEADMAN_AFTER_SEC` (15),
an account listed in that heartbeat's `near` map is refused (`quota`) once
`headroom − PERGB_DEADMAN_RATE (50 MB/s) × heartbeat age ≤ 0`. Accounts that
were not near the limit keep being served (plan V22).

## Allocator

- Pool = subnet ids `lo..hi` of the /48 (facts `subnets`, default `0000-fffe`),
  never `ffff`. Candidates = pool − excluded. **Nothing is reserved for a per-GB
  customer** (A8): every per-GB address of every customer comes from the
  candidates and the same /64 may serve many customers at once; status
  `alloc.free` = candidates.
- **excluded** = scan-found (agent push) ∪ reserved (`reserve_nets`). Scan shrink
  guard: additions at once; a /64 leaves only when every complete scan for
  ≥ 10 min lacked it (≥ two complete scans); incomplete scans are add-only; a
  push whose confirmed removal is > 2 % of the scan entries is refused with
  `excluded_shrink` (its additions are kept; an operator can resend with
  `"force": true`). Reserved entries leave only by `release_nets`, at once (A6).
- **Modes** (A10; the list's `mode`, legacy `rotate` = `per_request`, `sticky` =
  `timer`). Every port is a line slot `p<port − base>`; lines 1000+ are
  `-session-s<5 digits>` slots on the base port:
  - `per_request`: a fresh pick per connection — the least recently used of 4
    random candidates (A12: candidates the site refused are skipped, up to 16
    draws; when everything is refused the last draw is taken and counted);
  - `timer`: window `w = floor((now − timerAnchor) / ttl)` (`ttlSec`, or a
    `-ttl-` param for that line); the address is derived from
    (key, list, slot, ttl, w, `linkEpoch`, `lineEpochs[slot]`), so every line
    changes at the tick and the schedule never drifts;
  - `link`: derived from (key, list, slot, `linkEpoch`, `lineEpochs[slot]`) — the
    change-IP link bumps an epoch;
  - `static`: derived from (key, list, slot): the same line always gets the same
    address, through package end, top-ups, restarts and DB loss, while its /64
    is not per-piece's. Remembered and persisted (one `add` event for the
    orchestrator's mirror); when per-piece takes the /64 the line moves to its
    next probe (`release` reason `excluded` + `add` reason `moved`).
  Derivation: `net_i = lo + HMAC_SHA256(k, "netrun-pergb-pick\0" ‖ kind ‖ 0 ‖
  list_id(4) ‖ slot ‖ 0 ‖ extra ‖ 0 ‖ i(4))[0:8] mod (hi − lo + 1)` for i = 0, 1,
  …, skipping excluded /64s (static also skips, for up to 64 probes, /64s
  another static/sticky line of the same list holds); host = the I3 tag with
  `r16` from `"netrun-pergb-pick-r\0"` (redrawn while iid < 2^32); IPv4 choice
  from `"netrun-pergb-pick-v4\0"`. `extra` = `""` (static), `"ttl:w:e1:e2"`
  (timer), `"e1:e2"` (link).
- **Sticky sessions**: a `-session-<name>` param (any name but a line slot) is
  sticky in every mode for its `-ttl-` (default 600 s, 30 s … 24 h), counted from
  the first connection; another ttl keeps the IP and sets
  `expires = created + new ttl`; after expiry the next address is in a different
  /64; re-drawn up to 8 times to avoid the list's other /64s. A `-ttl-` param
  without a session on a non-timer list makes that line sticky too. Persisted.
- **Липкая сессия** (A11, `stickyPauseSec` 5 or 10 on per_request / timer
  lists): a line is busy while new connections arrive less than the pause apart;
  a busy line keeps its address when the mode wants a change, and switches at its
  first quiet gap or `PERGB_STICKY_MAX_DEFER_SEC` (120 s) after the change was
  due. Link changes are never postponed. Open connections are never cut by any
  mode. Timer/link/pause states are memory only (derived or seconds long).
- Memory bounds (session names are customer-chosen; never a reject):
  `PERGB_STICKY_MAX_PER_ACCOUNT` (20000) live sessions per account and
  `PERGB_STICKY_MAX` (250000) per node — beyond them the account's oldest (or the
  node's soonest-expiring) session is forgotten (`alloc.stickyEvicted`).
- **Smart rotation** (A12): ctl `avoid` keeps `site → {net: until}` in memory
  (≤ 200k entries, soonest expiry evicted first); not persisted — the agent
  pushes the full set after a restart or an epoch change.

## ctl ops (I5 + amendments A1, A6, A7, A10, A12)

All of I5. Additions (all additive):

- `reserve_nets {count 1..5000, owner:"perpiece", ref, force?}` → `{nets, ref}`;
  same `ref` → same nets; `capacity` when free would drop below
  `minFree64ForPerpiece` (facts) / `PERGB_MIN_FREE64_FOR_PERPIECE` (5000) unless
  `force`; never a /64 used by rotation in the last 60 s, preferring /64s no
  remembered line sits on; durable before the reply.
- `release_nets {nets, ref}` → `{released: <count>, coolDownUntil: null}`;
  releases by net (the ref only makes the call idempotent); a /64 that is not
  reserved is a no-op (a scan-found one leaves through the scans); no cool-down (A6).
- `avoid {entries: [{net, site, until}], removed: [{net, site}], full}` →
  `{ok, pairs, sites}` (A12; `net` a subnet id, `until` unix s).
- `ipv4_admission` accepts `addrs: {ip: open}` (A7).
- list records (L) take `mode` `per_request|timer|link|static` (legacy
  `rotate|sticky`), `ttlSec` 30..86400, `timerAnchor` (unix s), `linkEpoch`,
  `lineEpochs {slot: n}`, `stickyPauseSec`; accounts' `staticCap` /
  `stickyExclCap` and facts' `reserves` are accepted and ignored (A8).
- `facts` accepts `egressIpv4s` (A7).
- `excluded` accepts `"force": true`; a refusal also returns `excluded`,
  `wouldRemove`, `limit`; success returns `removed`.
- `snapshot` also returns `static: {adopted, kept, refused: {reason: n}}`.
- `status` also returns `ready`, `secretLoaded`, `facts`, `counters`, `db`,
  `uptimeSec`, `deadman.{afterSec, active}`, `counts.lines`, `ipv4Closed`,
  `smartRotation {avoidedPairs, sites, picksAvoided1h, exhausted1h,
  exhaustedSites}`, `alloc.{reserved, scanExcluded, lines, stickyEvicted,
  staticMoved}` (`boundExclusive`, `sameAccount64`, `coolDown` are always 0).
- `logins` items also carry the list `mode`.
- `near_stats` entries also carry `headroom`.
- `facts` accepts `subnets` as `[lo, hi]` ints, hex strings or `"lo-hi"`, and an
  optional `minFree64ForPerpiece`.
- Errors: `bad_request` (with `detail`), `unknown_op`, `seq_mismatch`,
  `excluded_shrink`, `capacity`, `ref_conflict`, `unknown_account`,
  `not_ready`, `db_write_failed`, `internal`.

`heartbeat`, `admission` and `ipv4_admission` are not committed before the
reply: admission is in memory only (open after a restart until the agent's next
guard tick), the last heartbeat is written by the batch writer. Every other
state-changing op is durable when it replies.

`avoid` is memory only as well.

Schema 2 of `radius.db` (A6/A8/A10): a schema-1 file is treated like a corrupt
one (moved aside, new epoch, full re-push).

Types: `epoch` is a random integer in `[2^32, 2^53)` (safe in JavaScript);
`seq` an integer; list `login` is stored as `netrun-<id>` (a bare id is
prefixed); `bindings` items carry `at` as unix seconds (float).

## Runbook

```
systemctl status netrun-radius.socket netrun-radius.service
python3 -I /opt/netrun/radius/radctl.py status          # epoch, seq, alloc, latency, rejects
python3 -I /opt/netrun/radius/radctl.py rejects
python3 -I /opt/netrun/radius/radctl.py bindings '{"after": 0, "limit": 20}'
journalctl -u netrun-radius -n 50
```

- Socket closed or service failed: `systemctl reset-failed netrun-radius.socket
  netrun-radius.service && systemctl start netrun-radius.socket`.
- Corrupt DB: it is moved to `radius.db.broken-<ts>` automatically and the
  service starts empty under a new epoch (`dbRecovered: true`); the agent
  re-pushes facts and excluded, the orchestrator a full snapshot.
- No secret (`secretLoaded: false`): requests are dropped; check
  `/etc/netrun-pergb/radius.secret` (0640 root:netrun-radius; the directory
  must be traversable by netrun-radius).

## Tests

```
python3 -I -m unittest discover -s node_runtime/radius/tests          # ~35 s, any OS
sudo scripts/test_pergb_radius_e2e.sh                                  # Linux: real 3proxy in a netns
sudo scripts/test_netrun_radius_units.sh --throwaway-host              # Linux VM/CI: real systemd
```

`tests/test_e2e_dryrun.py` runs the e2e driver against `tests/fake3proxy.py`
(same RADIUS behaviour as 3proxy, no netns) so the driver, the socket-activation
stand-in and every restart/timeout path also run on macOS.
`NETRUN_RADIUS_PERF_SLACK=2` doubles the time budgets of the performance tests
on slow runners. Regenerate the I3 fixture with
`python3 -I node_runtime/radius/tests/gen_feistel_vectors.py > node_runtime/radius/tests/feistel_vectors.json`.
