# netrun-radius — per-GB RADIUS of a NETRUN node

Pay-per-GB v2 (plan §3.1–§3.4, interfaces I1, I3, I5, I10). The per-GB 3proxy
(`3proxy-pergb`, `auth radius`) asks this server for every connection; the
answer carries the source address 3proxy binds:

- **Access-Accept** with exactly one `Framed-IPv6-Address` (a tagged host in a
  /64 of the node's /48) or `Framed-IP-Address` (the egress IPv4, for an IPv4
  destination);
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
| `alloc.py` | the /64 allocator of the pool (whole /48 minus `ffff`, amendment A1) |
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
- **D** sweeper: sticky expiry (heap), cool-downs, event pruning (7 days),
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
`account_off`, `quota`, `capacity`, `static_cap`; node-only: `not_ready` (no
facts yet). An IPv4 destination holds no /64 (no binding is created).

Probe login `netrun-svcprobe`: probe password, destination in the canary set,
≤ 2 Accepts/s, always rotation (tag list id 0), ignores admission and deadman.

Deadman: when the last heartbeat is older than `PERGB_DEADMAN_AFTER_SEC` (15),
an account listed in that heartbeat's `near` map is refused (`quota`) once
`headroom − PERGB_DEADMAN_RATE (50 MB/s) × heartbeat age ≤ 0`. Accounts that
were not near the limit keep being served (plan V22).

## Allocator

- Pool = subnet ids `lo..hi` of the /48 (facts `subnets`, default `0000-fffe`),
  never `ffff`. Candidates = pool − excluded; free = candidates without a
  binding (array + index map).
- **excluded** = scan-found (agent push) ∪ reserved (`reserve_nets`) ∪ cool-down
  (24 h after `release_nets`). Scan shrink guard: additions at once; a /64 leaves
  only when every complete scan for ≥ 10 min lacked it (≥ two complete scans);
  incomplete scans are add-only; a push whose confirmed removal is > 2 % of the
  scan entries is refused with `excluded_shrink` (its additions are kept; an
  operator can resend with `"force": true`). Reserved entries never leave by scan.
- **rotation**: least recently used of 4 random free /64s, fresh tagged host per
  connection; fallback when nothing is free: any candidate without a static
  binding. Never on a static /64.
- **static**: exclusive, best of 8 free by oldest last use; `static_cap`
  (account `staticCap`, default 100) and the 5 % reserve (`capacity`).
- **sticky**: exclusive while the account holds fewer than `stickyExclCap`
  exclusive sticky /64s (trial: 0) and free > 15 % of candidates; otherwise
  shared (packs onto shared /64s, never a static one, never one the account
  already uses — rule 5; the rare exception is counted as `sameAccount64`).
  TTL counts from the first connection; asking a live slot with another TTL keeps
  the IP and sets `expires = created + new ttl`; after expiry the next binding
  is in a different /64. A sticky request on a static slot gets the static IP;
  a static request on an exclusive sticky slot converts it in place.
- Safety caps (customer-chosen session ids): `PERGB_STICKY_MAX_PER_ACCOUNT`
  (20000) live sticky bindings per account, `PERGB_BINDINGS_MAX` (250000) per
  node; over them new bindings are refused with `capacity`.

## ctl ops (I5 + amendment A1)

All of I5. Additions (all additive):

- `reserve_nets {count 1..5000, owner:"perpiece", ref, force?}` → `{nets, ref}`;
  same `ref` → same nets; `capacity` when free would drop below
  `minFree64ForPerpiece` (facts) / `PERGB_MIN_FREE64_FOR_PERPIECE` (5000) unless
  `force`; never a bound /64 or one used in the last 60 s; durable before the reply.
- `release_nets {nets, ref}` → `{released: <count>, coolDownUntil: <unix>}`;
  idempotent per `ref`; any listed /64 (reserved or scan-found) cools down 24 h.
- `excluded` accepts `"force": true`; a refusal also returns `excluded`,
  `wouldRemove`, `limit`; success returns `removed`.
- `snapshot` also returns `static: {adopted, kept, refused: {reason: n}}`.
- `status` also returns `ready`, `secretLoaded`, `facts`, `counters`, `db`,
  `uptimeSec`, `deadman.{afterSec, active}`, `alloc.{reserved, coolDown,
  scanExcluded, sameAccountEvents}`.
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
