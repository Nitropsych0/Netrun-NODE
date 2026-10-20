# Lane `node-agent-hardening` — fixes (Netrun-NODE, branch `claude/fix-node-agent-hardening-4fb23a`)

Cut from `main` @ `9474bc4`. Five findings, fixed in the brief's order, one commit each (no push, no PR).

**Baseline (macOS, before any edit):** `node --test node_runtime/node_agent/*.test.js` 446/446;
every `scripts/test_*.sh` and `node_runtime/soft/generator/test_*.sh` rc=0 except three that cannot run
here and fail identically on `main` (`test_netrun_radius_units.sh`, `test_pergb_agent_linux.sh`: "pass
--throwaway-host"; `test_pergb_radius_e2e.sh`: Linux-only). `pytest` is not installed, so
`node_runtime/radius/tests` were not run (the lane touches nothing there).
**After:** node 463/463 (+17 tests), the same shell scripts rc=0, the same three unchanged, `bash -n` on every
touched script, generator `sed 's/&>>/>>/g' | bash -n` clean, `node --check` on every touched `.js`.
"Fails before": every new/changed test was re-run against a pristine `git archive 9474bc4` — all fail there.

## 1. S-ORCH-1/node — the agent's whole API over TLS `:8086`

* **Changed.** `server.js`: the plain listener's callback became the hoisted `handleAgentRequest`
  (exported) and is passed to `createTlsServer({agentHandler})`. `pergb_tls_server.js`: with an
  `agentHandler`, every path except `/pergb*` and `/vpn*` goes to it **before the body is read**
  (per-route `X-API-KEY`, keyless `/health` = `{ok:true}`, exactly as on `:8085`); the listener's gate no
  longer needs `/etc/netrun-pergb` (`NETRUN_AGENT_TLS_REQUIRE_PERGB=1` restores it) but the
  `agent_firewall_without_8086` gate is untouched; `status().routes` = `"full"` / `"pergb_only"`.
  `describe.js`: `supports.agent_tls = 1`, `supports.agent_tls_port` unconditionally.
  `NODE_AGENT_ALLOW_PLAIN_HTTP` (default `true`): `false` pins `:8085` to `127.0.0.1`
  (`plainListenHost()`), so the node-local callers (watchdog_probe, `netrun-harden agent-key`, the
  generator's `/pergb/reserve_nets`) keep working. `netrun-harden.sh status` reports
  `A3 agent TLS :8086: listening|closed`. `bootstrap_new_node.sh` / `quick-install.sh` enroll
  `https://<ip>:8086`. env.example, service template, README, RUNBOOK updated.
* **Proof.** `server.agent_tls.test.js` (new: real HTTPS listener + the real handler: `/health` keyless
  `{ok:true}` and full with key, `/describe` 401/200 with `supports.agent_tls`, `/jobs`, 404, plain-HTTP flag),
  `pergb_tls_server.test.js` (+2: gate opens without `/etc/netrun-pergb` but stays closed on a guard without
  8086; a 100 KB POST reaches `agentHandler` intact, `/pergb/*` and `/vpn/*` stay local, `routes === 'full'`),
  `describe.capacity.test.js` (+1), `test_netrun_harden_security.sh` (status names the TLS check).
* **Verify on a real node.** (a) `systemctl restart netrun-node-agent`, then
  `curl -sk https://127.0.0.1:8086/health` → `{"ok":true}`, and with the key `pergb.tls.listening=true,
  routes="full"`; (b) from the orchestrator IP `curl --cacert <fleet root> https://<ip>:8086/describe -H
  "X-API-KEY: …"` verifies the IP cert and answers 200; from any other IP `:8086` must be dropped;
  (c) nodes guarded before 8086 existed: `netrun-harden secure`/`agent-firewall` (the listener logs
  `agent_firewall_without_8086` and stays closed until then); (d) nodes without a lego/`node.pem`
  certificate keep `:8086` closed (`error: no_ip_cert`) — run `netrun-https setup`; (e) later,
  `NODE_AGENT_ALLOW_PLAIN_HTTP=false` and confirm `ss -ltn | grep 8085` shows `127.0.0.1` only and watchdog /
  `netrun-harden agent-key` still pass.
* **Contract (orchestrator-node-transport).** TLS listener `:8086`, same `X-API-KEY`, same routes, cert =
  the node's IP certificate under the fleet root already verified for per-GB; `:8085` stays plain behind
  `NODE_AGENT_ALLOW_PLAIN_HTTP=true` (default); flip it only after `nodes.url` has zero `http://` rows and L-O1
  is deployed. `/describe supports.agent_tls` / `agent_tls_port` can be probed before switching a node's URL.

## 2. S-U2/node — register over HTTPS only

* **Changed.** `quick-install.sh` refuses a non-`https://` `--orch-url` (admin orchestrator key + agent key
  travel in the enroll request) unless `--allow-insecure-http`; usage examples are https. The legacy
  `deploy/node/cloud-init.sh` / `cloud-init.yaml` (unconditional plain-HTTP register) were `git rm`-ed —
  nothing in this repo referenced them; the orchestrator renders the only user_data.
  `docs/cloud_init_provisioning.md` rewritten (HTTPS-only registration at `ORCHESTRATOR_REGISTER_URL`,
  `agent_api_key` added to the body contract). CI step added to `pergb-linux.yml`.
* **Proof.** `scripts/test_quick_install_https.sh` (new): http/ftp/schemeless URLs → exit 1 with
  "orch-url must be https://" before the root check; `--allow-insecure-http` and https get past it to
  "must run as root"; usage text; both cloud-init files gone; docs name the https path. (Runs as non-root;
  skips itself as root.)
* **Ops / other lanes.** Orchestrator half (fail provisioning without an https `ORCHESTRATOR_REGISTER_URL`,
  node-side `netrun_register_url_ok`) is in the orchestrator lanes; `NODE_REGISTER_FORWARD=true` on the site
  must be on first. Nothing to verify on a node beyond a real provision-prepare delivering
  `REGISTER_URL_SET="https://netrun.world/node-register"`.

## 3. S-NODE-3/node — no shop/admin bot token on nodes

* **Changed.** `netrun-hq-watch.sh` reads `HQ_WATCH_TG_TOKEN` / `HQ_WATCH_TG_CHAT` / `HQ_WATCH_TG_TOPIC`
  from `/etc/netrun/hq-watch.env` (per-variable fallback to `TG_TOKEN`/`TG_CHAT`/`TG_TOPIC` with a
  deprecation warning on stderr), ignores a config whose mode has group/other bits (quiet no-op + message),
  is a quiet no-op without a config/token. `node_followup_v2.sh` installs the script (0700,
  `/usr/local/sbin/netrun-hq-watch`) and both units and enables the timer on **every** node, and never
  writes the env file or takes a token (it never took one from install args — there was no such code; the
  only token path was hand-placing the file, now documented as orchestrator-pushed only). README HQ-watch
  section, RUNBOOK checklist line `hq-watch:$(systemctl is-active netrun-hq-watch.timer)`.
* **Proof.** `scripts/test_hq_watch.sh` (+8 checks: 0644/0640/0604/0660/0666 refused, 0600/0400 work;
  `NODE_LABEL='New York 1'` intact; legacy names work + warn, new names win, no warning for new names;
  missing token no-op; token never in curl argv), `scripts/test_hq_watch_install.sh` (new, static + `bash -n`,
  wired into CI together with shellcheck of both scripts).
* **Verify on a real node.** After `node_followup_v2.sh`: `systemctl is-active netrun-hq-watch.timer` =
  active, `systemctl start netrun-hq-watch.service` is silent and writes nothing without the file; once the
  orchestrator pushes the file (wave 2): `stat -c %a /etc/netrun/hq-watch.env` = 600, one run is silent, state
  file under `/var/lib/netrun-hq-watch/`. **Ops (owner):** create the dedicated alerts-only bot, push via the
  orchestrator, and only then revoke the old admin-bot token that is still on existing nodes' `hq-watch.env`
  (this lane does not touch existing files on nodes).
* **Contract (wave-2 S-NODE-3/orchestrator).** File `/etc/netrun/hq-watch.env`, 0600 root, keys
  `HQ_WATCH_TG_TOKEN`, `HQ_WATCH_TG_CHAT`, `HQ_WATCH_TG_TOPIC`, `NODE_LABEL` (single-quoted), optional
  `HQ_URL`/`HQ_HOST`/`HQ_REF_URL`/`HQ_FAILS`/`HQ_REMIND_MIN`. A file the orchestrator writes with a wrong
  mode is silently ignored — it must write 0600.

## 4. L-U2 — generator fails closed on a stale credentials / address list

* **Changed.** `proxyyy_automated.sh`: new `list_line_count` / `credentials_list_is_valid`;
  `generate_random_users_if_needed` reuses an existing list only if it has exactly `proxy_count` valid
  `login:password` lines, else logs (`stale credentials list … N line(s) … needs M — regenerating`) and
  regenerates atomically (tmp + `mv`, 0600), with a post-condition check; `generate_ipv6_addresses_if_needed`
  refuses a list of the wrong length (`log_err_and_exit`, list untouched — per-GB/routed lists hold /64s only
  the agent may release); the generated start-up script exits 1 (no cfg, no spawn) on a wrong-length address
  list, fewer credentials than ports, or a malformed (empty part / no colon) credentials entry — so
  `users :CL:` is unreachable. `server.js`: `dropStaleBatchLists` / `dropIpv6List` (freshAddresses refactored
  onto it); `/generate` drops a leftover credentials list (unless identical explicit credentials) and an ipv6
  list whose length ≠ `proxyCount` when the ps scan shows no 3proxy on that start port, recording
  `result.staleLists` (counts only); `parkFailedAttempt` also removes the credentials list.
* **Proof.** `test_fleet_health.sh` §2b (1-line/5-line/malformed regenerated, exact reused verbatim, no `.tmp`,
  mode 600, log names 1 and 3), `test_generator_flags.sh` §4b (199/201 vs 200 refused with both numbers, list
  untouched; 200 reused) and §5b (short/malformed/over-long lists → exit 1, no cfg, helper not called; valid →
  `users u1:CL:p1`/`u2:CL:p2`, zero `users :CL:`), `server.credentials.test.js` (+5: stale drop + `staleLists`,
  same-count drop without explicit credentials and keep with identical explicit ones, equal-count ipv6 kept,
  parked attempt loses its list, `dropStaleBatchLists` shape). Existing FO-06 / rebind / kill-on-rebind /
  genlock suites pass unchanged.
* **Verify on a real node.** Regenerate on a start port whose old batch was released with a larger count →
  the new batch has real credentials in every row; `journalctl -u netrun-node-agent | grep "stale per-start-port"`
  shows the drop; a node whose cron `proxy-startup_*.sh` predates this change is unchanged (guards apply to
  batches generated after the deploy). Answer to the audit's open question: the orchestrator's gap-aware
  allocator can reissue a released start port with another count, and the node now handles it.

## 5. S-NODE-2 — `/generate` runs only the vetted generator

* **Changed.** `server.js`: `NODE_AGENT_GENERATOR_ROOT` (default `/opt/netrun/node_runtime`) and
  `NODE_AGENT_GENERATOR_SCRIPT` (default `<root>/soft/generator/proxyyy_automated.sh`);
  `resolveGeneratorScript` (relative → `generator_script_not_allowed`/`relative_path`; missing/directory →
  `generator_script_not_found`; realpath outside the root, incl. symlinks → `generator_script_not_allowed`/
  `outside_generator_root`; returns the realpath that is spawned); `generatorScript` is now optional; `cwd` is
  `process.cwd()` always (a differing body value is logged); `job.json` records `request.providedGeneratorScript`
  / `providedCwd`; `resolveInputPath` deleted. Five existing server suites set
  `NODE_AGENT_GENERATOR_ROOT=TMP` (their fakes live there). env.example, README.
* **Proof.** `server.generator_path.test.js` (new): unit cases for default/relative/outside/symlink/dir/missing/
  valid; HTTP 400 with no job dir, no lock and the out-of-root script never run; `cwd:'/etc'` ignored
  (`seen_cwd` = the agent's cwd, `providedCwd === '/etc'`); default and explicit-default both run.
* **Verify on a real node.** `bash scripts/smoke_generate.sh` (sends the canonical path) → `ready`;
  `journalctl -u netrun-node-agent | grep generator_script_not_allowed` empty after the next orchestrator refill.
  A node with a non-standard `NETRUN_HOME` needs `NODE_AGENT_GENERATOR_ROOT` in its unit drop-in.

## Env-var / port / flag contract (all new)

| Name | Default | Meaning |
|---|---|---|
| `:8086` (existing port) | open when the IP cert exists and the agent guard (if any) includes 8086 | now serves every agent route |
| `NODE_AGENT_ALLOW_PLAIN_HTTP` | `true` | `false` → `:8085` binds `127.0.0.1` only |
| `NETRUN_AGENT_TLS_REQUIRE_PERGB` | `0` | `1` → open `:8086` only where `/etc/netrun-pergb` exists |
| `/describe` `supports.agent_tls` / `agent_tls_port` | `1` / `8086` | orchestrator probe before switching a node URL |
| `/health` `pergb.tls.routes` | `"full"` | `"pergb_only"` = listener without the agent handler |
| `HQ_WATCH_TG_TOKEN` / `_CHAT` / `_TOPIC` | — | hq-watch config keys; `TG_*` deprecated fallback |
| `NODE_AGENT_GENERATOR_ROOT` / `_SCRIPT` | `/opt/netrun/node_runtime` / `<root>/soft/generator/proxyyy_automated.sh` | `/generate` whitelist |
| `quick-install.sh --allow-insecure-http` | off | allow an `http://` `--orch-url` |
| `/generate` errors | — | `400 generator_script_not_allowed`, `400 generator_script_not_found`; `job.json` `result.staleLists` |

## Decisions taken by default (owner has not answered)

* `NODE_AGENT_ALLOW_PLAIN_HTTP` defaults `true` (brief); `false` means loopback-only rather than "no
  listener", because node-local callers need `:8085`.
* `:8086` now opens on every node with an IP cert (`NETRUN_AGENT_TLS_REQUIRE_PERGB=0`), still behind the
  agent-firewall gate.
* Legacy `TG_*` names stay readable (deprecation warning) instead of being dropped; a non-0600 hq-watch config
  is ignored rather than fixed up.
* `generatorScript` becomes optional instead of required; the default root is `/opt/netrun/node_runtime`.
* A generator-side stale ipv6 list is refused (not regenerated); the agent, not the generator, drops it.

## Not done / follow-ups

* **L-N1** (named in the delegating task: "fail closed on a failed proxy-list write, detect a running batch
  like netrun-3proxy-spawn.sh") is not one of this lane's five findings and has no spec in the brief (it is only
  mentioned in the packager note), so it was **not** implemented; the L-U2 change here touches the same
  `/generate` region and generator functions and should be sequenced before it.
* Existing nodes' `hq-watch.env` (with the old admin-bot token) is untouched — rotation is the owner's/wave-2 job.
* Not run here (no Linux): nftables/systemd/3proxy/real Let's Encrypt behaviour — covered by fakes and the
  "verify on a real node" lists above.
