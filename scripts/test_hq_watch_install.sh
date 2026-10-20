#!/usr/bin/env bash
# Audit S-NODE-3 (static, like test_quick_install_repo.sh): node_followup_v2.sh
# installs the HQ watcher on every node — script 0700 at /usr/local/sbin/
# netrun-hq-watch, both units from deploy/node, timer enabled — and NEVER writes
# /etc/netrun/hq-watch.env or takes a token (the orchestrator pushes that file;
# no config = the watcher is a quiet no-op). Run with:
#   bash scripts/test_hq_watch_install.sh
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd -P)"
FU="$ROOT_DIR/scripts/node_followup_v2.sh"
D="$ROOT_DIR/deploy/node"
fail() { echo "FAIL: $1"; exit 1; }
ok() { echo "ok: $1"; }

bash -n "$FU" || fail "bash -n node_followup_v2.sh"
bash -n "$D/netrun-hq-watch.sh" || fail "bash -n netrun-hq-watch.sh"
ok "bash -n on the follow-up and the watcher"

grep -qE 'install -m 0700 "\$HQ_WATCH_SRC" /usr/local/sbin/netrun-hq-watch$' "$FU" || fail "the watcher is not installed 0700 at /usr/local/sbin/netrun-hq-watch"
grep -q 'HQ_WATCH_SRC="\$SELF_DIR/../deploy/node/netrun-hq-watch.sh"' "$FU" || fail "the watcher source is not deploy/node/netrun-hq-watch.sh"
grep -qE 'install -m 0644 "\$SELF_DIR/../deploy/node/netrun-hq-watch.service" /etc/systemd/system/netrun-hq-watch.service' "$FU" || fail "the service unit is not installed from deploy/node"
grep -qE 'install -m 0644 "\$SELF_DIR/../deploy/node/netrun-hq-watch.timer" /etc/systemd/system/netrun-hq-watch.timer' "$FU" || fail "the timer unit is not installed from deploy/node"
grep -q 'systemctl enable --now netrun-hq-watch.timer' "$FU" || fail "the timer is not enabled"
ok "script 0700, both units from deploy/node, timer enabled"

# the follow-up runs before systemctl enable: the install must come before the daemon-reload
inst=$(grep -n 'install -m 0700 "\$HQ_WATCH_SRC"' "$FU" | head -1 | cut -d: -f1)
reload=$(grep -n '^systemctl daemon-reload' "$FU" | head -1 | cut -d: -f1)
[ -n "$inst" ] && [ -n "$reload" ] && [ "$inst" -lt "$reload" ] || fail "units must be installed before systemctl daemon-reload"
ok "units are installed before daemon-reload"

# ExecStart of the unit is the installed path
grep -qx 'ExecStart=/usr/local/sbin/netrun-hq-watch' "$D/netrun-hq-watch.service" || fail "ExecStart is not /usr/local/sbin/netrun-hq-watch"
grep -q '^\[Service\]' "$D/netrun-hq-watch.service" && grep -q '^Type=oneshot' "$D/netrun-hq-watch.service" || fail "service unit shape"
grep -q '^\[Timer\]' "$D/netrun-hq-watch.timer" && grep -q '^OnUnitActiveSec=60s' "$D/netrun-hq-watch.timer" && grep -q '^WantedBy=timers.target' "$D/netrun-hq-watch.timer" || fail "timer unit shape"
if command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze verify "$D/netrun-hq-watch.service" "$D/netrun-hq-watch.timer" 2>&1 | grep -v 'ExecStart.*not found\|Failed to open' | grep -qi 'error' && fail "systemd-analyze verify"
fi
ok "units parse and ExecStart points at the installed path"

# no token plumbing in the installers: nothing writes the env file or takes TG_* / HQ_WATCH_TG_* from args
for f in "$FU" "$ROOT_DIR/install_node_v2.sh" "$ROOT_DIR/scripts/quick-install.sh" "$ROOT_DIR/scripts/bootstrap_new_node.sh"; do
  [ -f "$f" ] || continue
  if grep -nE 'hq-watch\.env|HQ_WATCH_TG_TOKEN|TG_TOKEN' "$f" | grep -vE '^[0-9]+:[[:space:]]*#'; then
    fail "$(basename "$f") must not write hq-watch.env or handle the token (the orchestrator pushes it)"
  fi
done
ok "no installer writes hq-watch.env or takes a Telegram token"
echo "test_hq_watch_install.sh — all checks passed"
