#!/usr/bin/env bash
# quick-install.sh — one-command NETRUN node bootstrap.
#
# Run on a fresh Ubuntu 22.04+ node as root:
#
#   curl -fsSL https://raw.githubusercontent.com/Tmwyw/node_runtime_new/main/scripts/quick-install.sh \
#     | bash -s -- \
#         --orch-url http://51.38.205.194:8090 \
#         --orch-api-key YOUR_API_KEY_HERE \
#         --node-name "NETRUN Frankfurt" \
#         --geo DE
#
# What it does (in order):
#   1. Updates apt, installs git/curl/jq
#   2. Clones https://github.com/Tmwyw/node_runtime_new → /tmp/netrun-source
#   3. Runs install_node_v2.sh (UFW purge + DNS pin + sysctl tune + node-agent + 3proxy-restore + doctor)
#   4. Verifies node-agent /health returns 200
#   5. Registers the node with orchestrator via POST /v1/nodes/enroll
#   6. Prints SKU-binding SQL the operator needs to run on orchestrator
#
# All hardening from Incident 2026-05-12 (UFW reset, DNS unreliability,
# PMTU=1380 TLS bug, kernel conntrack limits, 3proxy boot-respawn) is baked in.

set -euo pipefail

ORCH_URL=""
ORCH_API_KEY=""
NODE_NAME=""
GEO=""
REPO_URL="https://github.com/Tmwyw/node_runtime_new.git"
REPO_BRANCH="main"
CAPACITY=4000
WEIGHT=100
MAX_PARALLEL_JOBS=1
MAX_BATCH_SIZE=1500

usage() {
  cat <<'USAGE'
Usage: quick-install.sh --orch-url URL --orch-api-key KEY --node-name "NAME" --geo XX [opts]

Required:
  --orch-url URL          Orchestrator HTTP base URL (e.g. http://51.38.205.194:8090)
  --orch-api-key KEY      Orchestrator API key (from /opt/netrun-orchestrator/.env on orch host)
  --node-name "NAME"      Human-readable name (e.g. "NETRUN Frankfurt")
  --geo XX                ISO 2-letter country code (DE/SG/BR/AU/CA/FR/etc.)

Optional:
  --capacity N            Target stock per SKU (default 4000)
  --weight N              Allocation weight 0-1000 (default 100)
  --max-parallel-jobs N   Concurrent /generate jobs (default 1)
  --max-batch-size N      Max ports per job (default 1500)
  --branch NAME           Repo branch to clone (default main)
  --repo URL              Override repo URL (default Tmwyw/node_runtime_new)

Example:
  bash quick-install.sh \
    --orch-url http://51.38.205.194:8090 \
    --orch-api-key xxx \
    --node-name "NETRUN Frankfurt" --geo DE
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --orch-url) ORCH_URL="$2"; shift 2;;
    --orch-api-key) ORCH_API_KEY="$2"; shift 2;;
    --node-name) NODE_NAME="$2"; shift 2;;
    --geo) GEO="$2"; shift 2;;
    --capacity) CAPACITY="$2"; shift 2;;
    --weight) WEIGHT="$2"; shift 2;;
    --max-parallel-jobs) MAX_PARALLEL_JOBS="$2"; shift 2;;
    --max-batch-size) MAX_BATCH_SIZE="$2"; shift 2;;
    --branch) REPO_BRANCH="$2"; shift 2;;
    --repo) REPO_URL="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "[quick-install] unknown arg: $1" >&2; usage; exit 1;;
  esac
done

[ -z "$ORCH_URL" ] && { echo "[quick-install] missing --orch-url" >&2; usage; exit 1; }
[ -z "$ORCH_API_KEY" ] && { echo "[quick-install] missing --orch-api-key" >&2; usage; exit 1; }
[ -z "$NODE_NAME" ] && { echo "[quick-install] missing --node-name" >&2; usage; exit 1; }
[ -z "$GEO" ] && { echo "[quick-install] missing --geo" >&2; usage; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "[quick-install] must run as root" >&2; exit 1; }

# Strip trailing slash from orch URL
ORCH_URL="${ORCH_URL%/}"

log() { printf '\033[1;36m[quick-install]\033[0m %s\n' "$*"; }
ok()  { printf '\033[1;32m[quick-install]\033[0m \033[32m✓\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[quick-install]\033[0m ERROR: %s\n' "$*" >&2; exit 1; }

log "Target: $NODE_NAME ($GEO)"
log "Orchestrator: $ORCH_URL"

# === 1. apt deps ===
log "1/6 Installing apt dependencies (git curl jq)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq git curl jq ca-certificates
ok "deps installed"

# === 2. Clone repo ===
log "2/6 Cloning $REPO_URL (branch $REPO_BRANCH)"
rm -rf /tmp/netrun-source
git clone --depth=1 --branch "$REPO_BRANCH" "$REPO_URL" /tmp/netrun-source
ok "source cloned"

# === 3. Run install_node_v2.sh ===
log "3/6 Running install_node_v2.sh (hardening + node-agent install)"
log "    UFW purge + DNS pin + sysctl tune + pinned TCP signature + FD limits + 3proxy-restore"
cd /tmp/netrun-source
bash install_node_v2.sh
ok "install_node_v2.sh finished"

# === 4. Verify /health ===
log "4/6 Verifying node-agent /health"
HEALTH=$(curl -fsS -m 10 http://127.0.0.1:8085/health || die "node-agent /health failed")
if ! echo "$HEALTH" | jq -e '.success == true and .status == "ready"' >/dev/null; then
  echo "$HEALTH" | jq .
  die "node-agent unhealthy"
fi
ok "node-agent ready"

# Get the box's public IPv4 for orchestrator URL
PUBLIC_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | head -1 | grep -oE 'src [0-9.]+' | sed 's/src //')
[ -z "$PUBLIC_IP" ] && die "could not determine public IPv4 of this box"
NODE_URL="http://${PUBLIC_IP}:8085"
log "    Node URL: $NODE_URL"

# === 5. Register with orchestrator ===
# Schema (orchestrator/api_schemas.py:EnrollRequest):
#   agent_url    (required) — node-agent HTTP URL
#   name         (optional) — human-readable name
#   geo_code     (optional) — 2-letter country code
#   api_key      (optional) — node-side api key (we don't use one)
#   force        (default false) — overwrite existing entry by url
#   auto_bind_active_skus — if true, auto-binds to SKU matching geo_code
#                            (saves operator from manual SQL binding)
# Auth header: X-Netrun-Api-Key (FastAPI converts underscores to dashes)
log "5/6 Registering with orchestrator at $ORCH_URL"
ENROLL_PAYLOAD=$(jq -n \
  --arg name "$NODE_NAME" \
  --arg agent_url "$NODE_URL" \
  --arg geo_code "$GEO" \
  '{name: $name, agent_url: $agent_url, geo_code: $geo_code, force: true, auto_bind_active_skus: true}')

ENROLL_RESPONSE=$(curl -fsS -X POST "$ORCH_URL/v1/nodes/enroll" \
  -H "X-Netrun-Api-Key: $ORCH_API_KEY" \
  -H "Content-Type: application/json" \
  -d "$ENROLL_PAYLOAD" 2>&1) || die "enrollment failed: $ENROLL_RESPONSE"

NODE_ID=$(echo "$ENROLL_RESPONSE" | jq -r '.node.id // .id // .node_id // empty')
[ -z "$NODE_ID" ] && {
  echo "$ENROLL_RESPONSE" | jq .
  die "enrollment response missing node id"
}
AUTO_BOUND=$(echo "$ENROLL_RESPONSE" | jq -r '.auto_bound_skus // [] | join(", ")')
ok "registered: node_id=$NODE_ID"
[ -n "$AUTO_BOUND" ] && ok "auto-bound SKUs: $AUTO_BOUND"

# === 6. Doctor check + summary ===
log "6/6 Running netrun-doctor.sh"
bash /opt/netrun/scripts/netrun-doctor.sh || true

cat <<DONE

────────────────────────────────────────────────────────────────────────────
\033[1;32m✓ NODE READY\033[0m

  Name:     $NODE_NAME
  Geo:      $GEO
  IP:       $PUBLIC_IP
  Node ID:  $NODE_ID
  Agent:    $NODE_URL/health

Enrollment used auto_bind_active_skus=true — if an active SKU with code
'ipv6_$(echo "$GEO" | tr '[:upper:]' '[:lower:]')' exists on the orchestrator, refill will start filling
the pool automatically within 30 sec.

\033[1;33mOPTIONAL\033[0m — verify the binding landed (run on ORCHESTRATOR host):

  sudo -u postgres psql netrun_orchestrator -c "
    SELECT s.code, b.is_active
    FROM sku_node_bindings b
    JOIN skus s ON s.id = b.sku_id
    WHERE b.node_id = '$NODE_ID';"

\033[1;33mIF NO SKU EXISTS YET\033[0m for geo $GEO — create one then re-run enroll
with --force (or manually bind):

  sudo -u postgres psql netrun_orchestrator <<EOF
  INSERT INTO skus (code, geo, product_kind, duration_days, price_per_piece,
                    target_stock, refill_batch_size, is_active)
  VALUES ('ipv6_$(echo "$GEO" | tr '[:upper:]' '[:lower:]')', '$GEO', 'ipv6', 30, 0.14, 4000, 500, TRUE)
  ON CONFLICT (code) DO NOTHING;
  INSERT INTO sku_node_bindings (sku_id, node_id, is_active)
  SELECT s.id, '$NODE_ID', TRUE
  FROM skus s WHERE s.code = 'ipv6_$(echo "$GEO" | tr '[:upper:]' '[:lower:]')'
  ON CONFLICT (sku_id, node_id) DO UPDATE SET is_active = TRUE;
  EOF

Monitor pool growth on orchestrator:

  watch -n 5 "sudo -u postgres psql netrun_orchestrator -c \\
    \"SELECT n.geo, COUNT(*) FILTER (WHERE pi.status='available') AS avail \\
     FROM nodes n LEFT JOIN proxy_inventory pi ON pi.node_id = n.id \\
     WHERE n.id = '$NODE_ID' GROUP BY n.geo;\""

────────────────────────────────────────────────────────────────────────────
DONE
