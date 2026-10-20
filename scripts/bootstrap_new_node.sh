#!/usr/bin/env bash
# bootstrap_new_node.sh — one-shot setup for a fresh Vultr/Hetzner/etc. proxy node.
#
# Run FROM YOUR LOCAL MACHINE or ORCHESTRATOR:
#   bash bootstrap_new_node.sh <NODE_IP> <NODE_NAME> <GEO_2LETTER>
#
# Example:
#   bash bootstrap_new_node.sh 1.2.3.4 "NETRUN Berlin" DE
#
# Assumes:
#   - Fresh Ubuntu 22.04+ instance, root SSH password access
#   - You are in the directory containing this `node_runtime` repo
#   - SSH config has the orchestrator's API URL/key in env vars (see below)
#
# What it does:
#   1. scp the entire node_runtime/ to /tmp/netrun-source/ on the node
#   2. ssh: bash install_node_v2.sh (which: hardens system, installs node-agent,
#      sets up auto-restore service, pins DNS, disables UFW, etc.)
#   3. ssh: run netrun-doctor.sh to verify all green
#   4. Print enrollment command to register the node in orchestrator

set -euo pipefail

if [ "$#" -ne 3 ]; then
  cat <<USAGE
Usage: bash bootstrap_new_node.sh <NODE_IP> <NODE_NAME_QUOTED> <GEO_2LETTER>

Example:
  bash bootstrap_new_node.sh 1.2.3.4 "NETRUN Berlin" DE

The node must have:
  - Fresh Ubuntu 22.04+ image
  - Root SSH access (you'll be prompted for password 2-3 times)
  - IPv6 enabled in Vultr/Hetzner panel

After bootstrap, follow the printed enrollment command to register
the new node with your orchestrator.
USAGE
  exit 1
fi

NODE_IP="$1"
NODE_NAME="$2"
GEO_CODE="$3"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"

log() { printf '\033[1;36m[bootstrap]\033[0m %s\n' "$*"; }
ok() { printf '\033[1;32m[bootstrap]\033[0m \033[32m✓\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[bootstrap]\033[0m ERROR: %s\n' "$*" >&2; exit 1; }

log "Target: $NODE_NAME ($GEO_CODE) at $NODE_IP"
log "Source: $REPO_ROOT"

# === 1. Sanity: SSH reachable ===
log "1/5 Verifying SSH reachability"
if ! timeout 10 ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 \
      "root@$NODE_IP" 'echo "ssh ok"' >/dev/null 2>&1; then
  die "ssh root@$NODE_IP unreachable — verify IP and password"
fi
ok "SSH works"

# === 2. Copy node_runtime/ to node ===
log "2/5 Copying node_runtime to /tmp/netrun-source/ on node (may take 30-60s)"
ssh -o StrictHostKeyChecking=no "root@$NODE_IP" 'rm -rf /tmp/netrun-source && mkdir -p /tmp/netrun-source'
tar -C "$REPO_ROOT" --exclude='./.git' --exclude='./node_modules' -czf - . \
  | ssh -o StrictHostKeyChecking=no "root@$NODE_IP" 'tar -C /tmp/netrun-source -xzf -'
ok "Source copied"

# === 3. Run install_node_v2.sh ===
log "3/5 Running install_node_v2.sh on node (hardening + node-agent install)"
log "    (this takes 1-3 minutes; ssh logs streamed below)"
ssh -o StrictHostKeyChecking=no "root@$NODE_IP" 'cd /tmp/netrun-source && bash install_node_v2.sh'
ok "install_node_v2.sh finished"

# === 4. Run netrun-doctor.sh ===
log "4/5 Running netrun-doctor.sh diagnostic"
ssh -o StrictHostKeyChecking=no "root@$NODE_IP" 'bash /opt/netrun/scripts/netrun-doctor.sh'
ok "Doctor check finished"

# === 5. Print enrollment command ===
log "5/5 Bootstrap complete. Enroll the node with your orchestrator:"
cat <<ENROLL

────────────────────────────────────────────────────────────────────────────────
On your ORCHESTRATOR machine, run:

  curl -X POST "\$ORCH_BASE_URL/v1/nodes/enroll" \\
    -H "X-API-Key: \$ORCH_API_KEY" \\
    -H "Content-Type: application/json" \\
    -d '{
      "name": "$NODE_NAME",
      "url": "https://$NODE_IP:8086",
      "geo": "$GEO_CODE",
      "capacity": 4000,
      "weight": 100,
      "max_parallel_jobs": 1,
      "max_batch_size": 1500
    }'

Then bind to the geo's SKU (replace SKU_ID with the row id from skus table):

  sudo -u postgres psql netrun_orchestrator <<EOF
INSERT INTO sku_node_bindings (sku_id, node_id, is_active)
SELECT s.id, n.id, TRUE
FROM skus s
JOIN nodes n ON n.url IN ('https://$NODE_IP:8086', 'http://$NODE_IP:8085')
WHERE s.code = 'ipv6_$(echo "$GEO_CODE" | tr '[:upper:]' '[:lower:]')'
ON CONFLICT (sku_id, node_id) DO UPDATE SET is_active = TRUE;
EOF

After binding, refill scheduler will start filling the pool to target_stock
automatically (no manual generation needed). Check progress:

  watch -n 5 'sudo -u postgres psql netrun_orchestrator -c "
SELECT n.geo, COUNT(*) FILTER (WHERE pi.status=\\'available\\') AS avail
FROM nodes n LEFT JOIN proxy_inventory pi ON pi.node_id = n.id
GROUP BY n.geo ORDER BY n.geo;"'
────────────────────────────────────────────────────────────────────────────────

ENROLL
ok "Done. New node should pass all doctor checks. ~20-30 min until first 1000 proxies available."
