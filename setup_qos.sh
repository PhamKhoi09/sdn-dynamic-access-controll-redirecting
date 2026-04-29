#!/bin/bash
#   ./setup_qos.sh          # for s1 (default)
#   ./setup_qos.sh s2       # for another switch

set -e

SWITCH=${1:-s1}
PORTS=$(ovs-vsctl list-ports "$SWITCH" 2>/dev/null)

if [ -z "$PORTS" ]; then
    echo "[ERROR] Switch '$SWITCH' not found. Please check the switch name."
    exit 1
fi

echo "=========================================="
echo "[STEP 1] Clear old QoS and Queue (if any)"
echo "=========================================="

# Clear QoS from each port first
for PORT in $PORTS; do
    ovs-vsctl --if-exists clear Port "$PORT" qos || true
    echo "  [CLEAR] Port $PORT"
done

# Destroy all remaining QoS and Queue objects
ovs-vsctl --all destroy QoS  2>/dev/null || true
ovs-vsctl --all destroy Queue 2>/dev/null || true
echo "[INFO] Đã xóa toàn bộ QoS/Queue cũ."

echo ""
echo "=========================================="
echo "[STEP 2] Create QoS + 4 Queues in 1 transaction"
echo "=========================================="

# Build dynamic set port command for all ports of the switch
SET_PORTS=""
for PORT in $PORTS; do
    SET_PORTS="$SET_PORTS -- set port $PORT qos=@newqos"
done

sudo ovs-vsctl \
  $SET_PORTS \
  -- --id=@newqos create qos type=linux-htb other-config:max-rate=10000000 \
       queues:0=@q0 queues:1=@q1 queues:2=@q2 queues:3=@q3 \
  -- --id=@q0 create queue other-config:min-rate=5000000 other-config:max-rate=10000000 \
  -- --id=@q1 create queue other-config:min-rate=3000000 other-config:max-rate=6000000 \
  -- --id=@q2 create queue other-config:min-rate=1000000 other-config:max-rate=3000000 \
  -- --id=@q3 create queue other-config:min-rate=200000  other-config:max-rate=1000000

echo "[INFO] Successfully created QoS on switch '$SWITCH'."

echo ""
echo "=========================================="
echo "[STEP 3] Verify the result"
echo "=========================================="

echo ""
echo "--- List of QoS ---"
ovs-vsctl list qos

echo ""
echo "--- First port ($SWITCH) ---"
FIRST_PORT=$(echo "$PORTS" | head -1)
ovs-vsctl get port "$FIRST_PORT" qos
