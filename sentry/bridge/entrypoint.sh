#!/bin/bash
set -euo pipefail

echo "🌉 Starting Cardea Bridge Service..."

# Wait for other services to be ready
echo "⏳ Waiting for dependent services..."
sleep 10

# Create data directories
mkdir -p /opt/bridge/data /opt/zeek/logs /var/log/suricata /opt/kitnet/data

# Set environment variables
export BRIDGE_HOST=${BRIDGE_HOST:-0.0.0.0}
export BRIDGE_PORT=${BRIDGE_PORT:-8080}
export LOG_LEVEL=${LOG_LEVEL:-info}

echo "🚀 Starting Bridge API on ${BRIDGE_HOST}:${BRIDGE_PORT}..."

# Start the Bridge service
cd /opt/bridge
python -m uvicorn src.bridge_service:app --host $BRIDGE_HOST --port $BRIDGE_PORT --log-level $LOG_LEVEL