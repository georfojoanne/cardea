#!/bin/bash
# Zeek service entrypoint script

set -e

echo "🔍 Starting Zeek network analysis service..."

# Validate environment
if [ -z "$ZEEK_INTERFACE" ]; then
    echo "❌ ZEEK_INTERFACE not set, using default: eth0"
    export ZEEK_INTERFACE=eth0
fi

# Create necessary directories
mkdir -p /opt/zeek/logs/current

# Generate node configuration if not exists
if [ ! -f "/opt/zeek/etc/node.cfg" ]; then
    echo "📝 Generating node configuration..."
    cat > /opt/zeek/etc/node.cfg << EOF
[manager]
type=manager
host=localhost

[logger]
type=logger
host=localhost

[worker-1]
type=worker
host=localhost
interface=$ZEEK_INTERFACE
EOF
fi

# Ensure proper permissions
sudo chown -R zeek:zeek /opt/zeek/logs

echo "✅ Zeek configuration complete"
echo "🌐 Monitoring interface: $ZEEK_INTERFACE"

# Start Zeek in cluster mode
exec /opt/zeek/bin/zeekctl deploy