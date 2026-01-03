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

# Create basic site configuration
if [ ! -f "/opt/zeek/share/zeek/site/local.zeek" ]; then
    mkdir -p /opt/zeek/share/zeek/site
    cat > /opt/zeek/share/zeek/site/local.zeek << EOF
# Basic Zeek configuration
@load base/frameworks/cluster
@load base/frameworks/logging
@load base/protocols/conn
@load base/protocols/http
@load base/protocols/dns

# Enable JSON logging
redef LogAscii::output_to_file = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;
redef LogAscii::use_json = T;
EOF
fi

echo "✅ Zeek configuration complete"
echo "🌐 Monitoring interface: $ZEEK_INTERFACE"

# Start Zeek in standalone mode (more reliable for containers)
exec /opt/zeek/bin/zeek -i $ZEEK_INTERFACE /opt/zeek/share/zeek/site/local.zeek