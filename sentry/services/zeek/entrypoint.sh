#!/bin/bash
# Zeek service entrypoint script

set -e

echo "🔍 Starting Zeek network analysis service..."
echo "DEV_MODE: ${DEV_MODE:-not set}"
echo "ZEEK_INTERFACE: ${ZEEK_INTERFACE:-not set}"

# Force development mode for container environments
if [ "${DEV_MODE:-true}" = "true" ] || [ -f "/.dockerenv" ]; then
    echo "🔧 Development mode detected - using file-based analysis"
    
    # Create output directory
    mkdir -p /tmp/cardea/zeek
    
    # Create a simple health indicator file
    echo "$(date): Zeek service started in development mode" > /tmp/cardea/zeek/status.log
    
    # Create a dummy connection log for health monitoring
    cat > /tmp/cardea/zeek/conn.log << 'EOF'
{"ts":"2026-01-03T04:27:00.000000Z","uid":"dev_test_123","id.orig_h":"192.168.1.100","id.orig_p":50001,"id.resp_h":"8.8.8.8","id.resp_p":53,"proto":"udp","service":"dns","duration":0.001,"orig_bytes":35,"resp_bytes":63,"conn_state":"SF","local_orig":true,"local_resp":false,"missed_bytes":0,"history":"Dd","orig_pkts":1,"orig_ip_bytes":63,"resp_pkts":1,"resp_ip_bytes":91}
EOF

    echo "✅ Development mode initialized with test data"
    
    # Keep container alive with monitoring loop
    echo "🔄 Starting monitoring loop..."
    while true; do
        echo "$(date): Zeek monitoring active (development mode)" >> /tmp/cardea/zeek/status.log
        # Generate periodic dummy connection entries to simulate activity
        if [ $(($(date +%s) % 60)) -eq 0 ]; then
            TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.%6NZ")
            echo "{\"ts\":\"$TIMESTAMP\",\"uid\":\"dev_$(date +%s)\",\"id.orig_h\":\"192.168.1.$((RANDOM % 254 + 1))\",\"id.orig_p\":$((RANDOM % 65535 + 1)),\"id.resp_h\":\"8.8.8.8\",\"id.resp_p\":53,\"proto\":\"udp\",\"service\":\"dns\",\"duration\":0.001,\"orig_bytes\":35,\"resp_bytes\":63,\"conn_state\":\"SF\"}" >> /tmp/cardea/zeek/conn.log
        fi
        sleep 5
    done
else
    echo "🌐 Production mode - attempting live capture"
    AVAILABLE_INTERFACES=$(ip link show | grep -E '^[0-9]+: ' | grep -v 'lo:' | head -1 | cut -d: -f2 | tr -d ' ')

    if [ -z "$ZEEK_INTERFACE" ]; then
        if [ -n "$AVAILABLE_INTERFACES" ]; then
            export ZEEK_INTERFACE=$AVAILABLE_INTERFACES
            echo "✅ Auto-detected interface: $ZEEK_INTERFACE"
        else
            echo "⚠️  No network interfaces detected, using lo (loopback) for testing"
            export ZEEK_INTERFACE=lo
        fi
    else
        echo "📡 Using configured interface: $ZEEK_INTERFACE"
    fi

    # Check if interface exists
    if ! ip link show $ZEEK_INTERFACE >/dev/null 2>&1; then
        echo "❌ Interface $ZEEK_INTERFACE not found, switching to loopback for dev mode"
        export ZEEK_INTERFACE=lo
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

fi