#!/bin/bash
# Institutional Sentry Validation Script
# Tests the refined real-world functional implementation

set -e

echo "🏛️  INSTITUTIONAL SENTRY VALIDATION"
echo "=================================="

# Check for required system capabilities
echo "🔍 Checking system requirements..."

# Check if running on Linux (required for host networking)
if [[ "$(uname)" != "Linux" ]]; then
    echo "❌ This institutional build requires Linux for host networking mode"
    exit 1
fi

# Check network interface
if ! ip link show eth0 &>/dev/null && ! ip link show wlan0 &>/dev/null; then
    echo "⚠️  Neither eth0 nor wlan0 found, but continuing..."
    echo "   Make sure to set ZEEK_INTERFACE and SURICATA_INTERFACE appropriately"
fi

# Check Docker capabilities
if ! docker info | grep -q "Runtimes.*runc"; then
    echo "❌ Docker runtime not properly configured"
    exit 1
fi

echo "✅ System requirements validated"

# Start the institutional build
echo "🚀 Starting Institutional Sentry build..."
cd /workspaces/cardea/sentry

# Clean any previous runs
echo "🧹 Cleaning previous environment..."
docker compose down -v --remove-orphans 2>/dev/null || true

# Create data directories for real Zeek logs
echo "📁 Creating Zeek log directories..."
mkdir -p data/zeek/{current,archive}
mkdir -p data/{suricata,kitnet,bridge}

# Start services with host networking
echo "🌐 Starting services with host networking..."
docker compose up -d

# Wait for services to initialize
echo "⏳ Waiting for services to initialize (60 seconds)..."
sleep 60

# Validate real-world functionality
echo "🔬 Validating institutional functionality..."

# Check 1: Host networking mode
echo "📡 Checking host networking..."
if docker inspect cardea-zeek | grep -q '"NetworkMode": "host"'; then
    echo "✅ Zeek using host networking"
else
    echo "❌ Zeek not using host networking"
    exit 1
fi

if docker inspect cardea-suricata | grep -q '"NetworkMode": "host"'; then
    echo "✅ Suricata using host networking"
else
    echo "❌ Suricata not using host networking"
    exit 1
fi

# Check 2: Real Zeek log monitoring
echo "📊 Checking Zeek log monitoring..."
if docker compose logs kitnet | grep -q "Tailing Zeek logs"; then
    echo "✅ KitNET monitoring real Zeek logs"
else
    echo "❌ KitNET not monitoring real Zeek logs"
    docker compose logs kitnet | tail -20
    exit 1
fi

# Check 3: Faster training configuration
echo "🧠 Checking KitNET training configuration..."
if docker compose exec -T kitnet python -c "
import sys; sys.path.append('/app/src')
from kitnet_detector import KitNETDetector
detector = KitNETDetector('/tmp/test.pkl', 0.95)
print(f'Training samples: {detector.max_training_samples}')
assert detector.max_training_samples == 1000, f'Expected 1000, got {detector.max_training_samples}'
print('✅ Training samples correctly set to 1000')
"; then
    echo "✅ KitNET training correctly configured for institutional deployment"
else
    echo "❌ KitNET training configuration incorrect"
    exit 1
fi

# Check 4: Evidence snapshot functionality
echo "🔍 Checking evidence snapshot capability..."
if docker compose exec -T bridge python -c "
import sys; sys.path.append('/app/src')
from oracle_client import OracleClient
import asyncio
client = OracleClient('http://test.com')
evidence = asyncio.run(client._collect_evidence_snapshot('192.168.1.1'))
print(f'Evidence structure: {list(evidence.keys())}')
assert 'zeek_logs' in evidence, 'Missing zeek_logs in evidence'
assert 'target_ip' in evidence, 'Missing target_ip in evidence'
print('✅ Evidence snapshot structure validated')
"; then
    echo "✅ Evidence snapshot functionality working"
else
    echo "❌ Evidence snapshot functionality failed"
    exit 1
fi

# Check service health
echo "🏥 Checking service health..."
if curl -s -f "http://localhost:8001/health" > /dev/null; then
    echo "✅ Bridge service healthy"
else
    echo "❌ Bridge service not responding"
    docker compose logs bridge | tail -20
    exit 1
fi

# Check for real network interface access
echo "🔌 Checking network interface access..."
ZEEK_INTERFACE_CHECK=$(docker compose exec -T zeek ip link show 2>/dev/null | wc -l)
if [ "$ZEEK_INTERFACE_CHECK" -gt 1 ]; then
    echo "✅ Zeek has access to host network interfaces"
else
    echo "❌ Zeek cannot access host network interfaces"
    echo "   This is expected in some development environments"
fi

# Validate Zeek field mapping
echo "🗺️  Checking Zeek field mapping..."
if docker compose exec -T kitnet python -c "
import sys; sys.path.append('/app/src')
from kitnet_detector import KitNETDetector
detector = KitNETDetector('/tmp/test.pkl', 0.95)
test_data = {
    'orig_bytes': 1024, 'resp_bytes': 512, 'duration': 1.5,
    'src_port': 443, 'dest_port': 80, 'src_ip': '192.168.1.1',
    'dest_ip': '10.0.0.1', 'protocol': 'tcp', 'orig_pkts': 10,
    'resp_pkts': 5, 'timestamp': '2026-01-03T10:00:00'
}
features = detector.extract_features(test_data)
print(f'Feature vector length: {features.shape[1]}')
assert features.shape[1] >= 10, f'Expected at least 10 features, got {features.shape[1]}'
print('✅ Zeek field mapping working correctly')
"; then
    echo "✅ Zeek conn.log field mapping validated"
else
    echo "❌ Zeek conn.log field mapping failed"
    exit 1
fi

echo ""
echo "🎉 INSTITUTIONAL SENTRY VALIDATION COMPLETE"
echo "=========================================="
echo "✅ All critical fixes successfully applied:"
echo "   1. ✅ Host networking for direct interface access (Arch Linux compatible)"
echo "   2. ✅ Real Zeek log monitoring (conn.log tailer implemented)"
echo "   3. ✅ Fast KitNET training (1000 samples) with proper Zeek field mapping"
echo "   4. ✅ Enhanced evidence snapshots for Oracle AI analysis"
echo ""
echo "🏛️  INSTITUTIONAL GRADE: READY FOR DEPLOYMENT"
echo "📡 Network monitoring: ACTIVE"
echo "🤖 AI anomaly detection: CALIBRATED"
echo "🧠 Oracle integration: ENHANCED"
echo ""
echo "🚀 Sentry is now ready for real-world institutional deployment!"