#!/bin/bash
# Platform-Aware Environment Setup Script
# Dynamically detects platform and generates appropriate configuration

set -e

echo "🌍 CARDEA PLATFORM-AWARE SETUP"
echo "==============================="

# Function to check Python dependencies
check_python_deps() {
    echo "🐍 Checking Python dependencies..."
    if ! python3 -c "import platform, subprocess, json, yaml" 2>/dev/null; then
        echo "📦 Installing required Python packages..."
        pip3 install pyyaml 2>/dev/null || pip install pyyaml 2>/dev/null || {
            echo "❌ Could not install required Python packages"
            echo "   Please install: pip install pyyaml"
            exit 1
        }
    fi
    echo "✅ Python dependencies available"
}

# Function to detect and validate platform
detect_platform() {
    echo "🔍 Detecting platform capabilities..."
    
    cd /workspaces/cardea
    
    # Run platform detection
    python3 << 'EOF'
import sys
import os
sys.path.append('/workspaces/cardea/shared/utils')

from platform_detector import platform_detector
from environment_configurator import EnvironmentConfigurator

# Get platform configuration
platform_config = platform_detector.get_platform_config()
validation = platform_detector.validate_environment()

# Generate environment configuration
configurator = EnvironmentConfigurator()

# Generate platform report
report = configurator.generate_platform_report()
print(report)

# Generate environment file for Sentry
sentry_env_path = "/workspaces/cardea/sentry/.env"
env_config = configurator.generate_sentry_env(sentry_env_path)

print(f"\n📝 Environment configuration written to: {sentry_env_path}")

# Check if deployment is ready
if not validation["ready"]:
    print("\n❌ PLATFORM NOT READY FOR DEPLOYMENT")
    for error in validation["errors"]:
        print(f"   Error: {error}")
    sys.exit(1)
else:
    print("\n✅ PLATFORM READY FOR DEPLOYMENT")
    
    # Print key configuration
    print(f"\n🔧 Key Configuration:")
    print(f"   Network Interface: {env_config.get('ZEEK_INTERFACE', 'Not set')}")
    print(f"   Performance Mode: {env_config.get('ZEEK_PERFORMANCE_MODE', 'balanced')}")
    print(f"   Host Networking: {env_config.get('USE_HOST_NETWORKING', 'false')}")
    print(f"   Memory Limit (Zeek): {env_config.get('ZEEK_MEMORY_LIMIT', 'default')}")
EOF
}

# Function to generate Docker Compose configuration
generate_docker_config() {
    echo "🐳 Generating platform-optimized Docker configuration..."
    
    python3 << 'EOF'
import sys
import yaml
sys.path.append('/workspaces/cardea/shared/utils')

from environment_configurator import EnvironmentConfigurator

configurator = EnvironmentConfigurator()
docker_config = configurator.generate_docker_compose_config()

# Read existing docker-compose.yml
existing_compose_path = "/workspaces/cardea/sentry/docker-compose.yml"
platform_compose_path = "/workspaces/cardea/sentry/docker-compose.platform.yml"

# Write platform-optimized version
with open(platform_compose_path, 'w') as f:
    yaml.dump(docker_config, f, default_flow_style=False)

print(f"✅ Platform-optimized Docker Compose written to: {platform_compose_path}")
print("   Use this file for platform-specific optimizations")
EOF
}

# Function to validate network interfaces
validate_interfaces() {
    echo "🌐 Validating network interfaces..."
    
    # Get the detected interface from the generated config
    if [ -f "/workspaces/cardea/sentry/.env" ]; then
        DETECTED_INTERFACE=$(grep "ZEEK_INTERFACE=" /workspaces/cardea/sentry/.env | cut -d'=' -f2)
        echo "🔍 Detected interface: $DETECTED_INTERFACE"
        
        # Check if interface exists and is up
        if ip link show "$DETECTED_INTERFACE" &>/dev/null; then
            if ip link show "$DETECTED_INTERFACE" | grep -q "UP"; then
                echo "✅ Interface $DETECTED_INTERFACE is UP and ready"
            else
                echo "⚠️  Interface $DETECTED_INTERFACE exists but is DOWN"
                echo "   Consider bringing it up: sudo ip link set $DETECTED_INTERFACE up"
            fi
        else
            echo "❌ Interface $DETECTED_INTERFACE not found"
            echo "   Available interfaces:"
            ip link show | grep "^[0-9]" | cut -d: -f2 | sed 's/^ */   /'
        fi
    fi
}

# Function to check system capabilities
check_capabilities() {
    echo "🔐 Checking system capabilities..."
    
    # Check if running as root or with necessary capabilities
    if [ "$EUID" -eq 0 ]; then
        echo "✅ Running as root - packet capture capabilities available"
    else
        echo "👤 Running as non-root user"
        
        # Check for CAP_NET_RAW capability
        if command -v capsh >/dev/null 2>&1; then
            if capsh --print | grep -q "cap_net_raw"; then
                echo "✅ CAP_NET_RAW capability available"
            else
                echo "⚠️  CAP_NET_RAW capability not detected"
                echo "   May need to run with: sudo docker compose up"
            fi
        else
            echo "ℹ️  Cannot check capabilities (capsh not available)"
        fi
    fi
    
    # Check Docker access
    if docker info >/dev/null 2>&1; then
        echo "✅ Docker access confirmed"
    else
        echo "❌ Cannot access Docker"
        echo "   Try: sudo usermod -aG docker $USER && newgrp docker"
    fi
}

# Function to create platform-specific startup script
create_startup_script() {
    echo "📜 Creating platform-specific startup script..."
    
    cat > /workspaces/cardea/sentry/start-platform.sh << 'EOF'
#!/bin/bash
# Platform-Aware Sentry Startup Script

set -e

echo "🛡️  Starting Cardea Sentry (Platform-Optimized)"
echo "=============================================="

# Check if platform configuration exists
if [ ! -f ".env" ]; then
    echo "❌ Platform configuration not found!"
    echo "   Run: make dev-setup"
    exit 1
fi

# Load environment
set -a
source .env
set +a

echo "🌍 Platform: $(uname -s) $(uname -r)"
echo "🌐 Interface: ${ZEEK_INTERFACE:-eth0}"
echo "⚡ Performance: ${ZEEK_PERFORMANCE_MODE:-balanced}"
echo "🐳 Host Network: ${USE_HOST_NETWORKING:-false}"

# Create necessary directories
mkdir -p data/{zeek,suricata,kitnet,bridge}

# Use platform-optimized compose if available
if [ -f "docker-compose.platform.yml" ]; then
    echo "🔧 Using platform-optimized configuration"
    docker compose -f docker-compose.platform.yml up -d
else
    echo "🔧 Using standard configuration"
    docker compose up -d
fi

echo "✅ Sentry started with platform optimizations"
echo "📊 Monitor: http://localhost:3001"
echo "🔌 API: http://localhost:8001"
EOF

    chmod +x /workspaces/cardea/sentry/start-platform.sh
    echo "✅ Platform startup script created: sentry/start-platform.sh"
}

# Main execution
main() {
    check_python_deps
    detect_platform
    
    # Only continue if platform validation passed
    if [ $? -eq 0 ]; then
        generate_docker_config
        validate_interfaces
        check_capabilities
        create_startup_script
        
        echo ""
        echo "🎉 PLATFORM-AWARE SETUP COMPLETE"
        echo "================================"
        echo "✅ Environment detected and configured"
        echo "✅ Docker configuration optimized"
        echo "✅ Network interfaces validated"
        echo "✅ System capabilities checked"
        echo ""
        echo "🚀 To start Sentry with platform optimizations:"
        echo "   cd sentry && ./start-platform.sh"
        echo ""
        echo "📝 Configuration files generated:"
        echo "   sentry/.env - Environment variables"
        echo "   sentry/docker-compose.platform.yml - Optimized Docker config"
        echo "   sentry/start-platform.sh - Platform-aware startup script"
    else
        echo "❌ Platform setup failed. Please address the errors above."
        exit 1
    fi
}

main "$@"