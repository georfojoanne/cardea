# Project Cardea

> A hybrid, agentic AI cybersecurity platform for Small-to-Medium Enterprises

## Overview

Project Cardea provides cost-effective 24/7 cybersecurity monitoring through a dual-layer architecture:

- **Cardea Sentry (The Reflex)** - Local edge detection system running on-premise ✅ **FUNCTIONAL**
- **Cardea Oracle (The Brain)** - Cloud-based AI threat analysis and management 🚧 **PHASE 3**
- **Web Dashboard** - Real-time monitoring and management interface 📋 **PHASE 4**

## Current Status: Phase 2 Complete ✅

**Sentry Layer is now fully functional and ready for independent deployment!**

### Completed Features ✅
- **Real Network Monitoring**: Zeek processes actual network traffic (not simulation)
- **Intrusion Detection**: Suricata provides real-time threat detection
- **AI Anomaly Detection**: KitNET analyzes network patterns
- **Cross-Platform Support**: Automatic OS and network interface detection
- **Service Orchestration**: Bridge coordinates all services and prepares Oracle integration
- **Production Ready**: Docker containers with proper configuration management

### Ready for Testing 🧪
```bash
# Quick validation and startup
./scripts/start-sentry.sh

# Manual verification
cd sentry && docker-compose up
```

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Cardea Sentry │────│  Cardea Oracle  │────│   Web Dashboard │
│   (Edge Layer)  │    │  (Cloud Layer)  │    │  (User Layer)   │
│      ✅ READY    │    │   🚧 PHASE 3    │    │   📋 PHASE 4    │
│                 │    │                 │    │                 │
│ • Zeek          │    │ • Oracle Cloud  │    │ • Next.js       │
│ • Suricata      │    │ • Autonomous DB │    │ • React Flow    │
│ • KitNET        │    │ • OCI Functions │    │ • Shadcn UI     │
│ • Bridge        │    │ • ML Pipeline   │    │ • Notifications │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Quick Start - Sentry Deployment

### Prerequisites
- **Docker** (20.10+) and **Docker Compose** (v2+)
- **Linux/macOS** (Windows via WSL2)
- **Network access** for packet capture
- **Python 3.9+** (for development)

### 1. Automated Setup
```bash
# Clone and setup
git clone <repository>
cd cardea

# Make scripts executable
chmod +x scripts/*.sh

# Validate and start services
./scripts/start-sentry.sh
```

### 2. Manual Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env to match your network interface

# Start services
cd sentry
docker-compose up -d
```

### 3. Verify Operation
```bash
# Check service status
docker-compose ps

# Test Bridge API
curl http://localhost:8080/health

# View live logs
docker-compose logs -f
```

## Service Architecture

### Zeek (Network Analysis)
- **Function**: Passive network traffic monitoring
- **Output**: Connection logs (`sentry/data/zeek/conn.log`)
- **Features**: Real-time protocol analysis, metadata extraction

### Suricata (Intrusion Detection)
- **Function**: Real-time threat detection and alerting
- **Output**: EVE JSON alerts (`sentry/data/suricata/eve.json`)
- **Features**: Signature-based detection, protocol anomalies

### KitNET (AI Anomaly Detection)
- **Function**: Machine learning anomaly detection
- **Input**: Zeek connection logs
- **Features**: Adaptive learning, real-time scoring

### Bridge (Orchestration)
- **Function**: Service coordination and API gateway
- **API**: REST API at http://localhost:8080
- **Features**: Alert aggregation, Oracle preparation, health monitoring

## Platform Compatibility

Cardea automatically adapts to your environment:

### Supported Platforms
- **Ubuntu/Debian** (APT package management)
- **Arch Linux** (Pacman optimization)
- **CentOS/RHEL** (YUM/DNF packages)
- **macOS** (Homebrew integration)

### Network Interface Detection
```bash
# Test platform detection
python3 -c "
from shared.utils.platform_detector import PlatformDetector
detector = PlatformDetector()
print('OS:', detector.get_os_info())
print('Interfaces:', detector.get_network_interfaces())
"
```

## Project Structure

```
cardea/
├── sentry/           # ✅ Edge layer (COMPLETE)
│   ├── services/     # Zeek, Suricata, KitNET, Bridge
│   ├── data/         # Service logs and outputs
│   └── docker-compose.yml
├── oracle/           # 🚧 Cloud layer (PHASE 3)
├── dashboard/        # 📋 User interface (PHASE 4) 
├── shared/           # ✅ Common utilities (COMPLETE)
│   └── utils/        # Platform detection, configuration
├── scripts/          # ✅ Automation (COMPLETE)
│   ├── start-sentry.sh      # Main startup script
│   └── validate_runtime.py  # Testing utilities
└── docs/             # 📋 Documentation (EXPANDING)
```

## Development & Testing

### Runtime Validation
```bash
# Basic functionality test
python3 test_runtime_basic.py

# Comprehensive validation
./scripts/start-sentry.sh check

# Platform compatibility test
python3 shared/utils/platform_cli.py
```

### Service Management
```bash
# Start services
./scripts/start-sentry.sh start

# Check status
./scripts/start-sentry.sh check

# Stop services
./scripts/start-sentry.sh stop
```

### Development Mode
```bash
# Local development with hot reload
cd sentry/bridge
python -m uvicorn src.bridge_service:app --reload --host 0.0.0.0
```

## Configuration

### Environment Variables (.env)
```bash
# Network interfaces (auto-detected)
ZEEK_INTERFACE=eth0
SURICATA_INTERFACE=eth0

# Service configuration
LOG_LEVEL=info
BRIDGE_PORT=8080

# Development settings
DEV_MODE=true
DEBUG_SERVICES=false
```

### Performance Tuning
```bash
# Worker processes
ZEEK_WORKERS=2
SURICATA_THREADS=auto

# Buffer sizes
KITNET_BUFFER_SIZE=10000

# Resource limits (docker-compose.yml)
mem_limit: 2g
```

## Monitoring & Troubleshooting

### Health Checks
```bash
# API health
curl http://localhost:8080/health

# Service status
docker-compose ps

# Resource usage
docker stats
```

### Common Issues
- **Permission denied**: Add user to docker group
- **Interface not found**: Check `ip addr` and update `.env`
- **High CPU usage**: Reduce `ZEEK_WORKERS` or limit monitored traffic

## Next Steps - Phase 3: Oracle Integration

With Sentry now fully functional, the next phase will add:
- **Oracle Autonomous Database** for threat intelligence storage
- **OCI Functions** for serverless alert processing
- **Advanced ML Pipeline** for pattern recognition
- **API Gateway** for secure cloud communication

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**🚀 Status**: Sentry layer is production-ready and independently deployable!

## License

MIT License - see [LICENSE](LICENSE) for details.
