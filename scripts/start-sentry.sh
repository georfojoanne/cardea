#!/bin/bash
# Cardea Sentry - Application Startup Script
# Validates dependencies and starts the application

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

function log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

function log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

function log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

function log_error() {
    echo -e "${RED}❌ $1${NC}"
}

function check_docker() {
    log_info "Checking Docker availability..."
    
    if command -v docker &> /dev/null; then
        log_success "Docker is installed"
        
        if docker ps &> /dev/null; then
            log_success "Docker daemon is running"
            return 0
        else
            log_error "Docker daemon is not running"
            log_info "Start Docker daemon and try again"
            return 1
        fi
    else
        log_error "Docker is not installed"
        log_info "Install Docker: https://docs.docker.com/get-docker/"
        return 1
    fi
}

function check_docker_compose() {
    log_info "Checking Docker Compose availability..."
    
    if command -v docker-compose &> /dev/null; then
        log_success "Docker Compose is available"
        return 0
    elif docker compose version &> /dev/null; then
        log_success "Docker Compose (v2) is available"
        return 0
    else
        log_error "Docker Compose is not available"
        log_info "Install Docker Compose: https://docs.docker.com/compose/install/"
        return 1
    fi
}

function check_python_deps() {
    log_info "Checking Python dependencies..."
    
    local missing_deps=()
    
    # Check required Python packages
    for package in "fastapi" "aiohttp" "uvicorn"; do
        if ! python3 -c "import $package" &> /dev/null; then
            missing_deps+=("$package")
        fi
    done
    
    if [ ${#missing_deps[@]} -eq 0 ]; then
        log_success "Python dependencies are available"
        return 0
    else
        log_warning "Missing Python packages: ${missing_deps[*]}"
        log_info "Install with: pip3 install ${missing_deps[*]}"
        
        # Offer to install automatically
        read -p "Install missing packages automatically? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            pip3 install "${missing_deps[@]}"
            log_success "Dependencies installed"
            return 0
        else
            return 1
        fi
    fi
}

function validate_configs() {
    log_info "Validating service configurations..."
    
    local config_files=(
        "sentry/services/zeek/config/node.cfg"
        "sentry/services/zeek/config/zeek.cfg"
        "sentry/services/suricata/config/suricata.yaml"
        "sentry/docker-compose.yml"
    )
    
    local missing_configs=()
    
    for config in "${config_files[@]}"; do
        if [ ! -f "$config" ]; then
            missing_configs+=("$config")
        fi
    done
    
    if [ ${#missing_configs[@]} -eq 0 ]; then
        log_success "All configuration files present"
        return 0
    else
        log_error "Missing configuration files:"
        printf '  - %s\n' "${missing_configs[@]}"
        return 1
    fi
}

function create_data_directories() {
    log_info "Creating data directories..."
    
    local data_dirs=(
        "sentry/data/zeek"
        "sentry/data/suricata" 
        "sentry/data/kitnet"
        "sentry/logs"
    )
    
    for dir in "${data_dirs[@]}"; do
        mkdir -p "$dir"
        log_success "Created $dir"
    done
}

function start_services() {
    log_info "Starting Cardea Sentry services..."
    
    cd sentry
    
    # Use appropriate docker-compose command
    if command -v docker-compose &> /dev/null; then
        docker-compose up -d
    else
        docker compose up -d
    fi
    
    log_success "Services starting in background"
    log_info "Use 'docker-compose ps' to check status"
    log_info "Use 'docker-compose logs -f' to view logs"
    
    # Wait a moment and check if services are running
    sleep 5
    
    if command -v docker-compose &> /dev/null; then
        docker-compose ps
    else
        docker compose ps
    fi
}

function main() {
    echo "🛡️  CARDEA SENTRY - Startup Validation & Launch"
    echo "=============================================="
    
    # Change to project root
    cd "$(dirname "$0")/.."
    
    local checks_passed=0
    local total_checks=4
    
    # Run validation checks
    if check_docker; then
        ((checks_passed++))
    fi
    
    if check_docker_compose; then
        ((checks_passed++))
    fi
    
    if check_python_deps; then
        ((checks_passed++))
    fi
    
    if validate_configs; then
        ((checks_passed++))
    fi
    
    echo
    echo "=============================================="
    log_info "Validation Results: $checks_passed/$total_checks checks passed"
    
    if [ $checks_passed -eq $total_checks ]; then
        log_success "All checks passed! Starting services..."
        create_data_directories
        start_services
        
        echo
        log_success "🚀 Cardea Sentry is starting!"
        echo
        echo "📊 Access points:"
        echo "  • Bridge API: http://localhost:8080"
        echo "  • Zeek logs: sentry/data/zeek/"
        echo "  • Suricata logs: sentry/data/suricata/"
        echo
        echo "🔧 Management commands:"
        echo "  • Check status: cd sentry && docker-compose ps"
        echo "  • View logs: cd sentry && docker-compose logs -f"
        echo "  • Stop services: cd sentry && docker-compose down"
        
    elif [ $checks_passed -ge 3 ]; then
        log_warning "Most checks passed - minor issues detected"
        log_info "You may be able to proceed, but some features might not work"
    else
        log_error "Too many checks failed - please fix issues before starting"
        exit 1
    fi
}

# Handle script arguments
case "${1:-start}" in
    "start")
        main
        ;;
    "check")
        echo "🔍 Running validation checks only..."
        cd "$(dirname "$0")/.."
        check_docker && check_docker_compose && check_python_deps && validate_configs
        log_info "Use './scripts/start-sentry.sh start' to launch after fixing issues"
        ;;
    "stop")
        log_info "Stopping Cardea Sentry services..."
        cd "$(dirname "$0")/../sentry"
        if command -v docker-compose &> /dev/null; then
            docker-compose down
        else
            docker compose down
        fi
        log_success "Services stopped"
        ;;
    *)
        echo "Usage: $0 {start|check|stop}"
        echo "  start - Validate dependencies and start services (default)"
        echo "  check - Run validation checks only"
        echo "  stop  - Stop running services"
        exit 1
        ;;
esac