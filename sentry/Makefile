# Sentry Makefile
# Atomic development commands for edge layer services

.PHONY: help dev build clean test logs shell health

# Default target
help:
	@echo "Cardea Sentry (Edge Layer) - Development Commands"
	@echo ""
	@echo "Development:"
	@echo "  dev         Start development environment"
	@echo "  build       Build all service containers"
	@echo "  clean       Stop and clean containers/volumes"
	@echo "  logs        View service logs"
	@echo "  shell       Access bridge service shell"
	@echo ""
	@echo "Monitoring:"
	@echo "  health      Check service health status"
	@echo "  status      Show container status"
	@echo ""
	@echo "Testing:"
	@echo "  test        Run all service tests"
	@echo "  test-unit   Run unit tests only"
	@echo "  test-integration  Run integration tests"

# Development environment
dev:
	@echo "🛡️ Starting Sentry development environment..."
	@mkdir -p data/{zeek,suricata,kitnet,bridge}
	@docker compose up -d
	@echo "✅ Sentry services started"
	@echo "📊 Web interface: http://localhost:3001"
	@echo "🔌 Bridge API: http://localhost:8001"

# Build all containers
build:
	@echo "🔨 Building Sentry service containers..."
	@docker compose build

# Clean environment
clean:
	@echo "🧹 Cleaning Sentry environment..."
	@docker compose down -v
	@docker compose rm -f
	@sudo rm -rf data/
	@echo "✅ Environment cleaned"

# View logs
logs:
	@docker compose logs -f

# Service-specific logs
logs-zeek:
	@docker compose logs -f zeek

logs-suricata:
	@docker compose logs -f suricata

logs-kitnet:
	@docker compose logs -f kitnet

logs-bridge:
	@docker compose logs -f bridge

logs-web:
	@docker compose logs -f web

# Access bridge shell for debugging
shell:
	@docker compose exec bridge /bin/bash

# Health checks
health:
	@echo "🔍 Checking Sentry service health..."
	@docker compose ps
	@echo ""
	@echo "Bridge Health:"
	@curl -s http://localhost:8001/health || echo "❌ Bridge not responding"

# Container status
status:
	@docker compose ps

# Testing
test:
	@echo "🧪 Running Sentry tests..."
	@make test-unit
	@make test-integration

test-unit:
	@echo "Running unit tests..."
	@docker compose exec bridge python -m pytest tests/unit/ -v

test-integration:
	@echo "Running integration tests..."
	@docker compose exec bridge python -m pytest tests/integration/ -v

# Network monitoring test
test-network:
	@echo "🌐 Testing network monitoring..."
	@docker compose exec bridge python scripts/test_network.py