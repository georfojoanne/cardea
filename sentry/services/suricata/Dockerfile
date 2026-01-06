# Suricata Intrusion Detection Service
FROM ubuntu:22.04

# Avoid interactive prompts during build
ARG DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    suricata \
    suricata-update \
    curl \
    iproute2 \
    python3 \
    python3-pip \
    jq \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /var/log/suricata /var/lib/suricata/rules \
    /etc/suricata/custom /etc/suricata/custom/rules /app/scripts

# Copy configuration files
COPY config/suricata.yaml /etc/suricata/custom/
COPY config/threshold.config /etc/suricata/custom/
COPY config/rules/ /etc/suricata/custom/rules/
COPY scripts/ /app/scripts/

# Set permissions
RUN chmod +x /app/scripts/*.py

# Install Python dependencies for log processing
RUN pip3 install pyyaml requests

# Environment variables
ENV SURICATA_INTERFACE=auto
ENV SURICATA_MODE=live
ENV LOG_LEVEL=info
ENV BRIDGE_HOST=localhost
ENV BRIDGE_PORT=8001

# Health check using our enhanced script
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD python3 /app/scripts/health_check.py || exit 1

# Startup script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /app

ENTRYPOINT ["/entrypoint.sh"]