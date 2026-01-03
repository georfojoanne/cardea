# Suricata Intrusion Detection Service
FROM ubuntu:22.04

# Avoid interactive prompts during build
ARG DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    suricata \
    curl \
    python3 \
    python3-pip \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /var/log/suricata /etc/suricata/custom /app/scripts

# Create suricata user if not exists
RUN id -u suricata &>/dev/null || useradd -r -s /bin/false suricata

# Copy configuration
COPY config/ /etc/suricata/custom/
COPY scripts/ /app/scripts/

# Set permissions
RUN chown -R suricata:suricata /var/log/suricata /etc/suricata/custom

# Install Python dependencies for log processing
RUN pip3 install pyyaml requests

# Environment variables
ENV SURICATA_INTERFACE=eth0
ENV LOG_LEVEL=info

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD pgrep -f suricata || exit 1

# Startup script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /app

ENTRYPOINT ["/entrypoint.sh"]