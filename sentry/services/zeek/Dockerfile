# Zeek Network Analysis Service
FROM ubuntu:22.04

# Avoid interactive prompts during build
ARG DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    gnupg \
    lsb-release \
    software-properties-common \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Add Zeek repository
RUN echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' > /etc/apt/sources.list.d/security:zeek.list
RUN wget -nv https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key -O Release.key
RUN apt-key add Release.key

# Install Zeek
RUN apt-get update && apt-get install -y zeek && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /opt/zeek/logs /opt/zeek/etc /opt/zeek/scripts

# Copy configuration and scripts
COPY config/ /opt/zeek/etc/
COPY scripts/ /opt/zeek/scripts/

# Create zeek user
RUN useradd -r -s /bin/false zeek
RUN chown -R zeek:zeek /opt/zeek

# Environment variables
ENV PATH=/opt/zeek/bin:$PATH
ENV ZEEK_INTERFACE=eth0
ENV LOG_LEVEL=info

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD pgrep -f zeek || exit 1

# Startup script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER zeek
WORKDIR /opt/zeek

EXPOSE 47760/tcp

ENTRYPOINT ["/entrypoint.sh"]