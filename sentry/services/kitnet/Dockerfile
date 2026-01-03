# KitNET AI Anomaly Detection Service
FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create necessary directories
RUN mkdir -p /app/data /app/config /app/models

# Copy application code
COPY src/ ./src/
COPY scripts/ ./scripts/

# Create non-root user
RUN useradd -r -s /bin/false kitnet
RUN chown -R kitnet:kitnet /app

# Environment variables
ENV PYTHONPATH=/app
ENV LOG_LEVEL=info
ENV KITNET_THRESHOLD=0.95
ENV BRIDGE_URL=http://bridge:8001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD python scripts/health_check.py || exit 1

USER kitnet

ENTRYPOINT ["python", "src/main.py"]