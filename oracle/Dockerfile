# Oracle Backend Service - Cloud Intelligence Platform
# FastAPI-based security analytics and threat correlation service

FROM python:3.11-slim

# Install system dependencies (optimized for cloud deployment)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    postgresql-client \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Create app directory
WORKDIR /app

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --compile -r requirements.txt \
    && pip cache purge

# Create necessary directories
RUN mkdir -p /app/data /app/config /app/logs

# Copy application code
COPY src/ ./src/
COPY config/ ./config/
COPY scripts/ ./scripts/

# Create non-root user for security
RUN useradd -r -s /bin/false -d /app oracle \
    && chown -R oracle:oracle /app

# Environment variables
ENV PYTHONPATH=/app \
    LOG_LEVEL=info \
    PORT=8000 \
    PYTHONUNBUFFERED=1 \
    DATABASE_URL=postgresql://oracle:password@db:5432/cardea_oracle

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

USER oracle

ENTRYPOINT ["python", "src/main.py"]