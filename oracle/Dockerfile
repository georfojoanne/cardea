FROM python:3.11-slim

# Install system dependencies + COMPILERS required for scikit-learn/pandas
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    g++ \
    build-essential \
    libpq-dev \
    postgresql-client \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first
COPY requirements.txt ./requirements.txt

# Install dependencies (This will take longer now but will succeed)
RUN pip install --no-cache-dir -r requirements.txt

# Create directories
RUN mkdir -p /app/data /app/config /app/logs

# Copy application code
COPY src/ ./src/
COPY config/ ./config/
COPY scripts/ ./scripts/

# Security: Non-root user
RUN useradd -r -s /bin/false -d /app oracle \
    && chown -R oracle:oracle /app

ENV PYTHONPATH=/app \
    LOG_LEVEL=info \
    PORT=8000 \
    PYTHONUNBUFFERED=1 \
    DATABASE_URL=postgresql+asyncpg://oracle:password@db:5432/cardea_oracle

EXPOSE 8000

USER oracle

# Use the main.py we refactored, or simple_main.py if you prefer
ENTRYPOINT ["python", "src/main.py"]