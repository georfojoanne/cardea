#!/usr/bin/env python3
"""
Simple Oracle Backend Test
Minimal service to test Docker build
"""

from fastapi import FastAPI
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Oracle Backend",
    version="1.0.0",
    description="Cloud-native security analytics platform"
)

@app.get("/health")
async def health_check():
    """Basic health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "oracle-backend"
    }

@app.get("/")
async def root():
    """Root endpoint"""
    return {"message": "Oracle Backend is running"}

if __name__ == "__main__":
    import uvicorn
    logger.info("🔮 Starting Oracle Backend Service...")
    uvicorn.run(app, host="0.0.0.0", port=8000)