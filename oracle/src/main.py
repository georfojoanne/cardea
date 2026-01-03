#!/usr/bin/env python3
"""
Oracle Backend Main Entry Point
Cloud-native security analytics and threat correlation platform
"""

import os
import sys
import logging
import uvicorn
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent))

from oracle_service import create_app
from database import init_database
from config import settings

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

async def startup():
    """Application startup tasks"""
    logger.info("🔮 Starting Oracle Backend Service...")
    
    # Initialize database
    try:
        await init_database()
        logger.info("✅ Database initialized successfully")
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
        sys.exit(1)
    
    logger.info(f"🌍 Oracle service starting on port {settings.PORT}")

def main():
    """Main entry point"""
    try:
        app = create_app()
        
        # Run the server
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=settings.PORT,
            log_level=settings.LOG_LEVEL.lower(),
            access_log=True
        )
    except Exception as e:
        logger.error(f"Failed to start Oracle service: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()