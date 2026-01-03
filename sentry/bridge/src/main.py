#!/usr/bin/env python3
"""
Bridge Service - Orchestration and Alert Escalation
Main orchestration service that monitors KitNET scores and escalates to Oracle
"""

import os
import sys
import asyncio
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional

# Add src to Python path
sys.path.insert(0, '/app/src')

from api_server import APIServer
from alert_processor import AlertProcessor
from oracle_client import OracleClient
from sentry_status import SentryStatus

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class BridgeService:
    """Main Bridge service orchestrator"""
    
    def __init__(self):
        self.sentry_id = os.getenv('SENTRY_ID', 'sentry_001')
        self.oracle_url = os.getenv('ORACLE_WEBHOOK_URL', 'http://localhost:8000/api/alerts')
        self.alert_threshold = float(os.getenv('ALERT_THRESHOLD', '0.95'))
        self.port = int(os.getenv('PORT', '8001'))
        
        # Initialize components
        self.alert_processor = AlertProcessor(
            threshold=self.alert_threshold,
            sentry_id=self.sentry_id
        )
        self.oracle_client = OracleClient(self.oracle_url)
        self.sentry_status = SentryStatus()
        
        # API server
        self.api_server = APIServer(
            port=self.port,
            alert_processor=self.alert_processor,
            oracle_client=self.oracle_client,
            sentry_status=self.sentry_status
        )
        
        logger.info(f"Bridge service initialized for Sentry: {self.sentry_id}")
        logger.info(f"Oracle URL: {self.oracle_url}")
        logger.info(f"Alert threshold: {self.alert_threshold}")
    
    async def start(self):
        """Start the Bridge service"""
        logger.info("🌉 Starting Bridge orchestration service...")
        
        try:
            # Start status monitoring
            status_task = asyncio.create_task(
                self.sentry_status.start_monitoring()
            )
            
            # Start API server
            api_task = asyncio.create_task(
                self.api_server.start()
            )
            
            # Start alert processing
            processing_task = asyncio.create_task(
                self.alert_processor.start_processing()
            )
            
            logger.info("✅ Bridge service started successfully")
            logger.info(f"📡 API server running on port {self.port}")
            
            # Run all tasks
            await asyncio.gather(status_task, api_task, processing_task)
            
        except Exception as e:
            logger.error(f"❌ Bridge service failed: {e}")
            raise

async def main():
    """Main entry point"""
    service = BridgeService()
    
    try:
        await service.start()
    except KeyboardInterrupt:
        logger.info(" Bridge service stopping...")
    except Exception as e:
        logger.error(f" Bridge service crashed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())