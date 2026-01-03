#!/usr/bin/env python3
"""
Alert Manager for KitNET
Manages alert sending to Bridge service
"""

import asyncio
import logging
import aiohttp
from typing import Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class AlertManager:
    """Manages alert sending to Bridge service"""
    
    def __init__(self, bridge_url: str):
        self.bridge_url = bridge_url
        self.alert_count = 0
        self.session = None
        
    async def send_alert(self, alert_data: Dict[str, Any]):
        """Send alert to Bridge service"""
        try:
            if not self.session:
                self.session = aiohttp.ClientSession()
            
            endpoint = f"{self.bridge_url}/api/v1/alerts/kitnet"
            
            async with self.session.post(endpoint, json=alert_data) as response:
                if response.status == 200:
                    self.alert_count += 1
                    result = await response.json()
                    logger.info(f"✅ Alert sent to Bridge: {result.get('alert_id')}")
                else:
                    logger.error(f"❌ Failed to send alert: {response.status}")
                    
        except Exception as e:
            logger.error(f"Error sending alert to Bridge: {e}")
    
    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()