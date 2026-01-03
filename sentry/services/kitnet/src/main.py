#!/usr/bin/env python3
"""
KitNET AI Anomaly Detection Service
Main entry point for network anomaly detection using KitNET ensemble autoencoders
"""

import os
import sys
import asyncio
import logging
from pathlib import Path

# Add src to Python path
sys.path.insert(0, '/app/src')

from kitnet_detector import KitNETDetector
from network_monitor import NetworkMonitor
from alert_manager import AlertManager

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class KitNETService:
    """Main KitNET service orchestrator"""
    
    def __init__(self):
        self.threshold = float(os.getenv('KITNET_THRESHOLD', '0.95'))
        self.bridge_url = os.getenv('BRIDGE_URL', 'http://bridge:8001')
        self.data_dir = Path('/app/data')
        self.config_dir = Path('/app/config')
        
        # Initialize components
        self.detector = KitNETDetector(
            model_path=self.data_dir / 'kitnet_model.pkl',
            threshold=self.threshold
        )
        self.monitor = NetworkMonitor()
        self.alert_manager = AlertManager(self.bridge_url)
        
        logger.info(f"KitNET service initialized with threshold: {self.threshold}")
    
    async def start(self):
        """Start the KitNET anomaly detection service"""
        logger.info("🤖 Starting KitNET AI anomaly detection service...")
        
        try:
            # Initialize detector (training phase if no model exists)
            await self.detector.initialize()
            
            # Start network monitoring
            packet_queue = asyncio.Queue()
            monitor_task = asyncio.create_task(
                self.monitor.start_monitoring(packet_queue)
            )
            
            # Start packet processing
            processor_task = asyncio.create_task(
                self.process_packets(packet_queue)
            )
            
            logger.info("✅ KitNET service started successfully")
            
            # Run until shutdown
            await asyncio.gather(monitor_task, processor_task)
            
        except Exception as e:
            logger.error(f"❌ KitNET service failed: {e}")
            raise
    
    async def process_packets(self, packet_queue: asyncio.Queue):
        """Process packets and detect anomalies"""
        logger.info("🔍 Starting packet anomaly detection...")
        
        while True:
            try:
                # Get packet from queue
                packet_data = await packet_queue.get()
                
                # Extract features and detect anomaly
                features = self.detector.extract_features(packet_data)
                anomaly_score = self.detector.detect_anomaly(features)
                
                # Check if anomaly exceeds threshold
                if anomaly_score >= self.threshold:
                    await self.handle_anomaly(packet_data, anomaly_score)
                
                # Mark task as done
                packet_queue.task_done()
                
            except Exception as e:
                logger.error(f"Error processing packet: {e}")
                continue
    
    async def handle_anomaly(self, packet_data: dict, score: float):
        """Handle detected anomaly by alerting Bridge service"""
        logger.warning(f"🚨 Anomaly detected with score: {score:.4f}")
        
        alert_data = {
            "source": "kitnet",
            "timestamp": packet_data.get("timestamp"),
            "anomaly_score": score,
            "threshold": self.threshold,
            "network": {
                "src_ip": packet_data.get("src_ip"),
                "dest_ip": packet_data.get("dest_ip"),
                "src_port": packet_data.get("src_port"),
                "dest_port": packet_data.get("dest_port"),
                "protocol": packet_data.get("protocol"),
                "packet_size": packet_data.get("size")
            },
            "features": packet_data.get("features", {})
        }
        
        # Send alert to Bridge service
        await self.alert_manager.send_alert(alert_data)

async def main():
    """Main entry point"""
    service = KitNETService()
    
    try:
        await service.start()
    except KeyboardInterrupt:
        logger.info("🛑 KitNET service stopping...")
    except Exception as e:
        logger.error(f"💥 KitNET service crashed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())