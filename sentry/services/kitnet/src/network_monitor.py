#!/usr/bin/env python3
"""
Network Monitor for KitNET
Captures and processes network packets for anomaly detection
"""

import asyncio
import logging
from typing import Dict, Any
from datetime import datetime
import json

logger = logging.getLogger(__name__)

class NetworkMonitor:
    """Network packet monitor for KitNET processing"""
    
    def __init__(self):
        self.packet_count = 0
        self.is_monitoring = False
        
    async def start_monitoring(self, packet_queue: asyncio.Queue):
        """Start network packet monitoring"""
        logger.info("📡 Starting network packet monitoring...")
        self.is_monitoring = True
        
        # Simulate packet capture in development
        # In production, this would interface with real packet capture
        await self._simulate_packet_capture(packet_queue)
    
    async def _simulate_packet_capture(self, packet_queue: asyncio.Queue):
        """Simulate packet capture for development/testing"""
        logger.info("🧪 Simulating network packets for development...")
        
        while self.is_monitoring:
            # Generate synthetic packet data for testing
            packet_data = self._generate_test_packet()
            await packet_queue.put(packet_data)
            
            self.packet_count += 1
            
            # Log progress every 100 packets
            if self.packet_count % 100 == 0:
                logger.debug(f"Processed {self.packet_count} packets")
            
            # Simulate packet arrival rate
            await asyncio.sleep(0.1)  # 10 packets per second
    
    def _generate_test_packet(self) -> Dict[str, Any]:
        """Generate synthetic packet data for testing"""
        import random
        
        # Base packet structure
        packet = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": f"192.168.1.{random.randint(1, 254)}",
            "dest_ip": f"10.0.0.{random.randint(1, 254)}",
            "src_port": random.randint(1024, 65535),
            "dest_port": random.choice([80, 443, 22, 53, 21, 25]),
            "protocol": random.choice(["tcp", "udp", "icmp"]),
            "size": random.randint(64, 1500),
            "ttl": random.randint(32, 255),
            "tcp_flags": random.randint(0, 255)
        }
        
        # Occasionally generate "anomalous" packets for testing
        if random.random() < 0.01:  # 1% chance
            packet.update({
                "src_ip": f"192.168.1.{random.randint(200, 254)}",  # Different subnet
                "dest_port": random.randint(8000, 9999),  # Unusual port
                "size": random.randint(1400, 1500),  # Large packet
                "ttl": random.randint(1, 10),  # Low TTL
            })
        
        return packet
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        logger.info("🛑 Stopping network packet monitoring...")
        self.is_monitoring = False