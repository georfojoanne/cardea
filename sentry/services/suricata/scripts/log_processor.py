#!/usr/bin/env python3
"""
Suricata Log Processor
Processes Suricata EVE JSON logs and sends alerts to Bridge service
"""

import json
import time
import requests
from pathlib import Path
from typing import Dict, Any
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SuricataLogProcessor:
    def __init__(self):
        self.bridge_url = "http://bridge:8001"
        self.eve_log_path = Path("/var/log/suricata/eve.json")
        self.last_position = 0
        
    def process_alert(self, alert_data: Dict[str, Any]) -> None:
        """Process and forward Suricata alerts to Bridge service"""
        try:
            # Extract relevant alert information
            alert_info = {
                "source": "suricata",
                "timestamp": alert_data.get("timestamp"),
                "alert": {
                    "signature": alert_data.get("alert", {}).get("signature", "Unknown"),
                    "category": alert_data.get("alert", {}).get("category", "Unknown"),
                    "severity": alert_data.get("alert", {}).get("severity", 3),
                    "signature_id": alert_data.get("alert", {}).get("signature_id")
                },
                "network": {
                    "src_ip": alert_data.get("src_ip"),
                    "dest_ip": alert_data.get("dest_ip"),
                    "src_port": alert_data.get("src_port"),
                    "dest_port": alert_data.get("dest_port"),
                    "protocol": alert_data.get("proto")
                },
                "flow_id": alert_data.get("flow_id")
            }
            
            # Send to Bridge service
            response = requests.post(
                f"{self.bridge_url}/api/v1/alerts/suricata",
                json=alert_info,
                timeout=5
            )
            
            if response.status_code == 200:
                logger.info(f"Alert forwarded: {alert_info['alert']['signature']}")
            else:
                logger.error(f"Failed to forward alert: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error processing alert: {e}")
    
    def tail_eve_log(self) -> None:
        """Tail Suricata EVE log file and process new entries"""
        logger.info("Starting Suricata log processor...")
        
        while True:
            try:
                if self.eve_log_path.exists():
                    with open(self.eve_log_path, 'r') as f:
                        f.seek(self.last_position)
                        
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                                
                            try:
                                event = json.loads(line)
                                
                                # Process alerts
                                if event.get("event_type") == "alert":
                                    self.process_alert(event)
                                    
                            except json.JSONDecodeError:
                                logger.warning(f"Invalid JSON line: {line[:100]}...")
                                continue
                        
                        self.last_position = f.tell()
                
                time.sleep(1)  # Check for new logs every second
                
            except Exception as e:
                logger.error(f"Error tailing log file: {e}")
                time.sleep(5)

if __name__ == "__main__":
    processor = SuricataLogProcessor()
    processor.tail_eve_log()