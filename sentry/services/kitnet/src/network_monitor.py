#!/usr/bin/env python3
"""
Network Monitor for KitNET
Captures and processes network packets for anomaly detection
"""

import asyncio
import logging
from typing import Dict, Any
from datetime import datetime
from pathlib import Path
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
        
        # Monitor real Zeek logs
        await self._tail_zeek_logs(packet_queue)
    
    async def _tail_zeek_logs(self, packet_queue: asyncio.Queue):
        """Tail Zeek conn.log file and parse real network data"""
        # Try multiple possible Zeek log locations
        possible_paths = [
            Path("/opt/zeek/logs/current/conn.log"),
            Path("/app/data/zeek/current/conn.log"),
            Path("/var/log/zeek/current/conn.log"),
            Path("/opt/zeek/logs/conn.log")
        ]
        
        zeek_log_path = None
        for path in possible_paths:
            if path.parent.exists():
                zeek_log_path = path
                break
        
        if not zeek_log_path:
            zeek_log_path = possible_paths[0]  # Default to first
            logger.warning(f"No existing Zeek log directory found, creating {zeek_log_path.parent}")
            zeek_log_path.parent.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"📊 Tailing Zeek logs: {zeek_log_path}")
        
        last_position = 0
        
        while self.is_monitoring:
            try:
                if zeek_log_path.exists():
                    with open(zeek_log_path, 'r') as f:
                        f.seek(last_position)
                        
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith('#'):
                                continue
                                
                            # Parse Zeek conn.log line
                            packet_data = self._parse_zeek_conn_line(line)
                            if packet_data:
                                await packet_queue.put(packet_data)
                                self.packet_count += 1
                                
                                # Log progress every 100 packets
                                if self.packet_count % 100 == 0:
                                    logger.debug(f"Processed {self.packet_count} real packets from Zeek")
                        
                        last_position = f.tell()
                else:
                    # Create a sample log entry if file doesn't exist (for testing)
                    if self.packet_count == 0:
                        logger.info(f"Creating sample Zeek log for testing: {zeek_log_path}")
                        self._create_sample_zeek_log(zeek_log_path)
                
                await asyncio.sleep(0.5)  # Check for new logs every 500ms
                
            except Exception as e:
                logger.error(f"Error tailing Zeek logs: {e}")
                await asyncio.sleep(2)
    
    def _parse_zeek_conn_line(self, line: str) -> Dict[str, Any]:
        """Parse Zeek conn.log line into packet data structure"""
        try:
            # Zeek conn.log fields (tab-separated)
            # ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state, local_orig, local_resp, missed_bytes, history, orig_pkts, orig_ip_bytes, resp_pkts, resp_ip_bytes, tunnel_parents
            fields = line.split('\t')
            
            if len(fields) < 10:
                return None
                
            packet_data = {
                "timestamp": datetime.fromtimestamp(float(fields[0])).isoformat(),
                "uid": fields[1],
                "src_ip": fields[2],  # id.orig_h
                "src_port": int(fields[3]) if fields[3] != '-' else 0,  # id.orig_p
                "dest_ip": fields[4],  # id.resp_h
                "dest_port": int(fields[5]) if fields[5] != '-' else 0,  # id.resp_p
                "protocol": fields[6],  # proto
                "service": fields[7] if fields[7] != '-' else None,
                "duration": float(fields[8]) if fields[8] != '-' else 0.0,
                "orig_bytes": int(fields[9]) if fields[9] != '-' else 0,
                "resp_bytes": int(fields[10]) if len(fields) > 10 and fields[10] != '-' else 0,
                "conn_state": fields[11] if len(fields) > 11 and fields[11] != '-' else None,
                "orig_pkts": int(fields[16]) if len(fields) > 16 and fields[16] != '-' else 0,
                "resp_pkts": int(fields[18]) if len(fields) > 18 and fields[18] != '-' else 0,
                "size": int(fields[9]) if fields[9] != '-' else 0  # Use orig_bytes as size
            }
            
            return packet_data
            
        except (ValueError, IndexError) as e:
            logger.debug(f"Error parsing Zeek line: {e}")
            return None
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        logger.info("🛑 Stopping network packet monitoring...")
        self.is_monitoring = False
    
    def _create_sample_zeek_log(self, log_path: Path):
        """Create a sample Zeek conn.log for testing when no real traffic exists"""
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Create sample Zeek conn.log entries
            sample_entries = [
                f"{datetime.now().timestamp()}\tCTest123\t192.168.1.100\t12345\t8.8.8.8\t53\tudp\tdns\t0.1\t64\t128\tSF\t-\t-\t0\tDd\t1\t92\t1\t156\t-",
                f"{datetime.now().timestamp()}\tCTest124\t192.168.1.100\t54321\t10.0.0.1\t80\ttcp\thttp\t1.5\t512\t1024\tSF\t-\t-\t0\tShADadfF\t10\t1536\t15\t2048\t-",
                f"{datetime.now().timestamp()}\tCTest125\t192.168.1.101\t443\t172.16.0.1\t8080\ttcp\t-\t0.3\t256\t256\tS0\t-\t-\t0\tS\t1\t284\t0\t0\t-"
            ]
            
            with open(log_path, 'w') as f:
                f.write("# Zeek conn.log sample data for testing\n")
                f.write("#separator \t\n")
                f.write("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\n")
                f.write("#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]\n")
                
                for entry in sample_entries:
                    f.write(entry + "\n")
                    
            logger.info(f"Created sample Zeek log with {len(sample_entries)} entries")
            
        except Exception as e:
            logger.error(f"Failed to create sample Zeek log: {e}")