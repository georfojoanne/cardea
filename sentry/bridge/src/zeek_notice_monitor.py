#!/usr/bin/env python3
"""
Zeek Notice Monitor for Bridge Service
Consumes Zeek notice.log and converts notices to high-priority security alerts.

Zeek notices are pre-filtered security events that Zeek's policy scripts
have already determined to be noteworthy. This provides detection capabilities
that complement Suricata's signature-based approach.

Key Zeek Notice Types:
- Scan::Port_Scan: Port scanning detected
- SSH::Password_Guessing: Brute force SSH attempts  
- SSL::Invalid_Server_Cert: Certificate validation failures
- HTTP::SQL_Injection_Attacker: SQL injection attempts
- Weird::Activity: Protocol anomalies
- Intel::Notice: IOC matches from threat intelligence
"""

import asyncio
import logging
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ZeekNotice:
    """Represents a parsed Zeek notice."""
    timestamp: str
    uid: Optional[str]
    src_ip: Optional[str]
    src_port: Optional[int]
    dest_ip: Optional[str]
    dest_port: Optional[int]
    note: str  # e.g., "Scan::Port_Scan"
    msg: str   # Human-readable message
    sub: Optional[str]  # Additional details
    actions: List[str]
    raw: Dict[str, Any]
    
    @property
    def category(self) -> str:
        """Extract category from note (e.g., 'Scan' from 'Scan::Port_Scan')."""
        if '::' in self.note:
            return self.note.split('::')[0]
        return self.note
    
    @property
    def subcategory(self) -> str:
        """Extract subcategory from note (e.g., 'Port_Scan' from 'Scan::Port_Scan')."""
        if '::' in self.note:
            return self.note.split('::')[1]
        return self.note
    
    def to_severity(self) -> str:
        """Map Zeek notice to severity level."""
        critical_notices = [
            'Intel::Notice',  # IOC match
            'Signatures::Sensitive_Signature',
            'HTTP::SQL_Injection_Attacker',
            'TeamCymruMalwareHashRegistry::Match',
        ]
        
        high_notices = [
            'Scan::Port_Scan',
            'Scan::Address_Scan',
            'SSH::Password_Guessing',
            'FTP::Bruteforcing',
            'SSL::Invalid_Server_Cert',
            'Weird::Activity',
            'TrackerHit',
        ]
        
        medium_notices = [
            'SSH::Interesting_Hostname',
            'SSL::Certificate_Expired',
            'Software::Vulnerable_Version',
            'CaptureLoss::Packet_Drops',
        ]
        
        if self.note in critical_notices or any(c in self.note for c in critical_notices):
            return 'critical'
        elif self.note in high_notices or any(h in self.note for h in high_notices):
            return 'high'
        elif self.note in medium_notices or any(m in self.note for m in medium_notices):
            return 'medium'
        return 'low'


# Mapping of Zeek notice types to MITRE ATT&CK techniques
NOTICE_TO_MITRE = {
    'Scan::Port_Scan': 'T1046 - Network Service Scanning',
    'Scan::Address_Scan': 'T1046 - Network Service Scanning',
    'SSH::Password_Guessing': 'T1110 - Brute Force',
    'FTP::Bruteforcing': 'T1110 - Brute Force',
    'HTTP::SQL_Injection_Attacker': 'T1190 - Exploit Public-Facing Application',
    'SSL::Invalid_Server_Cert': 'T1557 - Adversary-in-the-Middle',
    'Intel::Notice': 'Indicator of Compromise Match',
    'Weird::Activity': 'T1205 - Traffic Signaling / Protocol Anomaly',
    'TeamCymruMalwareHashRegistry::Match': 'T1204 - User Execution (Malware)',
    'Software::Vulnerable_Version': 'T1203 - Exploitation for Client Execution',
}


class ZeekNoticeMonitor:
    """
    Monitors Zeek notice.log for security-relevant events.
    
    This provides bridge-level integration of Zeek's built-in detection
    capabilities, which include:
    
    - Scan detection (port scans, address scans)
    - Brute force detection (SSH, FTP)
    - SSL/TLS anomalies (invalid certs, expired certs)
    - SQL injection attempts
    - Protocol anomalies (weird.log escalations)
    - Threat intelligence matches (Intel framework)
    """
    
    ZEEK_LOG_DIRS = [
        Path("/opt/zeek/logs/current"),
        Path("/opt/zeek/logs"),
        Path("/app/data/zeek"),
        Path("/var/log/zeek/current"),
        Path("/var/log/zeek"),
    ]
    
    def __init__(self, alert_callback: Optional[Callable] = None):
        """
        Initialize the notice monitor.
        
        Args:
            alert_callback: Async function to call when notices are detected.
                           Signature: async def callback(alert_data: Dict[str, Any])
        """
        self.alert_callback = alert_callback
        self.is_running = False
        self.last_position = 0
        self.notice_log_path: Optional[Path] = None
        self.notices_processed = 0
        self.notices_by_type: Dict[str, int] = {}
        
    def _find_notice_log(self) -> Optional[Path]:
        """Locate the Zeek notice.log file."""
        for log_dir in self.ZEEK_LOG_DIRS:
            notice_path = log_dir / "notice.log"
            if notice_path.exists():
                return notice_path
            # Also check parent if 'current' doesn't have it yet
            if log_dir.parent.exists():
                alt_path = log_dir.parent / "notice.log"
                if alt_path.exists():
                    return alt_path
        return None
    
    async def start(self):
        """Start monitoring Zeek notice.log."""
        self.is_running = True
        logger.info("🔔 Starting Zeek Notice Monitor...")
        
        self.notice_log_path = self._find_notice_log()
        
        if self.notice_log_path:
            logger.info(f"📋 Found notice.log at: {self.notice_log_path}")
        else:
            logger.warning("⚠️ No notice.log found - will check periodically")
        
        await self._monitor_loop()
    
    async def stop(self):
        """Stop the monitor."""
        self.is_running = False
        logger.info("🛑 Zeek Notice Monitor stopped")
    
    async def _monitor_loop(self):
        """Main monitoring loop."""
        while self.is_running:
            try:
                # Try to find log if we haven't yet
                if not self.notice_log_path:
                    self.notice_log_path = self._find_notice_log()
                
                if self.notice_log_path and self.notice_log_path.exists():
                    await self._process_notices()
                
                await asyncio.sleep(1)  # Check every second
                
            except Exception as e:
                logger.error(f"Notice monitor error: {e}")
                await asyncio.sleep(5)
    
    async def _process_notices(self):
        """Process new entries in notice.log."""
        try:
            with open(self.notice_log_path, 'r') as f:
                f.seek(self.last_position)
                
                for line in f:
                    notice = self._parse_notice(line.strip())
                    if notice:
                        await self._handle_notice(notice)
                
                self.last_position = f.tell()
                
        except Exception as e:
            logger.debug(f"Error reading notice.log: {e}")
    
    def _parse_notice(self, line: str) -> Optional[ZeekNotice]:
        """Parse a notice.log line (JSON or TSV format)."""
        if not line or line.startswith('#'):
            return None
        
        try:
            # Try JSON first
            data = json.loads(line)
            return self._parse_json_notice(data)
        except json.JSONDecodeError:
            pass
        
        # Fallback to TSV
        return self._parse_tsv_notice(line)
    
    def _parse_json_notice(self, data: Dict[str, Any]) -> ZeekNotice:
        """Parse JSON format notice."""
        return ZeekNotice(
            timestamp=data.get('ts', datetime.now(timezone.utc).isoformat()),
            uid=data.get('uid'),
            src_ip=data.get('id.orig_h', data.get('src')),
            src_port=int(data.get('id.orig_p', data.get('p', 0)) or 0),
            dest_ip=data.get('id.resp_h', data.get('dst')),
            dest_port=int(data.get('id.resp_p', 0) or 0),
            note=data.get('note', 'Unknown'),
            msg=data.get('msg', ''),
            sub=data.get('sub'),
            actions=data.get('actions', []) if isinstance(data.get('actions'), list) else [],
            raw=data,
        )
    
    def _parse_tsv_notice(self, line: str) -> Optional[ZeekNotice]:
        """Parse TSV format notice (fallback)."""
        try:
            fields = line.split('\t')
            if len(fields) < 10:
                return None
            
            # TSV field order: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, 
            #                  fuid, file_mime_type, file_desc, proto, note, msg, sub, ...
            return ZeekNotice(
                timestamp=fields[0],
                uid=fields[1] if fields[1] != '-' else None,
                src_ip=fields[2] if fields[2] != '-' else None,
                src_port=int(fields[3]) if fields[3] != '-' else None,
                dest_ip=fields[4] if fields[4] != '-' else None,
                dest_port=int(fields[5]) if fields[5] != '-' else None,
                note=fields[10] if len(fields) > 10 else 'Unknown',
                msg=fields[11] if len(fields) > 11 else '',
                sub=fields[12] if len(fields) > 12 and fields[12] != '-' else None,
                actions=[],
                raw={'_raw_tsv': fields},
            )
        except (ValueError, IndexError) as e:
            logger.debug(f"TSV notice parse error: {e}")
            return None
    
    async def _handle_notice(self, notice: ZeekNotice):
        """Handle a parsed notice - convert to alert and callback."""
        self.notices_processed += 1
        self.notices_by_type[notice.note] = self.notices_by_type.get(notice.note, 0) + 1
        
        severity = notice.to_severity()
        mitre = NOTICE_TO_MITRE.get(notice.note, 'Unknown Technique')
        
        # Log the notice
        log_method = logger.warning if severity in ('high', 'critical') else logger.info
        log_method(f"🔔 Zeek Notice [{severity.upper()}] {notice.note}: {notice.msg}")
        
        # Build alert data
        alert_data = {
            'source': 'zeek_notice',
            'severity': severity,
            'event_type': f"zeek_{notice.category.lower()}",
            'description': f"[{notice.note}] {notice.msg}" + (f" - {notice.sub}" if notice.sub else ""),
            'raw_data': {
                'notice_type': notice.note,
                'category': notice.category,
                'subcategory': notice.subcategory,
                'mitre_technique': mitre,
                'src_ip': notice.src_ip,
                'src_port': notice.src_port,
                'dest_ip': notice.dest_ip,
                'dest_port': notice.dest_port,
                'uid': notice.uid,
                'zeek_msg': notice.msg,
                'zeek_sub': notice.sub,
                'zeek_actions': notice.actions,
                'timestamp': notice.timestamp,
            },
            'confidence': 0.9,  # Zeek notices are high-confidence
        }
        
        # Call the callback if provided
        if self.alert_callback:
            try:
                await self.alert_callback(alert_data)
            except Exception as e:
                logger.error(f"Alert callback failed: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Return monitoring statistics."""
        return {
            'notices_processed': self.notices_processed,
            'notices_by_type': dict(self.notices_by_type),
            'log_path': str(self.notice_log_path) if self.notice_log_path else None,
            'is_running': self.is_running,
        }


# Singleton instance for use in bridge_service
_notice_monitor: Optional[ZeekNoticeMonitor] = None


def get_notice_monitor(alert_callback: Optional[Callable] = None) -> ZeekNoticeMonitor:
    """Get or create the Zeek notice monitor singleton."""
    global _notice_monitor
    if _notice_monitor is None:
        _notice_monitor = ZeekNoticeMonitor(alert_callback)
    elif alert_callback and _notice_monitor.alert_callback is None:
        _notice_monitor.alert_callback = alert_callback
    return _notice_monitor
