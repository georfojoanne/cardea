#!/usr/bin/env python3
"""
Network Monitor for KitNET
Multi-log Zeek consumer for comprehensive network anomaly detection

This module consumes multiple Zeek log types to provide rich feature extraction:
- conn.log: Connection metadata (primary source)
- dns.log: DNS queries for C2/tunneling detection
- http.log: HTTP transactions for data exfil detection
- ssl.log: TLS metadata for certificate anomalies
- notice.log: Zeek's built-in security notices
"""

import asyncio
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from collections import defaultdict
import json

logger = logging.getLogger(__name__)


@dataclass
class ConnectionContext:
    """Enriched connection context from multiple Zeek logs"""
    uid: str
    conn_data: Dict[str, Any] = field(default_factory=dict)
    dns_queries: List[Dict[str, Any]] = field(default_factory=list)
    http_requests: List[Dict[str, Any]] = field(default_factory=list)
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    notices: List[Dict[str, Any]] = field(default_factory=list)
    files: List[Dict[str, Any]] = field(default_factory=list)


class ZeekLogParser:
    """
    Unified Zeek JSON log parser.
    Handles both JSON format (preferred) and TSV fallback.
    """
    
    @staticmethod
    def parse_line(line: str, log_type: str) -> Optional[Dict[str, Any]]:
        """Parse a single Zeek log line, auto-detecting format."""
        line = line.strip()
        if not line or line.startswith('#'):
            return None
        
        # Try JSON first (our configured format)
        try:
            data = json.loads(line)
            data['_log_type'] = log_type
            return ZeekLogParser._normalize_json_fields(data, log_type)
        except json.JSONDecodeError:
            pass
        
        # Fallback to TSV parsing
        return ZeekLogParser._parse_tsv(line, log_type)
    
    @staticmethod
    def _normalize_json_fields(data: Dict[str, Any], log_type: str) -> Dict[str, Any]:
        """Normalize Zeek JSON field names to consistent internal format."""
        normalized = {'_log_type': log_type, '_raw': data}
        
        # Common timestamp handling
        if 'ts' in data:
            normalized['timestamp'] = data['ts']
        
        # UID for correlation
        if 'uid' in data:
            normalized['uid'] = data['uid']
        
        if log_type == 'conn':
            normalized.update({
                'src_ip': data.get('id.orig_h', data.get('id_orig_h', '')),
                'src_port': int(data.get('id.orig_p', data.get('id_orig_p', 0)) or 0),
                'dest_ip': data.get('id.resp_h', data.get('id_resp_h', '')),
                'dest_port': int(data.get('id.resp_p', data.get('id_resp_p', 0)) or 0),
                'protocol': data.get('proto', 'tcp'),
                'service': data.get('service'),
                'duration': float(data.get('duration', 0) or 0),
                'orig_bytes': int(data.get('orig_bytes', 0) or 0),
                'resp_bytes': int(data.get('resp_bytes', 0) or 0),
                'conn_state': data.get('conn_state', ''),
                'orig_pkts': int(data.get('orig_pkts', 0) or 0),
                'resp_pkts': int(data.get('resp_pkts', 0) or 0),
                'history': data.get('history', ''),
                'missed_bytes': int(data.get('missed_bytes', 0) or 0),
            })
            
        elif log_type == 'dns':
            normalized.update({
                'src_ip': data.get('id.orig_h', data.get('id_orig_h', '')),
                'dest_ip': data.get('id.resp_h', data.get('id_resp_h', '')),
                'query': data.get('query', ''),
                'qtype_name': data.get('qtype_name', ''),
                'rcode_name': data.get('rcode_name', ''),
                'answers': data.get('answers', []),
                'TTLs': data.get('TTLs', []),
                'rejected': data.get('rejected', False),
                # DNS tunneling indicators
                'query_length': len(data.get('query', '')),
                'subdomain_count': data.get('query', '').count('.'),
            })
            
        elif log_type == 'http':
            normalized.update({
                'src_ip': data.get('id.orig_h', data.get('id_orig_h', '')),
                'dest_ip': data.get('id.resp_h', data.get('id_resp_h', '')),
                'method': data.get('method', ''),
                'host': data.get('host', ''),
                'uri': data.get('uri', ''),
                'user_agent': data.get('user_agent', ''),
                'status_code': int(data.get('status_code', 0) or 0),
                'request_body_len': int(data.get('request_body_len', 0) or 0),
                'response_body_len': int(data.get('response_body_len', 0) or 0),
                'referrer': data.get('referrer', ''),
                'orig_mime_types': data.get('orig_mime_types', []),
                'resp_mime_types': data.get('resp_mime_types', []),
            })
            
        elif log_type == 'ssl':
            normalized.update({
                'src_ip': data.get('id.orig_h', data.get('id_orig_h', '')),
                'dest_ip': data.get('id.resp_h', data.get('id_resp_h', '')),
                'server_name': data.get('server_name', ''),
                'subject': data.get('subject', ''),
                'issuer': data.get('issuer', ''),
                'validation_status': data.get('validation_status', ''),
                'version': data.get('version', ''),
                'cipher': data.get('cipher', ''),
                'established': data.get('established', False),
                'ja3': data.get('ja3', ''),  # JA3 fingerprint if available
                'ja3s': data.get('ja3s', ''),
            })
            
        elif log_type == 'notice':
            normalized.update({
                'src_ip': data.get('id.orig_h', data.get('src', '')),
                'dest_ip': data.get('id.resp_h', data.get('dst', '')),
                'note': data.get('note', ''),
                'msg': data.get('msg', ''),
                'sub': data.get('sub', ''),
                'actions': data.get('actions', []),
                'suppress_for': data.get('suppress_for', 0),
            })
            
        elif log_type == 'files':
            normalized.update({
                'src_ip': data.get('tx_hosts', [''])[0] if data.get('tx_hosts') else '',
                'dest_ip': data.get('rx_hosts', [''])[0] if data.get('rx_hosts') else '',
                'fuid': data.get('fuid', ''),
                'source': data.get('source', ''),
                'mime_type': data.get('mime_type', ''),
                'filename': data.get('filename', ''),
                'md5': data.get('md5', ''),
                'sha1': data.get('sha1', ''),
                'sha256': data.get('sha256', ''),
                'total_bytes': int(data.get('total_bytes', 0) or 0),
                'seen_bytes': int(data.get('seen_bytes', 0) or 0),
            })
            
        elif log_type == 'weird':
            normalized.update({
                'src_ip': data.get('id.orig_h', data.get('id_orig_h', '')),
                'dest_ip': data.get('id.resp_h', data.get('id_resp_h', '')),
                'name': data.get('name', ''),
                'addl': data.get('addl', ''),
                'notice': data.get('notice', False),
            })
        
        return normalized
    
    @staticmethod
    def _parse_tsv(line: str, log_type: str) -> Optional[Dict[str, Any]]:
        """Fallback TSV parser for non-JSON Zeek output."""
        try:
            fields = line.split('\t')
            if len(fields) < 10:
                return None
            
            # Only conn.log TSV parsing for backwards compatibility
            if log_type == 'conn':
                return {
                    '_log_type': 'conn',
                    'timestamp': datetime.fromtimestamp(float(fields[0])).isoformat(),
                    'uid': fields[1],
                    'src_ip': fields[2],
                    'src_port': int(fields[3]) if fields[3] != '-' else 0,
                    'dest_ip': fields[4],
                    'dest_port': int(fields[5]) if fields[5] != '-' else 0,
                    'protocol': fields[6],
                    'service': fields[7] if fields[7] != '-' else None,
                    'duration': float(fields[8]) if fields[8] != '-' else 0.0,
                    'orig_bytes': int(fields[9]) if fields[9] != '-' else 0,
                    'resp_bytes': int(fields[10]) if len(fields) > 10 and fields[10] != '-' else 0,
                    'conn_state': fields[11] if len(fields) > 11 and fields[11] != '-' else None,
                    'orig_pkts': int(fields[16]) if len(fields) > 16 and fields[16] != '-' else 0,
                    'resp_pkts': int(fields[18]) if len(fields) > 18 and fields[18] != '-' else 0,
                    'history': fields[15] if len(fields) > 15 and fields[15] != '-' else '',
                }
            return None
        except (ValueError, IndexError) as e:
            logger.debug(f"TSV parse error for {log_type}: {e}")
            return None


class NetworkMonitor:
    """
    Multi-log Zeek network monitor for KitNET.
    
    Consumes and correlates data from multiple Zeek log files to provide
    enriched context for anomaly detection. This enables detection of:
    
    - DNS tunneling (via dns.log analysis)
    - Data exfiltration (via http.log + conn.log correlation)
    - Certificate anomalies (via ssl.log)
    - Protocol violations (via weird.log)
    - Zeek-detected threats (via notice.log)
    """
    
    # Log files to monitor, in order of importance
    ZEEK_LOGS = [
        ('conn', 'conn.log'),      # Primary: connection metadata
        ('dns', 'dns.log'),        # DNS queries - C2, tunneling
        ('http', 'http.log'),      # HTTP transactions - exfil, malware
        ('ssl', 'ssl.log'),        # TLS/SSL - cert anomalies
        ('notice', 'notice.log'),  # Zeek security notices
        ('files', 'files.log'),    # File transfers - malware
        ('weird', 'weird.log'),    # Protocol anomalies
    ]
    
    # Possible Zeek log directories
    ZEEK_LOG_DIRS = [
        Path("/opt/zeek/logs/current"),
        Path("/opt/zeek/logs"),
        Path("/app/data/zeek/current"),
        Path("/app/data/zeek"),
        Path("/var/log/zeek/current"),
        Path("/var/log/zeek"),
    ]
    
    def __init__(self):
        self.packet_count = 0
        self.is_monitoring = False
        self.log_positions: Dict[str, int] = {}
        self.connection_cache: Dict[str, ConnectionContext] = {}
        self.cache_max_size = 10000
        self.parser = ZeekLogParser()
        self.zeek_log_dir: Optional[Path] = None
        
        # Statistics
        self.stats = defaultdict(int)
    
    def _find_zeek_log_dir(self) -> Optional[Path]:
        """Find the active Zeek log directory."""
        for path in self.ZEEK_LOG_DIRS:
            if path.exists() and path.is_dir():
                # Check if there are actual log files
                if any(path.glob("*.log")):
                    return path
        return None
    
    async def start_monitoring(self, packet_queue: asyncio.Queue):
        """Start monitoring all Zeek log files."""
        logger.info("📡 Starting multi-log Zeek network monitoring...")
        self.is_monitoring = True
        
        # Find Zeek log directory
        self.zeek_log_dir = self._find_zeek_log_dir()
        
        if not self.zeek_log_dir:
            # Create default directory for testing
            self.zeek_log_dir = self.ZEEK_LOG_DIRS[0]
            self.zeek_log_dir.mkdir(parents=True, exist_ok=True)
            logger.warning(f"No Zeek logs found, using: {self.zeek_log_dir}")
        else:
            logger.info(f"📂 Found Zeek logs at: {self.zeek_log_dir}")
        
        # List available logs
        available_logs = list(self.zeek_log_dir.glob("*.log"))
        logger.info(f"📋 Available Zeek logs: {[f.name for f in available_logs]}")
        
        # Start tailing all configured logs
        await self._tail_all_logs(packet_queue)
    
    async def _tail_all_logs(self, packet_queue: asyncio.Queue):
        """Tail all Zeek log files concurrently."""
        while self.is_monitoring:
            try:
                # Process each log type
                for log_type, log_name in self.ZEEK_LOGS:
                    log_path = self.zeek_log_dir / log_name
                    
                    if log_path.exists():
                        await self._process_log_file(log_path, log_type, packet_queue)
                
                # Clean old cache entries
                self._cleanup_cache()
                
                # Log statistics periodically
                if self.packet_count % 500 == 0 and self.packet_count > 0:
                    self._log_stats()
                
                await asyncio.sleep(0.3)  # 300ms polling interval
                
            except Exception as e:
                logger.error(f"Error in log monitoring: {e}")
                await asyncio.sleep(2)
    
    async def _process_log_file(self, log_path: Path, log_type: str, packet_queue: asyncio.Queue):
        """Process new entries from a single log file."""
        position_key = str(log_path)
        last_position = self.log_positions.get(position_key, 0)
        
        try:
            with open(log_path, 'r') as f:
                f.seek(last_position)
                
                for line in f:
                    parsed = self.parser.parse_line(line, log_type)
                    
                    if parsed:
                        self.stats[log_type] += 1
                        
                        # Enrich and correlate data
                        enriched = self._enrich_data(parsed, log_type)
                        
                        # Primary data (conn.log) goes directly to queue
                        if log_type == 'conn':
                            await packet_queue.put(enriched)
                            self.packet_count += 1
                        
                        # Notice.log entries are high-priority alerts
                        elif log_type == 'notice':
                            enriched['_priority'] = 'high'
                            enriched['_source'] = 'zeek_notice'
                            await packet_queue.put(enriched)
                            self.packet_count += 1
                        
                        # Other logs enrich connection context
                        else:
                            self._update_connection_context(parsed, log_type)
                
                self.log_positions[position_key] = f.tell()
                
        except Exception as e:
            logger.debug(f"Error reading {log_path.name}: {e}")
    
    def _enrich_data(self, data: Dict[str, Any], log_type: str) -> Dict[str, Any]:
        """Enrich parsed data with additional context and computed features."""
        enriched = data.copy()
        
        # Add computed features for ML
        if log_type == 'conn':
            # Bytes ratio (useful for detecting tunneling/exfil)
            orig = data.get('orig_bytes', 0)
            resp = data.get('resp_bytes', 0)
            total = orig + resp
            enriched['bytes_ratio'] = orig / resp if resp > 0 else float('inf') if orig > 0 else 0
            enriched['total_bytes'] = total
            
            # Packet ratio
            orig_pkts = data.get('orig_pkts', 0)
            resp_pkts = data.get('resp_pkts', 0)
            enriched['pkt_ratio'] = orig_pkts / resp_pkts if resp_pkts > 0 else float('inf') if orig_pkts > 0 else 0
            
            # Connection duration category
            duration = data.get('duration', 0)
            if duration < 1:
                enriched['duration_category'] = 'short'
            elif duration < 60:
                enriched['duration_category'] = 'medium'
            elif duration < 3600:
                enriched['duration_category'] = 'long'
            else:
                enriched['duration_category'] = 'very_long'
            
            # Look up enrichment from other logs
            uid = data.get('uid')
            if uid and uid in self.connection_cache:
                ctx = self.connection_cache[uid]
                enriched['dns_queries'] = ctx.dns_queries
                enriched['http_requests'] = ctx.http_requests
                enriched['ssl_info'] = ctx.ssl_info
                enriched['notices'] = ctx.notices
                enriched['has_dns'] = len(ctx.dns_queries) > 0
                enriched['has_http'] = len(ctx.http_requests) > 0
                enriched['has_ssl'] = bool(ctx.ssl_info)
                enriched['has_notices'] = len(ctx.notices) > 0
        
        elif log_type == 'dns':
            # DNS tunneling indicators
            query = data.get('query', '')
            enriched['query_entropy'] = self._calculate_entropy(query)
            enriched['is_long_query'] = len(query) > 50
            enriched['subdomain_depth'] = query.count('.')
            
            # Detect potential DGA
            if query:
                domain_parts = query.split('.')
                if len(domain_parts) >= 2:
                    sld = domain_parts[-2]  # Second-level domain
                    enriched['sld_length'] = len(sld)
                    enriched['sld_entropy'] = self._calculate_entropy(sld)
        
        elif log_type == 'http':
            # Data exfiltration indicators
            enriched['uri_length'] = len(data.get('uri', ''))
            enriched['has_user_agent'] = bool(data.get('user_agent'))
            enriched['request_size'] = data.get('request_body_len', 0)
            enriched['response_size'] = data.get('response_body_len', 0)
            
            # Suspicious patterns
            uri = data.get('uri', '').lower()
            enriched['uri_suspicious'] = any(s in uri for s in [
                'base64', 'exec', 'cmd', 'powershell', 'eval', 
                'shell', '.php?', '.asp?', 'passwd', 'shadow'
            ])
        
        elif log_type == 'ssl':
            # Certificate anomaly indicators
            enriched['self_signed'] = 'self signed' in data.get('validation_status', '').lower()
            enriched['expired'] = 'expired' in data.get('validation_status', '').lower()
            enriched['untrusted'] = 'unable to get' in data.get('validation_status', '').lower()
            enriched['cert_valid'] = data.get('validation_status', '') == 'ok'
        
        return enriched
    
    def _update_connection_context(self, data: Dict[str, Any], log_type: str):
        """Update connection cache with data from auxiliary logs."""
        uid = data.get('uid')
        if not uid:
            return
        
        if uid not in self.connection_cache:
            self.connection_cache[uid] = ConnectionContext(uid=uid)
        
        ctx = self.connection_cache[uid]
        
        if log_type == 'dns':
            ctx.dns_queries.append(data)
        elif log_type == 'http':
            ctx.http_requests.append(data)
        elif log_type == 'ssl':
            ctx.ssl_info = data
        elif log_type == 'notice':
            ctx.notices.append(data)
        elif log_type == 'files':
            ctx.files.append(data)
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string (useful for DGA detection)."""
        if not text:
            return 0.0
        
        from collections import Counter
        import math
        
        freq = Counter(text.lower())
        length = len(text)
        entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
        return round(entropy, 4)
    
    def _cleanup_cache(self):
        """Remove old entries from connection cache."""
        if len(self.connection_cache) > self.cache_max_size:
            # Remove oldest 20% of entries
            remove_count = int(self.cache_max_size * 0.2)
            keys_to_remove = list(self.connection_cache.keys())[:remove_count]
            for key in keys_to_remove:
                del self.connection_cache[key]
    
    def _log_stats(self):
        """Log processing statistics."""
        stats_str = ", ".join(f"{k}:{v}" for k, v in sorted(self.stats.items()))
        logger.info(f"📊 Zeek stats - Total: {self.packet_count}, By type: {stats_str}")
    
    def stop_monitoring(self):
        """Stop network monitoring."""
        logger.info("🛑 Stopping Zeek network monitoring...")
        self.is_monitoring = False
    
    def get_stats(self) -> Dict[str, Any]:
        """Return current monitoring statistics."""
        return {
            'total_processed': self.packet_count,
            'by_log_type': dict(self.stats),
            'cache_size': len(self.connection_cache),
            'log_directory': str(self.zeek_log_dir),
        }