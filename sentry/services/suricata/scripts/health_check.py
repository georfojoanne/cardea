#!/usr/bin/env python3
"""
Health check script for Suricata service.
Provides detailed health metrics beyond just process status.
"""

import subprocess
import sys
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, Optional


def check_process_running() -> bool:
    """Check if Suricata process is running"""
    try:
        result = subprocess.run(['pgrep', '-f', 'suricata'], capture_output=True)
        return result.returncode == 0
    except Exception:
        return False


def get_stats_from_log() -> Optional[Dict[str, Any]]:
    """Parse the most recent stats from stats.log"""
    stats_log = Path("/var/log/suricata/stats.log")
    
    if not stats_log.exists():
        return None
    
    try:
        # Read last few lines for recent stats
        with open(stats_log, 'r') as f:
            lines = f.readlines()
        
        if not lines:
            return None
        
        # Parse the most recent stats block
        stats = {}
        for line in reversed(lines[-50:]):
            line = line.strip()
            if not line or line.startswith('-'):
                continue
            if '|' in line:
                parts = line.split('|')
                if len(parts) >= 3:
                    key = parts[1].strip()
                    value = parts[2].strip()
                    try:
                        stats[key] = int(value)
                    except ValueError:
                        try:
                            stats[key] = float(value)
                        except ValueError:
                            stats[key] = value
        
        return stats if stats else None
    except Exception:
        return None


def get_eve_stats() -> Dict[str, Any]:
    """Get stats from EVE JSON log"""
    eve_log = Path("/var/log/suricata/eve.json")
    
    stats = {
        "alerts_today": 0,
        "events_total": 0,
        "last_event_time": None,
        "event_types": {}
    }
    
    if not eve_log.exists():
        return stats
    
    try:
        today = datetime.now().date()
        
        # Read last 1000 lines for recent events
        with open(eve_log, 'r') as f:
            # Seek to approximate last 100KB
            try:
                f.seek(-100000, 2)
                f.readline()  # Skip partial line
            except:
                f.seek(0)
            
            for line in f:
                try:
                    event = json.loads(line.strip())
                    event_type = event.get("event_type", "unknown")
                    
                    stats["events_total"] += 1
                    stats["event_types"][event_type] = stats["event_types"].get(event_type, 0) + 1
                    
                    timestamp = event.get("timestamp", "")
                    if timestamp:
                        stats["last_event_time"] = timestamp
                    
                    if event_type == "alert":
                        try:
                            event_date = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).date()
                            if event_date == today:
                                stats["alerts_today"] += 1
                        except:
                            pass
                            
                except json.JSONDecodeError:
                    continue
        
        return stats
    except Exception:
        return stats


def check_log_freshness() -> Dict[str, Any]:
    """Check if logs are being written recently"""
    result = {
        "eve_fresh": False,
        "fast_fresh": False,
        "stats_fresh": False
    }
    
    now = datetime.now()
    threshold = timedelta(minutes=5)
    
    for log_name, log_file in [
        ("eve", "/var/log/suricata/eve.json"),
        ("fast", "/var/log/suricata/fast.log"),
        ("stats", "/var/log/suricata/stats.log")
    ]:
        path = Path(log_file)
        if path.exists():
            mtime = datetime.fromtimestamp(path.stat().st_mtime)
            if now - mtime < threshold:
                result[f"{log_name}_fresh"] = True
    
    return result


def main():
    """Main health check routine"""
    health = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "checks": {}
    }
    
    # Check 1: Process running
    process_ok = check_process_running()
    health["checks"]["process"] = {
        "status": "pass" if process_ok else "fail",
        "message": "Suricata process running" if process_ok else "Suricata process not found"
    }
    
    if not process_ok:
        health["status"] = "unhealthy"
        print(json.dumps(health, indent=2))
        sys.exit(1)
    
    # Check 2: Log freshness
    freshness = check_log_freshness()
    logs_fresh = any(freshness.values())
    health["checks"]["logs"] = {
        "status": "pass" if logs_fresh else "warn",
        "details": freshness,
        "message": "Logs being written" if logs_fresh else "No recent log activity"
    }
    
    # Check 3: EVE stats
    eve_stats = get_eve_stats()
    health["checks"]["eve_activity"] = {
        "status": "pass" if eve_stats["events_total"] > 0 else "warn",
        "alerts_today": eve_stats["alerts_today"],
        "last_event": eve_stats["last_event_time"],
        "event_types": eve_stats["event_types"]
    }
    
    # Check 4: Suricata internal stats
    internal_stats = get_stats_from_log()
    if internal_stats:
        health["checks"]["internal_stats"] = {
            "status": "pass",
            "capture.kernel_packets": internal_stats.get("capture.kernel_packets", 0),
            "decoder.pkts": internal_stats.get("decoder.pkts", 0),
            "detect.alert": internal_stats.get("detect.alert", 0),
            "flow.tcp": internal_stats.get("flow.tcp", 0),
            "flow.udp": internal_stats.get("flow.udp", 0)
        }
    else:
        health["checks"]["internal_stats"] = {
            "status": "warn",
            "message": "Stats log not available"
        }
    
    # Overall status
    if health["checks"]["process"]["status"] == "fail":
        health["status"] = "unhealthy"
    elif any(c.get("status") == "warn" for c in health["checks"].values()):
        health["status"] = "degraded"
    
    print(json.dumps(health, indent=2))
    
    if health["status"] == "unhealthy":
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()