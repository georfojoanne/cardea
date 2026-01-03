#!/usr/bin/env python3
"""
Cardea Bridge Service - Service Orchestration and API Gateway
Central coordination point for all Sentry services and Oracle integration
"""

import asyncio
import json
import logging
import sys
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from contextlib import asynccontextmanager

import aiofiles
from fastapi import FastAPI, HTTPException, BackgroundTasks, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
from pydantic import BaseModel, Field

# Add shared utilities to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "shared"))
from utils.platform_detector import PlatformDetector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Data Models
@dataclass
class Alert:
    """Alert data structure"""
    id: str
    timestamp: datetime
    severity: str
    source: str
    event_type: str
    description: str
    raw_data: Dict[str, Any]
    confidence: float = 0.0
    status: str = "new"

@dataclass
class EvidenceSnapshot:
    """Evidence collection for Oracle integration"""
    timestamp: datetime
    alerts: List[Alert]
    network_summary: Dict[str, Any]
    system_context: Dict[str, Any]
    threat_indicators: List[Dict[str, Any]]

class HealthResponse(BaseModel):
    """Health check response model"""
    status: str
    timestamp: str
    services: Dict[str, Dict[str, Any]]
    platform: Dict[str, str]

class AlertRequest(BaseModel):
    """Alert submission request"""
    source: str = Field(..., description="Alert source service")
    severity: str = Field(..., description="Alert severity level")
    event_type: str = Field(..., description="Type of security event")
    description: str = Field(..., description="Alert description")
    raw_data: Dict[str, Any] = Field(..., description="Raw alert data")
    confidence: float = Field(0.0, ge=0.0, le=1.0, description="Confidence score")

class BridgeService:
    """Main Bridge service class"""
    
    def __init__(self):
        self.platform_detector = PlatformDetector()
        self.alerts: List[Alert] = []
        self.services_status: Dict[str, Dict[str, Any]] = {}
        self.data_paths = {
            "zeek": Path("/opt/zeek/logs"),
            "suricata": Path("/var/log/suricata"),
            "kitnet": Path("/opt/kitnet/data"),
            "bridge": Path("/opt/bridge/data")
        }
        self._setup_data_paths()
        
    def _setup_data_paths(self):
        """Create data directories if they don't exist"""
        for service, path in self.data_paths.items():
            try:
                path.mkdir(parents=True, exist_ok=True)
                logger.info(f"Data path ready: {service} -> {path}")
            except Exception as e:
                logger.warning(f"Could not create {service} data path {path}: {e}")
                # Use fallback paths
                fallback = Path(f"/tmp/cardea/{service}")
                fallback.mkdir(parents=True, exist_ok=True)
                self.data_paths[service] = fallback
                logger.info(f"Using fallback path: {service} -> {fallback}")

    async def check_service_health(self, service: str) -> Dict[str, Any]:
        """Check individual service health"""
        health_info = {
            "status": "unknown",
            "last_check": datetime.now().isoformat(),
            "details": {}
        }
        
        try:
            if service == "zeek":
                # Check for recent Zeek logs
                zeek_log = self.data_paths["zeek"] / "conn.log"
                if zeek_log.exists():
                    stat = zeek_log.stat()
                    last_modified = datetime.fromtimestamp(stat.st_mtime)
                    age_minutes = (datetime.now() - last_modified).total_seconds() / 60
                    
                    health_info.update({
                        "status": "healthy" if age_minutes < 30 else "stale",
                        "details": {
                            "log_file": str(zeek_log),
                            "last_modified": last_modified.isoformat(),
                            "age_minutes": round(age_minutes, 2),
                            "file_size_bytes": stat.st_size
                        }
                    })
                else:
                    health_info.update({
                        "status": "warning",
                        "details": {"message": "No conn.log found", "expected_path": str(zeek_log)}
                    })
                    
            elif service == "suricata":
                # Check for recent Suricata alerts
                suricata_log = self.data_paths["suricata"] / "eve.json"
                if suricata_log.exists():
                    stat = suricata_log.stat()
                    last_modified = datetime.fromtimestamp(stat.st_mtime)
                    age_minutes = (datetime.now() - last_modified).total_seconds() / 60
                    
                    health_info.update({
                        "status": "healthy" if age_minutes < 60 else "stale",
                        "details": {
                            "log_file": str(suricata_log),
                            "last_modified": last_modified.isoformat(),
                            "age_minutes": round(age_minutes, 2),
                            "file_size_bytes": stat.st_size
                        }
                    })
                else:
                    health_info.update({
                        "status": "warning", 
                        "details": {"message": "No eve.json found", "expected_path": str(suricata_log)}
                    })
                    
            elif service == "kitnet":
                # Check KitNET process status
                health_info.update({
                    "status": "healthy",  # Assume healthy for now
                    "details": {"message": "AI monitoring active", "model_loaded": True}
                })
                
            elif service == "bridge":
                # Self-check
                health_info.update({
                    "status": "healthy",
                    "details": {
                        "alerts_processed": len(self.alerts),
                        "platform": self.platform_detector.get_os_info()["name"],
                        "data_paths_ready": all(p.exists() for p in self.data_paths.values())
                    }
                })
                
        except Exception as e:
            health_info.update({
                "status": "error",
                "details": {"error": str(e)}
            })
            logger.error(f"Health check failed for {service}: {e}")
            
        self.services_status[service] = health_info
        return health_info

    async def collect_evidence_snapshot(self) -> EvidenceSnapshot:
        """Collect comprehensive evidence snapshot for Oracle integration"""
        try:
            # Get recent alerts
            recent_alerts = [
                alert for alert in self.alerts 
                if alert.timestamp > datetime.now() - timedelta(hours=24)
            ]
            
            # Collect network summary from Zeek logs
            network_summary = await self._analyze_zeek_logs()
            
            # Get system context from platform detector
            system_context = {
                "os_info": self.platform_detector.get_os_info(),
                "hardware": self.platform_detector.get_hardware_info(),
                "network_interfaces": self.platform_detector.get_network_interfaces(),
                "timestamp": datetime.now().isoformat()
            }
            
            # Extract threat indicators
            threat_indicators = await self._extract_threat_indicators(recent_alerts)
            
            snapshot = EvidenceSnapshot(
                timestamp=datetime.now(),
                alerts=recent_alerts,
                network_summary=network_summary,
                system_context=system_context,
                threat_indicators=threat_indicators
            )
            
            # Save snapshot for Oracle processing
            await self._save_evidence_snapshot(snapshot)
            
            logger.info(f"Evidence snapshot collected: {len(recent_alerts)} alerts, {len(threat_indicators)} indicators")
            return snapshot
            
        except Exception as e:
            logger.error(f"Failed to collect evidence snapshot: {e}")
            raise

    async def _analyze_zeek_logs(self) -> Dict[str, Any]:
        """Analyze recent Zeek logs for network summary"""
        try:
            zeek_log = self.data_paths["zeek"] / "conn.log"
            if not zeek_log.exists():
                return {"status": "no_logs", "message": "Zeek logs not available"}
                
            # Read last 1000 lines for recent activity analysis
            async with aiofiles.open(zeek_log, 'r') as f:
                lines = await f.readlines()
                recent_lines = lines[-1000:] if len(lines) > 1000 else lines
                
            # Basic analysis of connections
            connections = 0
            protocols = {}
            unique_hosts = set()
            
            for line in recent_lines:
                if line.startswith('#') or not line.strip():
                    continue
                    
                try:
                    fields = line.split('\t')
                    if len(fields) >= 7:
                        connections += 1
                        protocol = fields[6] if len(fields) > 6 else 'unknown'
                        protocols[protocol] = protocols.get(protocol, 0) + 1
                        
                        # Extract hosts
                        if len(fields) >= 5:
                            unique_hosts.add(fields[2])  # orig_h
                            unique_hosts.add(fields[4])  # resp_h
                            
                except Exception:
                    continue
                    
            return {
                "total_connections": connections,
                "unique_hosts": len(unique_hosts),
                "protocols": protocols,
                "analysis_timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Zeek log analysis failed: {e}")
            return {"status": "error", "message": str(e)}

    async def _extract_threat_indicators(self, alerts: List[Alert]) -> List[Dict[str, Any]]:
        """Extract threat indicators from alerts for Oracle analysis"""
        indicators = []
        
        for alert in alerts:
            try:
                indicator = {
                    "type": alert.event_type,
                    "severity": alert.severity,
                    "source": alert.source,
                    "timestamp": alert.timestamp.isoformat(),
                    "confidence": alert.confidence,
                    "description": alert.description
                }
                
                # Extract specific indicators from raw data
                if "src_ip" in alert.raw_data:
                    indicator["src_ip"] = alert.raw_data["src_ip"]
                if "dest_ip" in alert.raw_data:
                    indicator["dest_ip"] = alert.raw_data["dest_ip"]
                if "signature" in alert.raw_data:
                    indicator["signature"] = alert.raw_data["signature"]
                    
                indicators.append(indicator)
                
            except Exception as e:
                logger.error(f"Failed to extract indicator from alert {alert.id}: {e}")
                
        return indicators

    async def _save_evidence_snapshot(self, snapshot: EvidenceSnapshot):
        """Save evidence snapshot to file for Oracle processing"""
        try:
            evidence_file = self.data_paths["bridge"] / f"evidence_{snapshot.timestamp.strftime('%Y%m%d_%H%M%S')}.json"
            
            # Convert snapshot to serializable format
            snapshot_data = {
                "timestamp": snapshot.timestamp.isoformat(),
                "alerts": [asdict(alert) for alert in snapshot.alerts],
                "network_summary": snapshot.network_summary,
                "system_context": snapshot.system_context,
                "threat_indicators": snapshot.threat_indicators
            }
            
            async with aiofiles.open(evidence_file, 'w') as f:
                await f.write(json.dumps(snapshot_data, indent=2, default=str))
                
            logger.info(f"Evidence snapshot saved: {evidence_file}")
            
        except Exception as e:
            logger.error(f"Failed to save evidence snapshot: {e}")

    def add_alert(self, alert_request: AlertRequest) -> Alert:
        """Add new alert to the system"""
        alert = Alert(
            id=f"alert_{len(self.alerts) + 1}_{int(datetime.now().timestamp())}",
            timestamp=datetime.now(),
            severity=alert_request.severity,
            source=alert_request.source,
            event_type=alert_request.event_type,
            description=alert_request.description,
            raw_data=alert_request.raw_data,
            confidence=alert_request.confidence
        )
        
        self.alerts.append(alert)
        logger.info(f"New alert added: {alert.id} from {alert.source}")
        
        return alert

# Global bridge service instance
bridge_service = BridgeService()

# FastAPI lifecycle management
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle"""
    logger.info("🌉 Starting Cardea Bridge Service...")
    
    # Startup tasks
    await bridge_service.check_service_health("bridge")
    logger.info("Bridge service initialized successfully")
    
    yield
    
    # Shutdown tasks
    logger.info("🛑 Shutting down Cardea Bridge Service...")

# FastAPI application
app = FastAPI(
    title="Cardea Bridge Service",
    description="Central orchestration and API gateway for Cardea Sentry services",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Endpoints
@app.get("/", response_model=Dict[str, str])
async def root():
    """Root endpoint"""
    return {
        "service": "Cardea Bridge",
        "version": "1.0.0",
        "status": "operational",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Comprehensive health check for all services"""
    logger.info("Performing health check...")
    
    services = {}
    for service_name in ["zeek", "suricata", "kitnet", "bridge"]:
        services[service_name] = await bridge_service.check_service_health(service_name)
    
    platform_info = {
        "os": bridge_service.platform_detector.get_os_info()["name"],
        "interfaces": len(bridge_service.platform_detector.get_network_interfaces()),
        "docker": "available" if bridge_service.platform_detector.is_docker_available() else "unavailable"
    }
    
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now().isoformat(),
        services=services,
        platform=platform_info
    )

@app.post("/alerts", status_code=status.HTTP_201_CREATED)
async def submit_alert(alert_request: AlertRequest, background_tasks: BackgroundTasks):
    """Submit new security alert"""
    try:
        alert = bridge_service.add_alert(alert_request)
        
        # Schedule evidence collection in background
        background_tasks.add_task(bridge_service.collect_evidence_snapshot)
        
        return {
            "status": "accepted",
            "alert_id": alert.id,
            "timestamp": alert.timestamp.isoformat(),
            "message": "Alert processed and evidence collection scheduled"
        }
        
    except Exception as e:
        logger.error(f"Failed to submit alert: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process alert: {str(e)}"
        )

@app.get("/alerts")
async def get_alerts(limit: int = 100, severity: Optional[str] = None):
    """Get recent alerts with optional filtering"""
    try:
        alerts = bridge_service.alerts[-limit:]
        
        if severity:
            alerts = [alert for alert in alerts if alert.severity.lower() == severity.lower()]
        
        return {
            "total": len(alerts),
            "alerts": [asdict(alert) for alert in alerts]
        }
        
    except Exception as e:
        logger.error(f"Failed to retrieve alerts: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve alerts: {str(e)}"
        )

@app.get("/evidence/snapshot")
async def get_evidence_snapshot():
    """Generate and return current evidence snapshot"""
    try:
        snapshot = await bridge_service.collect_evidence_snapshot()
        
        return {
            "timestamp": snapshot.timestamp.isoformat(),
            "alerts_count": len(snapshot.alerts),
            "threat_indicators_count": len(snapshot.threat_indicators),
            "network_summary": snapshot.network_summary,
            "system_context": snapshot.system_context
        }
        
    except Exception as e:
        logger.error(f"Failed to generate evidence snapshot: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate evidence snapshot: {str(e)}"
        )

@app.get("/services/{service_name}/status")
async def get_service_status(service_name: str):
    """Get status of specific service"""
    if service_name not in ["zeek", "suricata", "kitnet", "bridge"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Service '{service_name}' not found"
        )
    
    try:
        status_info = await bridge_service.check_service_health(service_name)
        return {
            "service": service_name,
            "status": status_info
        }
        
    except Exception as e:
        logger.error(f"Failed to check {service_name} status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to check service status: {str(e)}"
        )

@app.get("/platform/info")
async def get_platform_info():
    """Get detailed platform information"""
    try:
        return {
            "os_info": bridge_service.platform_detector.get_os_info(),
            "hardware_info": bridge_service.platform_detector.get_hardware_info(),
            "network_interfaces": bridge_service.platform_detector.get_network_interfaces(),
            "docker_available": bridge_service.platform_detector.is_docker_available(),
            "data_paths": {k: str(v) for k, v in bridge_service.data_paths.items()}
        }
        
    except Exception as e:
        logger.error(f"Failed to get platform info: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get platform information: {str(e)}"
        )

if __name__ == "__main__":
    # Configuration from environment
    host = os.getenv("BRIDGE_HOST", "0.0.0.0")
    port = int(os.getenv("BRIDGE_PORT", "8080"))
    debug = os.getenv("DEV_MODE", "false").lower() == "true"
    
    logger.info(f"🚀 Starting Cardea Bridge Service on {host}:{port}")
    logger.info(f"Debug mode: {debug}")
    
    uvicorn.run(
        "bridge_service:app",
        host=host,
        port=port,
        reload=debug,
        log_level="info" if not debug else "debug"
    )