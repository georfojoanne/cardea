#!/usr/bin/env python3
"""
API Server for Bridge Service
FastAPI server providing REST endpoints for Sentry coordination
"""

import logging
from datetime import datetime
from typing import Dict, Any, List
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

logger = logging.getLogger(__name__)

# Pydantic models for API requests/responses
class AlertRequest(BaseModel):
    source: str = Field(..., description="Alert source (suricata, kitnet)")
    timestamp: str = Field(..., description="Alert timestamp")
    anomaly_score: float = Field(None, description="KitNET anomaly score")
    network: Dict[str, Any] = Field(..., description="Network information")
    alert: Dict[str, Any] = Field(None, description="Suricata alert details")
    flow_id: str = Field(None, description="Flow identifier")

class AlertResponse(BaseModel):
    status: str
    message: str
    alert_id: str

class HealthResponse(BaseModel):
    status: str
    timestamp: str
    sentry_id: str
    services: Dict[str, bool]

class StatusResponse(BaseModel):
    sentry_id: str
    uptime: str
    alerts_processed: int
    last_alert: str
    services: Dict[str, Dict[str, Any]]

class APIServer:
    """FastAPI server for Bridge service"""
    
    def __init__(self, port: int, alert_processor, oracle_client, sentry_status):
        self.port = port
        self.alert_processor = alert_processor
        self.oracle_client = oracle_client
        self.sentry_status = sentry_status
        
        # Create FastAPI app
        self.app = FastAPI(
            title="Cardea Sentry Bridge API",
            description="Orchestration API for Cardea Sentry edge services",
            version="1.0.0"
        )
        
        # Configure CORS
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # Configure appropriately for production
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Setup routes
        self._setup_routes()
        
    def _setup_routes(self):
        """Setup API routes"""
        
        @self.app.get("/health", response_model=HealthResponse)
        async def health_check():
            """Health check endpoint"""
            services = await self.sentry_status.get_service_status()
            
            return HealthResponse(
                status="healthy",
                timestamp=datetime.now().isoformat(),
                sentry_id=self.sentry_status.sentry_id,
                services=services
            )
        
        @self.app.get("/status", response_model=StatusResponse)
        async def get_status():
            """Get detailed Sentry status"""
            status = await self.sentry_status.get_detailed_status()
            return StatusResponse(**status)
        
        @self.app.post("/api/v1/alerts/suricata", response_model=AlertResponse)
        async def receive_suricata_alert(
            alert: AlertRequest, 
            background_tasks: BackgroundTasks
        ):
            """Receive alert from Suricata service"""
            try:
                alert_id = await self.alert_processor.process_alert(alert.dict())
                
                # Process in background if high priority
                if alert.alert and alert.alert.get("severity", 3) <= 2:
                    background_tasks.add_task(
                        self.oracle_client.send_priority_alert, alert.dict()
                    )
                
                return AlertResponse(
                    status="received",
                    message="Suricata alert processed",
                    alert_id=alert_id
                )
                
            except Exception as e:
                logger.error(f"Error processing Suricata alert: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/api/v1/alerts/kitnet", response_model=AlertResponse)
        async def receive_kitnet_alert(
            alert: AlertRequest,
            background_tasks: BackgroundTasks
        ):
            """Receive alert from KitNET service"""
            try:
                alert_id = await self.alert_processor.process_alert(alert.dict())
                
                # Escalate to Oracle if score exceeds threshold
                if alert.anomaly_score >= self.alert_processor.threshold:
                    background_tasks.add_task(
                        self.oracle_client.escalate_anomaly, alert.dict()
                    )
                
                return AlertResponse(
                    status="received",
                    message=f"KitNET alert processed (score: {alert.anomaly_score:.4f})",
                    alert_id=alert_id
                )
                
            except Exception as e:
                logger.error(f"Error processing KitNET alert: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/v1/alerts", response_model=List[Dict[str, Any]])
        async def get_recent_alerts(limit: int = 50):
            """Get recent alerts"""
            try:
                alerts = await self.alert_processor.get_recent_alerts(limit)
                return alerts
            except Exception as e:
                logger.error(f"Error fetching alerts: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/api/v1/config/threshold")
        async def update_threshold(threshold: float):
            """Update anomaly detection threshold"""
            try:
                if not 0.0 <= threshold <= 1.0:
                    raise ValueError("Threshold must be between 0.0 and 1.0")
                    
                await self.alert_processor.update_threshold(threshold)
                
                return {"status": "updated", "threshold": threshold}
                
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                logger.error(f"Error updating threshold: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/v1/network/status")
        async def get_network_status():
            """Get network monitoring status"""
            try:
                status = await self.sentry_status.get_network_status()
                return status
            except Exception as e:
                logger.error(f"Error getting network status: {e}")
                raise HTTPException(status_code=500, detail=str(e))
    
    async def start(self):
        """Start the API server"""
        logger.info(f"Starting Bridge API server on port {self.port}")
        
        config = uvicorn.Config(
            app=self.app,
            host="0.0.0.0",
            port=self.port,
            log_level="info"
        )
        
        server = uvicorn.Server(config)
        await server.serve()