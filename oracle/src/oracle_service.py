"""
Oracle Backend FastAPI Service
Main application factory and API routes - PostgreSQL & Async Optimized
"""

import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, func, text # Added text import

from config import settings
from database import get_db, Alert
from models import (
    HealthResponse, AlertRequest, AlertResponse, 
    ThreatAnalysisResponse, SystemStatus, AnalyticsResponse
)
from analytics import ThreatAnalyzer, AlertCorrelator

logger = logging.getLogger(__name__)

def create_app() -> FastAPI:
    """Create and configure FastAPI application"""
    
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.VERSION,
        description="Cloud-native security analytics and threat correlation platform",
    )
    
    # 1. CORS: Allow everything for Dev portability
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Initialize analytics components
    threat_analyzer = ThreatAnalyzer()
    alert_correlator = AlertCorrelator()
    
    @app.get("/health", response_model=HealthResponse)
    async def health_check():
        """Service health check endpoint"""
        try:
            async with get_db() as db:
                await db.execute(text("SELECT 1"))
            db_status = "healthy"
        except Exception as e:
            db_status = f"error: {str(e)}"
            
        return HealthResponse(
            status="healthy" if db_status == "healthy" else "degraded",
            timestamp=datetime.now(timezone.utc),
            version=settings.VERSION,
            services={
                "database": {"status": db_status},
                "analytics": {"status": "healthy", "models_loaded": True}
            },
            system=SystemStatus(
                deployment_env=settings.DEPLOYMENT_ENVIRONMENT,
                alerts_processed=await get_alerts_count(),
                threat_score_threshold=settings.THREAT_SCORE_THRESHOLD
            )
        )
    
    @app.post("/api/alerts", response_model=AlertResponse)
    async def receive_alert(
        alert_request: AlertRequest, 
        background_tasks: BackgroundTasks,
    ):
        """Receive and process security alerts from Sentry services"""
        try:
            logger.info(f"Incoming Alert from {alert_request.source}")
            
            async with get_db() as db:
                alert = Alert(
                    source=alert_request.source,
                    alert_type=alert_request.alert_type,
                    severity=alert_request.severity,
                    title=alert_request.title,
                    description=alert_request.description,
                    raw_data=alert_request.raw_data,
                    timestamp=alert_request.timestamp or datetime.now(timezone.utc)
                )
                db.add(alert)
                await db.flush() 
                await db.refresh(alert)
                alert_id = alert.id
            
            background_tasks.add_task(
                process_alert_background, 
                alert_id, 
                threat_analyzer, 
                alert_correlator
            )
            
            return AlertResponse(
                alert_id=alert_id,
                status="received",
                threat_score=None,
                correlations=[],
                processing_time_ms=0
            )
            
        except Exception as e:
            logger.error(f"Failed to process alert: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/analytics", response_model=AnalyticsResponse)
    async def get_analytics(time_range: str = "24h"):
        """Get real security analytics for the Dashboard"""
        try:
            async with get_db() as db:
                analytics_data = await calculate_analytics(db, time_range)
            
            # 2. ENSURE KEYS: React crashes if these are None/Missing
            return AnalyticsResponse(
                total_alerts=analytics_data.get("total_alerts", 0),
                risk_score=analytics_data.get("risk_score", 0.0),
                alerts=analytics_data.get("alerts") or [], # Never send None/null
                generated_at=datetime.now(timezone.utc),
                time_range=time_range,
                alerts_by_severity=analytics_data.get("severity_stats") or {},
                alerts_by_type={},
                top_threats=[],
                trend_data=[]
            )
        except Exception as e:
            logger.error(f"Analytics Error: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    return app

async def calculate_analytics(db, time_range: str) -> Dict[str, Any]:
    """REAL PostgreSQL Logic: Fetch and aggregate threat data"""
    # Recent alerts
    stmt = select(Alert).order_by(Alert.timestamp.desc()).limit(50)
    result = await db.execute(stmt)
    alerts_list = result.scalars().all()
    
    # Total Count
    count_stmt = select(func.count()).select_from(Alert)
    count_result = await db.execute(count_stmt)
    total = count_result.scalar() or 0
    
    # Global Risk Score
    risk_stmt = select(func.avg(Alert.threat_score)).select_from(Alert)
    risk_result = await db.execute(risk_stmt)
    avg_risk = risk_result.scalar() or 0.0

    # Severity Stats
    sev_stmt = select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    sev_result = await db.execute(sev_stmt)
    severity_map = {row[0]: row[1] for row in sev_result.all()}
    
    return {
        "total_alerts": total,
        "risk_score": float(avg_risk),
        "alerts": alerts_list,
        "severity_stats": severity_map
    }

async def process_alert_background(alert_id: int, threat_analyzer: ThreatAnalyzer, correlator: AlertCorrelator):
    """Background task to process alerts with AI logic"""
    try:
        async with get_db() as db:
            result = await db.execute(select(Alert).where(Alert.id == alert_id))
            alert = result.scalar_one_or_none()
            if not alert: return
            
            # Skip AI if keys missing
            if settings.AZURE_OPENAI_API_KEY and settings.AI_ENABLED:
                threat_score = await threat_analyzer.calculate_threat_score(alert)
            else:
                threat_score = 0.4
                
            correlations = await correlator.find_correlations(alert)
            alert.threat_score = threat_score
            alert.correlations = correlations
            alert.processed_at = datetime.now(timezone.utc)
            await db.flush()
    except Exception as e:
        logger.error(f"Background processing failed for alert {alert_id}: {e}")

async def get_alerts_count() -> int:
    try:
        async with get_db() as db:
            result = await db.execute(select(func.count()).select_from(Alert))
            return result.scalar() or 0
    except Exception: return 0