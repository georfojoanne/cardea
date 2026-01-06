"""
Oracle Backend FastAPI Service - Optimized for Azure AI & Credit Protection
Includes Redis-based De-duplication and Rate Limiting
"""

import os
import logging
import hashlib
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
import redis.asyncio as redis

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, func, text

from config import settings
from database import get_db, Alert
from models import (
    HealthResponse, AlertRequest, AlertResponse, 
    ThreatAnalysisResponse, SystemStatus, AnalyticsResponse
)
from analytics import ThreatAnalyzer, AlertCorrelator

logger = logging.getLogger(__name__)

# --- SAFEGUARD CONSTANTS ---
DEDUPE_WINDOW_SECONDS = 60      # Ignore identical alerts within 1 minute
GLOBAL_MINUTE_LIMIT = 50        # Hard cap: Max 50 AI-processed alerts per minute
AI_MAX_RESPONSE_TOKENS = 150    # Force brevity to save output tokens

# Initialize Redis client for safeguards
redis_client = redis.from_url(
    f"redis://{os.getenv('REDIS_HOST', 'localhost')}:6379/0", 
    decode_responses=True
)

async def check_abuse_safeguards(alert: AlertRequest) -> bool:
    """
    Returns True if the alert is a duplicate or exceeds rate limits.
    """
    # 1. De-duplication Hash
    unique_str = f"{alert.source}:{alert.alert_type}:{alert.description}"
    dedupe_key = f"dedupe:{hashlib.md5(unique_str.encode()).hexdigest()}"
    
    # 2. Global Rate Limit Key
    minute_key = f"throttle:{datetime.now().strftime('%M')}"

    # Atomic check in Redis
    async with redis_client.pipeline(transaction=True) as pipe:
        pipe.get(dedupe_key)
        pipe.incr(minute_key)
        pipe.expire(minute_key, 60)
        results = await pipe.execute()

    is_duplicate = results[0] is not None
    current_minute_count = results[1]

    if is_duplicate:
        logger.warning(f"🚫 Dropping duplicate alert from {alert.source}")
        return True

    if current_minute_count > GLOBAL_MINUTE_LIMIT:
        logger.error(f"⚠️ GLOBAL RATE LIMIT EXCEEDED: {current_minute_count}/{GLOBAL_MINUTE_LIMIT}")
        return True

    # Mark as seen for the dedupe window
    await redis_client.setex(dedupe_key, DEDUPE_WINDOW_SECONDS, "1")
    return False

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.VERSION,
        description="Cloud-native security analytics with AI Credit Protection",
        debug=settings.get_effective_debug(),
    )
    
    # Configure CORS based on environment
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    threat_analyzer = ThreatAnalyzer()
    alert_correlator = AlertCorrelator()
    
    @app.get("/health", response_model=HealthResponse)
    async def health_check():
        """
        Comprehensive health check for all Oracle services.
        Returns status of: database, redis, Azure OpenAI, Azure AI Search
        """
        services = {}
        overall_healthy = True
        
        # 1. Database Health Check
        try:
            async with get_db() as db:
                await db.execute(text("SELECT 1"))
            services["database"] = {"status": "healthy", "type": "postgresql"}
        except Exception as e:
            services["database"] = {"status": "unhealthy", "error": str(e)[:100]}
            overall_healthy = False
        
        # 2. Redis Health Check
        try:
            await redis_client.ping()
            services["redis_cache"] = {"status": "healthy"}
        except Exception as e:
            services["redis_cache"] = {"status": "unhealthy", "error": str(e)[:100]}
            overall_healthy = False
        
        # 3. Azure OpenAI Health Check
        if settings.AI_ENABLED and threat_analyzer.ai_client:
            try:
                # Lightweight check - just verify client is configured
                services["azure_openai"] = {
                    "status": "healthy",
                    "enabled": True,
                    "deployment": settings.AZURE_OPENAI_DEPLOYMENT,
                    "endpoint": settings.AZURE_OPENAI_ENDPOINT[:50] + "..." if settings.AZURE_OPENAI_ENDPOINT else None
                }
            except Exception as e:
                services["azure_openai"] = {"status": "degraded", "error": str(e)[:100]}
        else:
            services["azure_openai"] = {
                "status": "disabled",
                "enabled": False,
                "reason": "AI_ENABLED=false or missing API key"
            }
        
        # 4. Azure AI Search Health Check
        if threat_analyzer.search_service and threat_analyzer.search_service.search_client:
            services["azure_search"] = {
                "status": "healthy",
                "enabled": True,
                "index": settings.AZURE_SEARCH_INDEX_NAME
            }
        else:
            services["azure_search"] = {
                "status": "disabled",
                "enabled": False,
                "reason": "Missing Azure Search credentials"
            }
        
        # 5. Analytics Service
        services["analytics"] = {
            "status": "healthy",
            "ai_powered": threat_analyzer.ai_client is not None,
            "rag_enabled": threat_analyzer.search_service.search_client is not None if threat_analyzer.search_service else False
        }
        
        # Determine overall status
        if overall_healthy:
            status = "healthy"
        elif services["database"]["status"] == "healthy":
            status = "degraded"  # Core DB works but other services have issues
        else:
            status = "unhealthy"
            
        return HealthResponse(
            status=status,
            timestamp=datetime.now(timezone.utc),
            version=settings.VERSION,
            services=services,
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
        """Receive alerts with Abuse Prevention layer"""
        try:
            # --- LAYER 1: ABUSE PREVENTION ---
            if await check_abuse_safeguards(alert_request):
                # Return 202 to the Sentry but do not process/save to save resources
                return AlertResponse(
                    alert_id=0, status="filtered_or_throttled",
                    threat_score=0.0, correlations=[], processing_time_ms=0
                )

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
        try:
            async with get_db() as db:
                analytics_data = await calculate_analytics(db, time_range)
            
            return AnalyticsResponse(
                total_alerts=analytics_data.get("total_alerts", 0),
                risk_score=analytics_data.get("risk_score", 0.0),
                alerts=analytics_data.get("alerts") or [], 
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

async def process_alert_background(alert_id: int, threat_analyzer: ThreatAnalyzer, correlator: AlertCorrelator):
    """AI analysis with strict token budgeting"""
    try:
        async with get_db() as db:
            result = await db.execute(select(Alert).where(Alert.id == alert_id))
            alert = result.scalar_one_or_none()
            if not alert: return
            
            # --- AI BRAIN WITH TOKEN CAPS ---
            threat_score = 0.4
            ai_analysis = None
            
            if settings.AZURE_OPENAI_API_KEY and settings.AI_ENABLED:
                # Optimized call: max_tokens prevents bill shock from long GPT ramblings
                threat_score = await threat_analyzer.calculate_threat_score(alert)
                
                # Get AI analysis if available
                if hasattr(alert, 'ai_analysis'):
                    ai_analysis = alert.ai_analysis
            
            # Find correlations
            correlations = await correlator.find_correlations(alert)
            
            # Update alert
            alert.threat_score = threat_score
            alert.correlations = correlations
            alert.processed_at = datetime.now(timezone.utc)
            await db.flush()
            
            # Index threat for RAG (non-blocking, failures are logged but not critical)
            try:
                await threat_analyzer.index_threat_for_rag(alert, threat_score, ai_analysis)
            except Exception as e:
                logger.warning(f"Failed to index threat for RAG: {e}")
            
    except Exception as e:
        logger.error(f"Background processing failed for alert {alert_id}: {e}")

async def calculate_analytics(db, time_range: str) -> Dict[str, Any]:
    stmt = select(Alert).order_by(Alert.timestamp.desc()).limit(50)
    result = await db.execute(stmt)
    alerts_list = result.scalars().all()
    
    # Serialize alerts for JSON response (Dashboard compatibility)
    serialized_alerts = []
    for alert in alerts_list:
        serialized_alerts.append({
            "id": alert.id,
            "source": alert.source,
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "title": alert.title,
            "description": alert.description,
            "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
            "threat_score": alert.threat_score,
            "raw_data": alert.raw_data,
        })
    
    count_stmt = select(func.count()).select_from(Alert)
    count_result = await db.execute(count_stmt)
    total = count_result.scalar() or 0
    
    risk_stmt = select(func.avg(Alert.threat_score)).select_from(Alert)
    risk_result = await db.execute(risk_stmt)
    avg_risk = risk_result.scalar() or 0.0

    sev_stmt = select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    sev_result = await db.execute(sev_stmt)
    severity_map = {row[0]: row[1] for row in sev_result.all()}
    
    return {
        "total_alerts": total,
        "risk_score": float(avg_risk),
        "alerts": serialized_alerts,
        "severity_stats": severity_map
    }

async def get_alerts_count() -> int:
    try:
        async with get_db() as db:
            result = await db.execute(select(func.count()).select_from(Alert))
            return result.scalar() or 0
    except Exception: return 0