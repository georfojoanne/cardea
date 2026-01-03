"""
Database Models and Connection Management
SQLAlchemy models for Oracle backend data persistence
"""

import asyncio
from datetime import datetime
from typing import Optional, Dict, Any, List
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import (
    Column, Integer, String, DateTime, Float, JSON, Text, 
    Boolean, ForeignKey, Index, text
)
from sqlalchemy.orm import relationship, selectinload
from contextlib import asynccontextmanager
import logging

from config import settings

logger = logging.getLogger(__name__)

# Database base
Base = declarative_base()

# Database engine and session
engine = None
async_session = None

class Alert(Base):
    """Alert data model"""
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    source = Column(String(100), nullable=False, index=True)
    alert_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    timestamp = Column(DateTime, nullable=False, index=True, default=datetime.utcnow)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    processed_at = Column(DateTime, nullable=True)
    
    # Analysis results
    threat_score = Column(Float, nullable=True)
    risk_level = Column(String(20), nullable=True)
    
    # Raw data and context
    raw_data = Column(JSON, nullable=True)
    network_context = Column(JSON, nullable=True)
    correlations = Column(JSON, nullable=True)
    indicators = Column(JSON, nullable=True)
    
    # Relationships
    threat_intel = relationship("ThreatIntelligence", back_populates="alerts")
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_alerts_timestamp_severity', 'timestamp', 'severity'),
        Index('idx_alerts_source_type', 'source', 'alert_type'),
        Index('idx_alerts_threat_score', 'threat_score'),
    )

class ThreatIntelligence(Base):
    """Threat intelligence data model"""
    __tablename__ = "threat_intelligence"
    
    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(String(100), unique=True, nullable=False, index=True)
    threat_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False)
    confidence_score = Column(Float, nullable=False)
    
    # Threat details
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    indicators = Column(JSON, nullable=True)  # IOCs, IP addresses, domains, etc.
    tactics = Column(JSON, nullable=True)     # MITRE ATT&CK tactics
    techniques = Column(JSON, nullable=True)  # MITRE ATT&CK techniques
    
    # Timeline
    first_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True)
    alerts = relationship("Alert", back_populates="threat_intel")

class SystemMetrics(Base):
    """System metrics and performance data"""
    __tablename__ = "system_metrics"
    
    id = Column(Integer, primary_key=True, index=True)
    metric_name = Column(String(100), nullable=False, index=True)
    metric_value = Column(Float, nullable=False)
    metric_unit = Column(String(50), nullable=True)
    tags = Column(JSON, nullable=True)  # Additional metadata
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    
    # Indexes
    __table_args__ = (
        Index('idx_metrics_name_timestamp', 'metric_name', 'timestamp'),
    )

class User(Base):
    """User authentication and authorization"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(200), nullable=True)
    hashed_password = Column(String(255), nullable=False)
    
    # Status and permissions
    is_active = Column(Boolean, default=True, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)
    roles = Column(JSON, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

class AlertCorrelation(Base):
    """Alert correlation relationships"""
    __tablename__ = "alert_correlations"
    
    id = Column(Integer, primary_key=True, index=True)
    primary_alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False)
    related_alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False)
    correlation_type = Column(String(50), nullable=False)
    correlation_score = Column(Float, nullable=False)
    correlation_reason = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    
    # Indexes
    __table_args__ = (
        Index('idx_correlations_primary', 'primary_alert_id'),
        Index('idx_correlations_related', 'related_alert_id'),
    )

# Database connection management
async def init_database():
    """Initialize database connection and create tables"""
    global engine, async_session
    
    try:
        # Convert PostgreSQL URL to async format
        database_url = settings.DATABASE_URL
        if database_url.startswith("postgresql://"):
            database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
        
        # Create async engine
        engine = create_async_engine(
            database_url,
            echo=settings.DEBUG,
            pool_pre_ping=True,
            pool_recycle=3600
        )
        
        # Create session factory
        async_session = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        
        # Create tables
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        logger.info("Database initialized successfully")
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise

@asynccontextmanager
async def get_db():
    """Database session context manager"""
    if async_session is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    
    async with async_session() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

async def close_database():
    """Close database connections"""
    global engine
    if engine:
        await engine.dispose()
        logger.info("Database connections closed")