"""
Oracle Backend Configuration
Environment-based configuration management for cloud deployment
"""

import os
from typing import Optional
from pydantic import BaseSettings, Field

class Settings(BaseSettings):
    """Application settings with environment variable support"""
    
    # Service Configuration
    APP_NAME: str = "Cardea Oracle Backend"
    VERSION: str = "1.0.0"
    DEBUG: bool = Field(default=False, env="DEBUG")
    LOG_LEVEL: str = Field(default="INFO", env="LOG_LEVEL")
    PORT: int = Field(default=8000, env="PORT")
    
    # Database Configuration
    DATABASE_URL: str = Field(
        default="postgresql://oracle:password@localhost:5432/cardea_oracle",
        env="DATABASE_URL"
    )
    
    # Redis Configuration  
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        env="REDIS_URL"
    )
    
    # Security Configuration
    SECRET_KEY: str = Field(
        default="your-secret-key-change-in-production",
        env="SECRET_KEY"
    )
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, env="TOKEN_EXPIRE_MINUTES")
    
    # Sentry Integration
    SENTRY_WEBHOOK_TOKEN: str = Field(
        default="sentry-webhook-token",
        env="SENTRY_WEBHOOK_TOKEN"
    )
    
    # Alert Processing
    MAX_ALERTS_PER_BATCH: int = Field(default=100, env="MAX_ALERTS_PER_BATCH")
    ALERT_RETENTION_DAYS: int = Field(default=90, env="ALERT_RETENTION_DAYS")
    
    # Threat Intelligence
    THREAT_SCORE_THRESHOLD: float = Field(default=0.7, env="THREAT_SCORE_THRESHOLD")
    CORRELATION_WINDOW_MINUTES: int = Field(default=60, env="CORRELATION_WINDOW_MINUTES")
    
    # Cloud Configuration (for future deployment)
    CLOUD_PROVIDER: Optional[str] = Field(default=None, env="CLOUD_PROVIDER")
    DEPLOYMENT_ENVIRONMENT: str = Field(default="development", env="ENVIRONMENT")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

# Global settings instance
settings = Settings()