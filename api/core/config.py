"""
Application configuration
"""
from pydantic_settings import BaseSettings
from typing import List, Optional
import os


class Settings(BaseSettings):
    """Application settings"""

    # API Configuration
    app_name: str = "Email Monitoring Agent API"
    app_version: str = "1.0.0"
    app_description: str = "AI-powered email classification and monitoring system with active learning"
    debug: bool = False

    # Server Configuration
    host: str = "0.0.0.0"
    port: int = 8000
    reload: bool = False

    # CORS Configuration
    allowed_origins: List[str] = ["*"]
    allowed_methods: List[str] = ["*"]
    allowed_headers: List[str] = ["*"]

    # Database Configuration
    mysql_host: str = "localhost"
    mysql_port: int = 3306
    mysql_database: str = "email_agent"
    mysql_user: str = "root"
    mysql_password: str = ""

    # Twilio Configuration
    twilio_account_sid: Optional[str] = None
    twilio_auth_token: Optional[str] = None
    twilio_phone_number: Optional[str] = None
    recipient_phone_number: Optional[str] = None

    # Email Configuration
    polling_interval: int = 30

    # Logging Configuration
    log_level: str = "INFO"
    log_file: str = "./data/logs/api.log"

    # Security Configuration
    rate_limit_per_minute: int = 60
    max_request_size: int = 10 * 1024 * 1024  # 10MB

    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()
