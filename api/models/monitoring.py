"""
Monitoring-related Pydantic models
"""
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class MonitoringStatus(BaseModel):
    """Monitoring status response"""
    monitoring_active: bool
    running: bool
    sms_enabled: bool
    polling_interval: int
    total_emails: int
    important_count: int
    suspicious_count: int
    latest_email: Optional[datetime]


class MonitoringControlResponse(BaseModel):
    """Response for monitoring control actions"""
    message: str
    status: str


class PollingIntervalRequest(BaseModel):
    """Request to update polling interval"""
    interval: int = Field(..., ge=10, le=3600, description="Polling interval in seconds")


class PollingIntervalResponse(BaseModel):
    """Response for polling interval update"""
    message: str
    interval: int
