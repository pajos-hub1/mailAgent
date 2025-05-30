"""
System-related Pydantic models
"""
from pydantic import BaseModel
from typing import Dict, Optional
from datetime import datetime


class SystemHealth(BaseModel):
    """System health status"""
    status: str
    components: Dict[str, bool]
    uptime: str
    last_check: Optional[datetime]


class AnalyticsSummary(BaseModel):
    """Analytics summary response"""
    statistics: Dict
    recent_emails: list
    generated_at: datetime


class ClearDataResponse(BaseModel):
    """Clear data response"""
    message: str


class SMSTestResponse(BaseModel):
    """SMS test response"""
    message: str
    success: bool
