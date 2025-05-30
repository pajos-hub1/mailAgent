"""
Email-related Pydantic models
"""
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
from datetime import datetime


class EmailData(BaseModel):
    """Email data model"""
    id: str
    subject: str
    sender: str = Field(alias="from")
    body: str
    date: str
    timestamp: datetime

    class Config:
        populate_by_name = True


class ClassificationResult(BaseModel):
    """Email classification result"""
    category: str
    confidence: float
    details: Dict[str, Any]


class EmailClassification(BaseModel):
    """Complete email classification response"""
    email: EmailData
    classification: ClassificationResult
    processed_at: datetime


class EmailClassifyRequest(BaseModel):
    """Request to classify an email"""
    subject: str
    sender: str = Field(alias="from")
    body: str
    date: Optional[str] = None

    class Config:
        populate_by_name = True


class RecentEmailsResponse(BaseModel):
    """Response for recent emails"""
    emails: list
    count: int
    filtered_by: Optional[str] = None
