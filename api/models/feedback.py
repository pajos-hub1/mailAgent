"""
Feedback-related Pydantic models
"""
from pydantic import BaseModel
from typing import Dict, Any


class FeedbackRequest(BaseModel):
    """User feedback request"""
    email_id: str
    predicted_category: str
    predicted_confidence: float
    user_category: str
    is_correct: bool
    email_data: Dict[str, Any]


class FeedbackResponse(BaseModel):
    """Feedback submission response"""
    message: str
    success: bool
