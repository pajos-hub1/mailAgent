"""
Learning system Pydantic models
"""
from pydantic import BaseModel
from typing import Dict, Any


class LearningStats(BaseModel):
    """Learning system statistics"""
    model_version: int
    is_trained: bool
    available_training_data: int
    class_distribution: Dict[str, int]
    feedback_type_distribution: Dict[str, int]
    ready_for_training: bool
    training_requirements: Dict[str, int]
    feedback_stats: Dict[str, Any]


class RetrainRequest(BaseModel):
    """Model retraining request"""
    force: bool = False


class RetrainResponse(BaseModel):
    """Model retraining response"""
    message: str
    success: bool
