"""
Analytics and statistics routes
"""
from fastapi import APIRouter, HTTPException, Depends, status
from datetime import datetime

from api.models.system import AnalyticsSummary, ClearDataResponse
from api.core.dependencies import get_agent
from core.email_agent import EmailMonitoringAgent


router = APIRouter(prefix="/analytics", tags=["Analytics"])


@router.get("/summary", response_model=AnalyticsSummary)
async def get_analytics_summary(agent: EmailMonitoringAgent = Depends(get_agent)):
    """Get email analytics summary"""
    try:
        stats = agent.get_statistics()
        recent_emails = agent.get_recent_emails(limit=20)

        return AnalyticsSummary(
            statistics=stats or {},
            recent_emails=recent_emails,
            generated_at=datetime.now()
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting analytics: {str(e)}"
        )


@router.get("/model-info")
async def get_model_info(agent: EmailMonitoringAgent = Depends(get_agent)):
    """Get current model information"""
    try:
        model_info = agent.get_model_info()
        return model_info

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting model info: {str(e)}"
        )


@router.delete("/data", response_model=ClearDataResponse)
async def clear_data(agent: EmailMonitoringAgent = Depends(get_agent)):
    """Clear all stored email data"""
    try:
        agent.clear_data()
        return ClearDataResponse(message="All data cleared successfully")

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error clearing data: {str(e)}"
        )
