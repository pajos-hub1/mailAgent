"""
Health check routes
"""
from fastapi import APIRouter, Depends
from datetime import datetime

from api.models.system import SystemHealth
from api.core.dependencies import get_agent_optional


router = APIRouter(tags=["Health"])


@router.get("/health", response_model=SystemHealth)
async def health_check():
    """Get system health status"""
    agent = get_agent_optional()

    components = {
        "email_agent": agent is not None,
        "gmail_fetcher": agent.fetcher.gmail_service is not None if agent else False,
        "classifier": agent.classifier.classifier is not None if agent else False,
        "sms_notifier": agent.notifier is not None if agent else False,
        "database": agent.classifier.active_learner.db.connection is not None if agent else False
    }

    status_text = "healthy" if all(components.values()) else "degraded"

    return SystemHealth(
        status=status_text,
        components=components,
        uptime="0:00:00",  # You can implement actual uptime tracking
        last_check=datetime.now()
    )
