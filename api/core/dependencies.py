"""
FastAPI dependencies
"""
from fastapi import HTTPException, status, Depends
from typing import Optional
import logging

from core.email_agent import EmailMonitoringAgent


# Global agent instance
_agent: Optional[EmailMonitoringAgent] = None
logger = logging.getLogger(__name__)


def get_agent() -> EmailMonitoringAgent:
    """Dependency to get the email agent instance"""
    global _agent

    if _agent is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Email agent not initialized"
        )

    return _agent


def set_agent(agent: EmailMonitoringAgent) -> None:
    """Set the global agent instance"""
    global _agent
    _agent = agent
    logger.info("Email agent instance set")


def get_agent_optional() -> Optional[EmailMonitoringAgent]:
    """Get agent instance without raising exception if not available"""
    global _agent
    return _agent
