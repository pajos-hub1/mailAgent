"""
Application lifespan management
"""
import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI

from core.email_agent import EmailMonitoringAgent
from utils.helpers import setup_logging
from api.core.dependencies import set_agent
from api.core.config import settings


logger = logging.getLogger(__name__)
monitoring_task: Optional[asyncio.Task] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan"""
    global monitoring_task

    # Startup
    logger.info("Starting Email Monitoring API")

    # Setup logging
    setup_logging(log_level=getattr(logging, settings.log_level.upper()))

    try:
        # Initialize email agent
        agent = EmailMonitoringAgent()
        set_agent(agent)
        logger.info("Email agent initialized successfully")

        # Store agent in app state for access in routes
        app.state.agent = agent

    except Exception as e:
        logger.error(f"Failed to initialize email agent: {e}")
        # Don't fail startup, but agent will be unavailable

    yield

    # Shutdown
    logger.info("Shutting down Email Monitoring API")

    # Cancel monitoring task if running
    if monitoring_task and not monitoring_task.done():
        monitoring_task.cancel()
        try:
            await monitoring_task
        except asyncio.CancelledError:
            logger.info("Monitoring task cancelled")

    # Stop agent
    agent = getattr(app.state, 'agent', None)
    if agent:
        agent.stop_monitoring()
        logger.info("Email agent stopped")

    logger.info("Email Monitoring API shutdown complete")


def get_monitoring_task() -> Optional[asyncio.Task]:
    """Get the current monitoring task"""
    global monitoring_task
    return monitoring_task


def set_monitoring_task(task: asyncio.Task) -> None:
    """Set the monitoring task"""
    global monitoring_task
    monitoring_task = task
