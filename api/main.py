"""
Main FastAPI application
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.core.config import settings
from api.core.lifespan import lifespan
from api.middleware.rate_limiting import RateLimitMiddleware
from api.middleware.logging import LoggingMiddleware

# Import routers
from api.routes import (
    health,
    emails,
    monitoring,
    learning,
    notifications,
    analytics
)
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
import asyncio
import logging
from datetime import datetime, timedelta
import uvicorn
import os
from contextlib import asynccontextmanager

# Import your existing modules
from core.email_agent import EmailMonitoringAgent
from utils.helpers import setup_logging

# Global agent instance
agent: Optional[EmailMonitoringAgent] = None
monitoring_task: Optional[asyncio.Task] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan"""
    global agent, monitoring_task

    # Startup
    setup_logging()
    logger = logging.getLogger(__name__)
    logger.info("Starting Email Monitoring API")

    try:
        agent = EmailMonitoringAgent()
        logger.info("Email agent initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize email agent: {e}")
        agent = None

    yield

    # Shutdown
    if monitoring_task and not monitoring_task.done():
        monitoring_task.cancel()
        try:
            await monitoring_task
        except asyncio.CancelledError:
            pass

    if agent:
        agent.stop_monitoring()

    logger.info("Email Monitoring API shutdown complete")


def create_app() -> FastAPI:
    """Create and configure FastAPI application"""

    app = FastAPI(
        title=settings.app_name,
        description=settings.app_description,
        version=settings.app_version,
        lifespan=lifespan,
        debug=settings.debug
    )

    # Add middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=settings.allowed_methods,
        allow_headers=settings.allowed_headers,
    )

    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(LoggingMiddleware)

    # Include routers
    app.include_router(health.router)
    app.include_router(emails.router)
    app.include_router(monitoring.router)
    app.include_router(learning.router)
    app.include_router(notifications.router)
    app.include_router(analytics.router)

    return app


# Create app instance
app = create_app()


# Pydantic models for request/response
class EmailData(BaseModel):
    id: str
    subject: str
    sender: str = Field(alias="from")
    body: str
    date: str
    timestamp: datetime

    class Config:
        populate_by_name = True


class ClassificationResult(BaseModel):
    category: str
    confidence: float
    details: Dict[str, Any]


class EmailClassification(BaseModel):
    email: EmailData
    classification: ClassificationResult
    processed_at: datetime


class FeedbackRequest(BaseModel):
    email_id: str
    predicted_category: str
    predicted_confidence: float
    user_category: str
    is_correct: bool
    email_data: Dict[str, Any]


class MonitoringStatus(BaseModel):
    monitoring_active: bool
    running: bool
    sms_enabled: bool
    polling_interval: int
    total_emails: int
    important_count: int
    suspicious_count: int
    latest_email: Optional[datetime]


class LearningStats(BaseModel):
    model_version: int
    is_trained: bool
    available_training_data: int
    class_distribution: Dict[str, int]
    feedback_type_distribution: Dict[str, int]
    ready_for_training: bool
    training_requirements: Dict[str, int]
    feedback_stats: Dict[str, Any]


class SystemHealth(BaseModel):
    status: str
    components: Dict[str, bool]
    uptime: str
    last_check: Optional[datetime]


# Dependency to get agent
def get_agent() -> EmailMonitoringAgent:
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Email agent not initialized"
        )
    return agent


# Health check endpoint
@app.get("/health", response_model=SystemHealth)
async def health_check():
    """Get system health status"""
    current_agent = agent

    components = {
        "email_agent": current_agent is not None,
        "gmail_fetcher": current_agent.fetcher.gmail_service is not None if current_agent else False,
        "classifier": current_agent.classifier.classifier is not None if current_agent else False,
        "sms_notifier": current_agent.notifier is not None if current_agent else False,
        "database": current_agent.classifier.active_learner.db.connection is not None if current_agent else False
    }

    status_text = "healthy" if all(components.values()) else "degraded"

    return SystemHealth(
        status=status_text,
        components=components,
        uptime="0:00:00",  # You can implement actual uptime tracking
        last_check=datetime.now()
    )


# Email monitoring endpoints
@app.post("/emails/check", response_model=List[EmailClassification])
async def check_emails(agent: EmailMonitoringAgent = Depends(get_agent)):
    """Manually check for new emails"""
    try:
        email_classifications = await agent.process_new_emails()

        results = []
        for email, classification in email_classifications:
            results.append(EmailClassification(
                email=EmailData(
                    id=email.get('id', ''),
                    subject=email.get('subject', ''),
                    sender=email.get('from', ''),
                    body=email.get('body', ''),
                    date=email.get('date', ''),
                    timestamp=email.get('date_parsed', datetime.now())
                ),
                classification=ClassificationResult(
                    category=classification.get('category', ''),
                    confidence=classification.get('confidence', 0.0),
                    details=classification.get('details', {})
                ),
                processed_at=datetime.now()
            ))

        return results

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error checking emails: {str(e)}"
        )


@app.post("/emails/classify")
async def classify_email(
        email_data: Dict[str, Any],
        agent: EmailMonitoringAgent = Depends(get_agent)
):
    """Classify a single email"""
    try:
        classification = agent.classifier.classify(email_data)

        return ClassificationResult(
            category=classification.get('category', ''),
            confidence=classification.get('confidence', 0.0),
            details=classification.get('details', {})
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error classifying email: {str(e)}"
        )


# Monitoring control endpoints
@app.post("/monitoring/start")
async def start_monitoring(
        background_tasks: BackgroundTasks,
        agent: EmailMonitoringAgent = Depends(get_agent)
):
    """Start email monitoring"""
    global monitoring_task

    if monitoring_task and not monitoring_task.done():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Monitoring is already running"
        )

    try:
        # Start monitoring in background
        monitoring_task = asyncio.create_task(agent.monitor_emails())

        return {"message": "Email monitoring started", "status": "active"}

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error starting monitoring: {str(e)}"
        )


@app.post("/monitoring/stop")
async def stop_monitoring(agent: EmailMonitoringAgent = Depends(get_agent)):
    """Stop email monitoring"""
    global monitoring_task

    try:
        agent.stop_monitoring()

        if monitoring_task and not monitoring_task.done():
            monitoring_task.cancel()
            try:
                await monitoring_task
            except asyncio.CancelledError:
                pass

        return {"message": "Email monitoring stopped", "status": "stopped"}

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error stopping monitoring: {str(e)}"
        )


@app.post("/monitoring/pause")
async def pause_monitoring(agent: EmailMonitoringAgent = Depends(get_agent)):
    """Pause email monitoring"""
    try:
        agent.pause_monitoring()
        return {"message": "Email monitoring paused", "status": "paused"}

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error pausing monitoring: {str(e)}"
        )


@app.post("/monitoring/resume")
async def resume_monitoring(agent: EmailMonitoringAgent = Depends(get_agent)):
    """Resume email monitoring"""
    try:
        agent.resume_monitoring()
        return {"message": "Email monitoring resumed", "status": "active"}

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error resuming monitoring: {str(e)}"
        )


@app.get("/monitoring/status", response_model=MonitoringStatus)
async def get_monitoring_status(agent: EmailMonitoringAgent = Depends(get_agent)):
    """Get current monitoring status"""
    try:
        status = agent.get_status()

        return MonitoringStatus(
            monitoring_active=status['monitoring_active'],
            running=status['running'],
            sms_enabled=status['sms_enabled'],
            polling_interval=status['polling_interval'],
            total_emails=status['total_emails'],
            important_count=status['important_count'],
            suspicious_count=status['suspicious_count'],
            latest_email=status['latest_email']
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting status: {str(e)}"
        )


# Learning and feedback endpoints
@app.post("/feedback")
async def submit_feedback(
        feedback: FeedbackRequest,
        agent: EmailMonitoringAgent = Depends(get_agent)
):
    """Submit user feedback for learning"""
    try:
        # Reconstruct prediction dict
        prediction = {
            'category': feedback.predicted_category,
            'confidence': feedback.predicted_confidence,
            'details': {}
        }

        success = agent.classifier.collect_user_feedback(
            feedback.email_data,
            prediction,
            feedback.user_category,
            feedback.is_correct
        )

        if success:
            return {"message": "Feedback submitted successfully", "success": True}
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to save feedback"
            )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error submitting feedback: {str(e)}"
        )


@app.get("/learning/stats", response_model=LearningStats)
async def get_learning_stats(agent: EmailMonitoringAgent = Depends(get_agent)):
    """Get learning system statistics"""
    try:
        stats = agent.classifier.get_learning_stats()

        return LearningStats(
            model_version=stats['model_version'],
            is_trained=stats['is_trained'],
            available_training_data=stats['available_training_data'],
            class_distribution=stats['class_distribution'],
            feedback_type_distribution=stats.get('feedback_type_distribution', {}),
            ready_for_training=stats['ready_for_training'],
            training_requirements=stats['training_requirements'],
            feedback_stats=stats['feedback_stats']
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting learning stats: {str(e)}"
        )


@app.post("/learning/retrain")
async def retrain_model(
        force: bool = False,
        agent: EmailMonitoringAgent = Depends(get_agent)
):
    """Retrain the learning model"""
    try:
        if force:
            success = agent.classifier.active_learner.force_retrain()
        else:
            success = agent.classifier.active_learner.retrain_model()

        if success:
            return {"message": "Model retrained successfully", "success": True}
        else:
            return {"message": "Retraining failed - insufficient data", "success": False}

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retraining model: {str(e)}"
        )


# SMS and notification endpoints
@app.post("/sms/test")
async def test_sms(agent: EmailMonitoringAgent = Depends(get_agent)):
    """Send a test SMS"""
    try:
        if not agent.notifier:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="SMS notifications not configured"
            )

        success = await agent.test_sms()

        if success:
            return {"message": "Test SMS sent successfully", "success": True}
        else:
            return {"message": "Test SMS failed", "success": False}

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error sending test SMS: {str(e)}"
        )


# Statistics and analytics endpoints
@app.get("/analytics/summary")
async def get_analytics_summary(agent: EmailMonitoringAgent = Depends(get_agent)):
    """Get email analytics summary"""
    try:
        stats = agent.get_statistics()
        recent_emails = agent.get_recent_emails(limit=20)

        return {
            "statistics": stats,
            "recent_emails": recent_emails,
            "generated_at": datetime.now()
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting analytics: {str(e)}"
        )


@app.get("/emails/recent")
async def get_recent_emails(
        limit: int = 10,
        category: Optional[str] = None,
        agent: EmailMonitoringAgent = Depends(get_agent)
):
    """Get recent processed emails"""
    try:
        emails = agent.get_recent_emails(limit=limit)

        # Filter by category if specified
        if category:
            emails = [email for email in emails if email['category'].lower() == category.lower()]

        return {
            "emails": emails,
            "count": len(emails),
            "filtered_by": category
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting recent emails: {str(e)}"
        )


# Configuration endpoints
@app.get("/config/model")
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


@app.put("/config/polling-interval")
async def update_polling_interval(
        interval: int = Field(..., ge=10, le=3600),
        agent: EmailMonitoringAgent = Depends(get_agent)
):
    """Update polling interval"""
    try:
        agent.polling_interval = interval
        return {"message": f"Polling interval updated to {interval} seconds", "interval": interval}

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error updating polling interval: {str(e)}"
        )


# Data management endpoints
@app.delete("/data/clear")
async def clear_data(agent: EmailMonitoringAgent = Depends(get_agent)):
    """Clear all stored email data"""
    try:
        agent.clear_data()
        return {"message": "All data cleared successfully"}

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error clearing data: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.reload,
        log_level=settings.log_level.lower()
    )
