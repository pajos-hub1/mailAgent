"""
Ultra-simplified main FastAPI application - No complex imports
"""
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import asyncio
import logging
from datetime import datetime
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


# Create FastAPI app
app = FastAPI(
    title="Email Monitoring Agent API",
    description="AI-powered email classification and monitoring system",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Simple Pydantic models
class EmailClassifyRequest(BaseModel):
    subject: str
    sender: str
    body: str
    date: Optional[str] = None

    class Config:
        schema_extra = {
            "example": {
                "subject": "Important Meeting",
                "sender": "boss@company.com",
                "body": "We need to discuss the project deadline.",
                "date": "2024-01-01T10:00:00"
            }
        }


class ClassificationResponse(BaseModel):
    category: str
    confidence: float
    details: Dict[str, Any]


class FeedbackRequest(BaseModel):
    email_id: str
    predicted_category: str
    predicted_confidence: float
    user_category: str
    is_correct: bool
    email_data: Dict[str, Any]


# Dependency to get agent
def get_agent() -> EmailMonitoringAgent:
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Email agent not initialized. Please check logs for initialization errors."
        )
    return agent


# Health check endpoint
@app.get("/health")
async def health_check():
    """Get system health status"""
    current_agent = agent

    components = {
        "email_agent": current_agent is not None,
        "gmail_fetcher": False,
        "classifier": False,
        "sms_notifier": False,
        "database": False
    }

    if current_agent:
        try:
            components["gmail_fetcher"] = current_agent.fetcher.gmail_service is not None
            components["classifier"] = current_agent.classifier.classifier is not None
            components["sms_notifier"] = current_agent.notifier is not None
            components["database"] = current_agent.classifier.active_learner.db.connection is not None
        except Exception as e:
            logging.getLogger(__name__).warning(f"Error checking components: {e}")

    status_text = "healthy" if components["email_agent"] and components["classifier"] else "degraded"

    return {
        "status": status_text,
        "components": components,
        "uptime": "0:00:00",
        "last_check": datetime.now().isoformat(),
        "message": "Email classification is available" if components["classifier"] else "Limited functionality"
    }


# Email classification endpoint
@app.post("/emails/classify", response_model=ClassificationResponse)
async def classify_email(
        email_request: EmailClassifyRequest,
        agent: EmailMonitoringAgent = Depends(get_agent)
):
    """Classify a single email"""
    try:
        # Convert request to email data format
        email_data = {
            "subject": email_request.subject,
            "from": email_request.sender,
            "body": email_request.body,
            "date": email_request.date or datetime.now().isoformat()
        }

        classification = agent.classifier.classify(email_data)

        return ClassificationResponse(
            category=classification.get('category', 'unknown'),
            confidence=classification.get('confidence', 0.0),
            details=classification.get('details', {})
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error classifying email: {str(e)}"
        )


# Check for new emails
@app.post("/emails/check")
async def check_emails(agent: EmailMonitoringAgent = Depends(get_agent)):
    """Manually check for new emails"""
    try:
        email_classifications = await agent.process_new_emails()

        results = []
        for email, classification in email_classifications:
            results.append({
                "email": {
                    "id": email.get('id', ''),
                    "subject": email.get('subject', ''),
                    "from": email.get('from', ''),
                    "body": email.get('body', '')[:200] + "..." if len(email.get('body', '')) > 200 else email.get(
                        'body', ''),
                    "date": email.get('date', ''),
                    "timestamp": email.get('date_parsed', datetime.now()).isoformat()
                },
                "classification": {
                    "category": classification.get('category', ''),
                    "confidence": classification.get('confidence', 0.0),
                    "details": classification.get('details', {})
                },
                "processed_at": datetime.now().isoformat()
            })

        return {
            "results": results,
            "count": len(results),
            "message": f"Found {len(results)} new emails" if results else "No new emails found"
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error checking emails: {str(e)}"
        )


# Monitoring status
@app.get("/monitoring/status")
async def get_monitoring_status(agent: EmailMonitoringAgent = Depends(get_agent)):
    """Get current monitoring status"""
    try:
        status = agent.get_status()
        return {
            "monitoring_active": status.get('monitoring_active', False),
            "running": status.get('running', False),
            "sms_enabled": status.get('sms_enabled', False),
            "polling_interval": status.get('polling_interval', 30),
            "total_emails": status.get('total_emails', 0),
            "important_count": status.get('important_count', 0),
            "suspicious_count": status.get('suspicious_count', 0),
            "latest_email": status.get('latest_email').isoformat() if status.get('latest_email') else None
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting status: {str(e)}"
        )


# Start monitoring
@app.post("/monitoring/start")
async def start_monitoring(agent: EmailMonitoringAgent = Depends(get_agent)):
    """Start email monitoring"""
    global monitoring_task

    if monitoring_task and not monitoring_task.done():
        return {"message": "Monitoring is already running", "status": "active"}

    try:
        monitoring_task = asyncio.create_task(agent.monitor_emails())
        return {"message": "Email monitoring started", "status": "active"}

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error starting monitoring: {str(e)}"
        )


# Stop monitoring
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


# Learning stats
@app.get("/learning/stats")
async def get_learning_stats(agent: EmailMonitoringAgent = Depends(get_agent)):
    """Get learning system statistics"""
    try:
        stats = agent.classifier.get_learning_stats()
        return stats

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting learning stats: {str(e)}"
        )


# Submit feedback
@app.post("/learning/feedback")
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

        return {
            "message": "Feedback submitted successfully" if success else "Failed to save feedback",
            "success": success
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error submitting feedback: {str(e)}"
        )


# Test SMS
@app.post("/notifications/sms/test")
async def test_sms(agent: EmailMonitoringAgent = Depends(get_agent)):
    """Send a test SMS"""
    try:
        if not agent.notifier:
            return {"message": "SMS notifications not configured", "success": False}

        success = await agent.test_sms()
        return {
            "message": "Test SMS sent successfully" if success else "Test SMS failed",
            "success": success
        }

    except Exception as e:
        return {
            "message": f"Error sending test SMS: {str(e)}",
            "success": False
        }


# Get model info
@app.get("/model/info")
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


# Get recent emails
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
            "filtered_by": category,
            "total_available": len(agent.get_recent_emails(limit=1000))
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting recent emails: {str(e)}"
        )


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "message": "Email Monitoring Agent API",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "health": "/health",
            "docs": "/docs",
            "classify_email": "/emails/classify",
            "check_emails": "/emails/check",
            "monitoring_status": "/monitoring/status"
        }
    }


if __name__ == "__main__":
    uvicorn.run(
        "api.main_simple:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
