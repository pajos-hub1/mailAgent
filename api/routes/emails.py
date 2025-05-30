"""
Email processing routes
"""
from fastapi import APIRouter, HTTPException, Depends, status
from typing import List, Optional

from api.models.email import (
    EmailClassification,
    EmailClassifyRequest,
    ClassificationResult,
    RecentEmailsResponse
)
from api.core.dependencies import get_agent
from core.email_agent import EmailMonitoringAgent

router = APIRouter(prefix="/emails", tags=["Email Processing"])


@router.post("/check", response_model=List[EmailClassification])
async def check_emails(agent: EmailMonitoringAgent = Depends(get_agent)):
    """Manually check for new emails"""
    try:
        email_classifications = await agent.process_new_emails()

        results = []
        for email, classification in email_classifications:
            results.append(EmailClassification(
                email={
                    "id": email.get('id', ''),
                    "subject": email.get('subject', ''),
                    "from": email.get('from', ''),
                    "body": email.get('body', ''),
                    "date": email.get('date', ''),
                    "timestamp": email.get('date_parsed', datetime.now())
                },
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


@router.post("/classify", response_model=ClassificationResult)
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
            "date": email_request.date or ""
        }

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


@router.get("/recent", response_model=RecentEmailsResponse)
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

        return RecentEmailsResponse(
            emails=emails,
            count=len(emails),
            filtered_by=category
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting recent emails: {str(e)}"
        )
