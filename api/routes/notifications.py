"""
Notification routes
"""
from fastapi import APIRouter, HTTPException, Depends, status

from api.models.system import SMSTestResponse
from api.core.dependencies import get_agent
from core.email_agent import EmailMonitoringAgent


router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.post("/sms/test", response_model=SMSTestResponse)
async def test_sms(agent: EmailMonitoringAgent = Depends(get_agent)):
    """Send a test SMS"""
    try:
        if not agent.notifier:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="SMS notifications not configured"
            )

        success = await agent.test_sms()

        return SMSTestResponse(
            message="Test SMS sent successfully" if success else "Test SMS failed",
            success=success
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error sending test SMS: {str(e)}"
        )
