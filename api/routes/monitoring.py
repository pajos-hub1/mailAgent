"""
Monitoring control routes
"""
from fastapi import APIRouter, HTTPException, Depends, status
import asyncio

from api.models.monitoring import (
    MonitoringStatus,
    MonitoringControlResponse,
    PollingIntervalRequest,
    PollingIntervalResponse
)
from api.core.dependencies import get_agent
from api.core.lifespan import get_monitoring_task, set_monitoring_task
from core.email_agent import EmailMonitoringAgent


router = APIRouter(prefix="/monitoring", tags=["Monitoring Control"])


@router.post("/start", response_model=MonitoringControlResponse)
async def start_monitoring(agent: EmailMonitoringAgent = Depends(get_agent)):
    """Start email monitoring"""
    monitoring_task = get_monitoring_task()

    if monitoring_task and not monitoring_task.done():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Monitoring is already running"
        )

    try:
        # Start monitoring in background
        task = asyncio.create_task(agent.monitor_emails())
        set_monitoring_task(task)

        return MonitoringControlResponse(
            message="Email monitoring started",
            status="active"
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error starting monitoring: {str(e)}"
        )


@router.post("/stop", response_model=MonitoringControlResponse)
async def stop_monitoring(agent: EmailMonitoringAgent = Depends(get_agent)):
    """Stop email monitoring"""
    monitoring_task = get_monitoring_task()

    try:
        agent.stop_monitoring()

        if monitoring_task and not monitoring_task.done():
            monitoring_task.cancel()
            try:
                await monitoring_task
            except asyncio.CancelledError:
                pass

        return MonitoringControlResponse(
            message="Email monitoring stopped",
            status="stopped"
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error stopping monitoring: {str(e)}"
        )


@router.post("/pause", response_model=MonitoringControlResponse)
async def pause_monitoring(agent: EmailMonitoringAgent = Depends(get_agent)):
    """Pause email monitoring"""
    try:
        agent.pause_monitoring()
        return MonitoringControlResponse(
            message="Email monitoring paused",
            status="paused"
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error pausing monitoring: {str(e)}"
        )


@router.post("/resume", response_model=MonitoringControlResponse)
async def resume_monitoring(agent: EmailMonitoringAgent = Depends(get_agent)):
    """Resume email monitoring"""
    try:
        agent.resume_monitoring()
        return MonitoringControlResponse(
            message="Email monitoring resumed",
            status="active"
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error resuming monitoring: {str(e)}"
        )


@router.get("/status", response_model=MonitoringStatus)
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


@router.put("/polling-interval", response_model=PollingIntervalResponse)
async def update_polling_interval(
    request: PollingIntervalRequest,
    agent: EmailMonitoringAgent = Depends(get_agent)
):
    """Update polling interval"""
    try:
        agent.polling_interval = request.interval
        return PollingIntervalResponse(
            message=f"Polling interval updated to {request.interval} seconds",
            interval=request.interval
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error updating polling interval: {str(e)}"
        )
