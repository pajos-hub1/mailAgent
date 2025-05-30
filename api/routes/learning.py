"""
Learning and feedback routes
"""
from fastapi import APIRouter, HTTPException, Depends, status

from api.models.learning import LearningStats, RetrainRequest, RetrainResponse
from api.models.feedback import FeedbackRequest, FeedbackResponse
from api.core.dependencies import get_agent
from core.email_agent import EmailMonitoringAgent

router = APIRouter(prefix="/learning", tags=["Learning & Feedback"])


@router.post("/feedback", response_model=FeedbackResponse)
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
            return FeedbackResponse(
                message="Feedback submitted successfully",
                success=True
            )
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


@router.get("/stats", response_model=LearningStats)
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


@router.post("/retrain", response_model=RetrainResponse)
async def retrain_model(
        request: RetrainRequest,
        agent: EmailMonitoringAgent = Depends(get_agent)
):
    """Retrain the learning model"""
    try:
        if request.force:
            success = agent.classifier.active_learner.force_retrain()
        else:
            success = agent.classifier.active_learner.retrain_model()

        if success:
            return RetrainResponse(
                message="Model retrained successfully",
                success=True
            )
        else:
            return RetrainResponse(
                message="Retraining failed - insufficient data",
                success=False
            )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retraining model: {str(e)}"
        )
