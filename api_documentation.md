# 📚 Email Monitoring Agent API Documentation

This document provides detailed information about the REST API endpoints available in the Email Monitoring Agent.

## 🔍 Base URL

\`\`\`
http://localhost:8000
\`\`\`

## 🔐 Authentication

Currently, the API does not implement authentication. For production use, consider adding an authentication mechanism.

## 📧 Email Endpoints

### Check for New Emails

Fetches new emails from Gmail and classifies them.

\`\`\`
POST /emails/check
\`\`\`

**Response**:

\`\`\`json
{
  "results": [
    {
      "email": {
        "id": "email_id",
        "subject": "Meeting Tomorrow",
        "from": "sender@example.com",
        "body": "Email content...",
        "date": "2023-05-30T10:00:00Z",
        "timestamp": "2023-05-30T10:00:00Z"
      },
      "classification": {
        "category": "important",
        "confidence": 0.85,
        "details": {
          "all_scores": {
            "important": 0.85,
            "suspicious": 0.05,
            "normal": 0.10
          }
        }
      },
      "processed_at": "2023-05-30T10:05:00Z"
    }
  ],
  "count": 1,
  "message": "Found 1 new emails"
}
\`\`\`

### Classify Email

Classifies a single email without fetching from Gmail.

\`\`\`
POST /emails/classify
\`\`\`

**Request Body**:

\`\`\`json
{
  "subject": "Project Update",
  "sender": "colleague@company.com",
  "body": "Here's the latest update on our project...",
  "date": "2023-05-30T09:00:00Z"
}
\`\`\`

**Response**:

\`\`\`json
{
  "category": "normal",
  "confidence": 0.75,
  "details": {
    "all_scores": {
      "important": 0.20,
      "suspicious": 0.05,
      "normal": 0.75
    }
  }
}
\`\`\`

### Get Recent Emails

Retrieves recently processed emails.

\`\`\`
GET /emails/recent
\`\`\`

**Query Parameters**:

- `limit` (optional): Maximum number of emails to return (default: 10)
- `category` (optional): Filter by category (important, suspicious, normal)

**Response**:

\`\`\`json
{
  "emails": [
    {
      "timestamp": "2023-05-30T10:05:00Z",
      "from": "sender@example.com",
      "subject": "Meeting Tomorrow",
      "category": "important",
      "confidence": 0.85,
      "body_preview": "Let's discuss the project..."
    }
  ],
  "count": 1,
  "filtered_by": "important",
  "total_available": 25
}
\`\`\`

## 🔄 Monitoring Endpoints

### Start Monitoring

Starts the email monitoring process.

\`\`\`
POST /monitoring/start
\`\`\`

**Response**:

\`\`\`json
{
  "message": "Email monitoring started",
  "status": "active"
}
\`\`\`

### Stop Monitoring

Stops the email monitoring process.

\`\`\`
POST /monitoring/stop
\`\`\`

**Response**:

\`\`\`json
{
  "message": "Email monitoring stopped",
  "status": "stopped"
}
\`\`\`

### Get Monitoring Status

Retrieves the current monitoring status.

\`\`\`
GET /monitoring/status
\`\`\`

**Response**:

\`\`\`json
{
  "monitoring_active": true,
  "running": true,
  "sms_enabled": true,
  "polling_interval": 30,
  "total_emails": 42,
  "important_count": 8,
  "suspicious_count": 3,
  "latest_email": "2023-05-30T10:05:00Z"
}
\`\`\`

## 🧠 Learning Endpoints

### Submit Feedback

Submits user feedback for improving the classification model.

\`\`\`
POST /learning/feedback
\`\`\`

**Request Body**:

\`\`\`json
{
  "email_id": "email_id",
  "predicted_category": "normal",
  "predicted_confidence": 0.75,
  "user_category": "important",
  "is_correct": false,
  "email_data": {
    "id": "email_id",
    "subject": "Project Update",
    "from": "colleague@company.com",
    "body": "Here's the latest update on our project..."
  }
}
\`\`\`

**Response**:

\`\`\`json
{
  "message": "Feedback submitted successfully",
  "success": true
}
\`\`\`

### Get Learning Stats

Retrieves statistics about the learning system.

\`\`\`
GET /learning/stats
\`\`\`

**Response**:

\`\`\`json
{
  "model_version": 6,
  "is_trained": true,
  "available_training_data": 42,
  "class_distribution": {
    "important": 15,
    "suspicious": 8,
    "normal": 19
  },
  "feedback_type_distribution": {
    "confirmation": 30,
    "correction": 12
  },
  "ready_for_training": true,
  "training_requirements": {
    "min_total_examples": 3,
    "min_classes": 2,
    "min_examples_per_class": 1
  },
  "feedback_stats": {
    "total_feedback": 42,
    "overall_accuracy": 71.4,
    "category_stats": {
      "important": {
        "total": 15,
        "correct": 10,
        "accuracy": 66.7
      },
      "suspicious": {
        "total": 8,
        "correct": 6,
        "accuracy": 75.0
      },
      "normal": {
        "total": 19,
        "correct": 14,
        "accuracy": 73.7
      }
    }
  }
}
\`\`\`

### Retrain Model

Triggers model retraining with collected feedback.

\`\`\`
POST /learning/retrain
\`\`\`

**Request Body**:

\`\`\`json
{
  "force": false
}
\`\`\`

**Response**:

\`\`\`json
{
  "message": "Model retrained successfully",
  "success": true
}
\`\`\`

## 📱 Notification Endpoints

### Test SMS

Sends a test SMS notification.

\`\`\`
POST /notifications/sms/test
\`\`\`

**Response**:

\`\`\`json
{
  "message": "Test SMS sent successfully",
  "success": true
}
\`\`\`

## 🔍 System Endpoints

### Health Check

Checks the health of the system components.

\`\`\`
GET /health
\`\`\`

**Response**:

\`\`\`json
{
  "status": "healthy",
  "components": {
    "email_agent": true,
    "gmail_fetcher": true,
    "classifier": true,
    "sms_notifier": true,
    "database": true
  },
  "uptime": "0:00:00",
  "last_check": "2023-05-30T10:05:00Z",
  "message": "Email classification is available"
}
\`\`\`

### Get Model Info

Retrieves information about the current classification model.

\`\`\`
GET /model/info
\`\`\`

**Response**:

\`\`\`json
{
  "current_model": "roberta-large-mnli",
  "name": "DeBERTa-v2 XLarge MNLI (Best for Email)",
  "specialty": "Natural Language Inference - Optimized for email classification",
  "gpu_available": false,
  "using_gpu": false,
  "learning_enabled": true,
  "learned_model_version": 6,
  "learned_model_trained": true
}
\`\`\`

## 🔄 Error Handling

The API uses standard HTTP status codes:

- `200 OK`: Successful request
- `400 Bad Request`: Invalid input
- `404 Not Found`: Resource not found
- `500 Internal Server Error`: Server-side error

Error responses follow this format:

\`\`\`json
{
  "detail": "Error message describing what went wrong"
}
\`\`\`

## 📝 Examples

### Classify an Email

**Request**:

\`\`\`bash
curl -X POST "http://localhost:8000/emails/classify" \
     -H "Content-Type: application/json" \
     -d '{
       "subject": "Urgent: Project Deadline",
       "sender": "manager@company.com",
       "body": "We need to discuss the project deadline immediately. Please call me ASAP."
     }'
\`\`\`

**Response**:

\`\`\`json
{
  "category": "important",
  "confidence": 0.85,
  "details": {
    "all_scores": {
      "important": 0.85,
      "suspicious": 0.05,
      "normal": 0.10
    }
  }
}
\`\`\`

### Start Monitoring

**Request**:

\`\`\`bash
curl -X POST "http://localhost:8000/monitoring/start"
\`\`\`

**Response**:

\`\`\`json
{
  "message": "Email monitoring started",
  "status": "active"
}
\`\`\`

### Submit Feedback

**Request**:

\`\`\`bash
curl -X POST "http://localhost:8000/learning/feedback" \
     -H "Content-Type: application/json" \
     -d '{
       "email_id": "email_id",
       "predicted_category": "normal",
       "predicted_confidence": 0.75,
       "user_category": "important",
       "is_correct": false,
       "email_data": {
         "id": "email_id",
         "subject": "Project Update",
         "from": "colleague@company.com",
         "body": "Here is the latest update on our project..."
       }
     }'
\`\`\`

**Response**:

\`\`\`json
{
  "message": "Feedback submitted successfully",
  "success": true
}
