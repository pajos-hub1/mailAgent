"""
Updated client for the modular API
"""
import requests
import json
from datetime import datetime
from typing import Dict, List, Optional


class EmailAgentClient:
    """Client for the Email Agent API"""

    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()

    # Health endpoints
    def health_check(self) -> Dict:
        """Check API health"""
        response = self.session.get(f"{self.base_url}/health")
        response.raise_for_status()
        return response.json()

    # Email endpoints
    def check_emails(self) -> List[Dict]:
        """Manually check for new emails"""
        response = self.session.post(f"{self.base_url}/emails/check")
        response.raise_for_status()
        return response.json()

    def classify_email(self, subject: str, sender: str, body: str, date: str = None) -> Dict:
        """Classify a single email"""
        data = {
            "subject": subject,
            "from": sender,
            "body": body,
            "date": date
        }
        response = self.session.post(f"{self.base_url}/emails/classify", json=data)
        response.raise_for_status()
        return response.json()

    def get_recent_emails(self, limit: int = 10, category: str = None) -> Dict:
        """Get recent emails"""
        params = {"limit": limit}
        if category:
            params["category"] = category

        response = self.session.get(f"{self.base_url}/emails/recent", params=params)
        response.raise_for_status()
        return response.json()

    # Monitoring endpoints
    def start_monitoring(self) -> Dict:
        """Start email monitoring"""
        response = self.session.post(f"{self.base_url}/monitoring/start")
        response.raise_for_status()
        return response.json()

    def stop_monitoring(self) -> Dict:
        """Stop email monitoring"""
        response = self.session.post(f"{self.base_url}/monitoring/stop")
        response.raise_for_status()
        return response.json()

    def pause_monitoring(self) -> Dict:
        """Pause email monitoring"""
        response = self.session.post(f"{self.base_url}/monitoring/pause")
        response.raise_for_status()
        return response.json()

    def resume_monitoring(self) -> Dict:
        """Resume email monitoring"""
        response = self.session.post(f"{self.base_url}/monitoring/resume")
        response.raise_for_status()
        return response.json()

    def get_monitoring_status(self) -> Dict:
        """Get monitoring status"""
        response = self.session.get(f"{self.base_url}/monitoring/status")
        response.raise_for_status()
        return response.json()

    def update_polling_interval(self, interval: int) -> Dict:
        """Update polling interval"""
        data = {"interval": interval}
        response = self.session.put(f"{self.base_url}/monitoring/polling-interval", json=data)
        response.raise_for_status()
        return response.json()

    # Learning endpoints
    def submit_feedback(self, feedback_data: Dict) -> Dict:
        """Submit user feedback"""
        response = self.session.post(f"{self.base_url}/learning/feedback", json=feedback_data)
        response.raise_for_status()
        return response.json()

    def get_learning_stats(self) -> Dict:
        """Get learning statistics"""
        response = self.session.get(f"{self.base_url}/learning/stats")
        response.raise_for_status()
        return response.json()

    def retrain_model(self, force: bool = False) -> Dict:
        """Retrain the model"""
        data = {"force": force}
        response = self.session.post(f"{self.base_url}/learning/retrain", json=data)
        response.raise_for_status()
        return response.json()

    # Notification endpoints
    def test_sms(self) -> Dict:
        """Send test SMS"""
        response = self.session.post(f"{self.base_url}/notifications/sms/test")
        response.raise_for_status()
        return response.json()

    # Analytics endpoints
    def get_analytics_summary(self) -> Dict:
        """Get analytics summary"""
        response = self.session.get(f"{self.base_url}/analytics/summary")
        response.raise_for_status()
        return response.json()

    def get_model_info(self) -> Dict:
        """Get model information"""
        response = self.session.get(f"{self.base_url}/analytics/model-info")
        response.raise_for_status()
        return response.json()

    def clear_data(self) -> Dict:
        """Clear all data"""
        response = self.session.delete(f"{self.base_url}/analytics/data")
        response.raise_for_status()
        return response.json()


# Example usage
if __name__ == "__main__":
    client = EmailAgentClient()

    try:
        # Check health
        health = client.health_check()
        print("API Health:", health)

        # Get monitoring status
        status = client.get_monitoring_status()
        print("Monitoring Status:", status)

        # Get learning stats
        learning_stats = client.get_learning_stats()
        print("Learning Stats:", learning_stats)

    except requests.exceptions.RequestException as e:
        print(f"API Error: {e}")
