"""
Test script for the simplified API
"""
import requests
import json
import time


def test_simplified_api():
    """Test the simplified API"""
    base_url = "http://localhost:8000"

    print("🧪 Testing Simplified Email Agent API")
    print("=" * 50)

    # Test 1: Root endpoint
    print("\n🏠 Testing Root Endpoint...")
    try:
        response = requests.get(f"{base_url}/", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Root endpoint working - {data['message']}")
        else:
            print(f"❌ Root endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Root endpoint error: {e}")
        return False

    # Test 2: Health Check
    print("\n🏥 Testing Health Check...")
    try:
        response = requests.get(f"{base_url}/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Health check successful - Status: {data['status']}")
            print(f"   Message: {data.get('message', 'No message')}")

            # Show component status
            components = data.get('components', {})
            for component, status in components.items():
                status_icon = "✅" if status else "❌"
                print(f"   {status_icon} {component}")
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health check error: {e}")
        return False

    # Test 3: Email Classification
    print("\n📧 Testing Email Classification...")
    try:
        test_emails = [
            {
                "subject": "Urgent: Project Deadline",
                "sender": "manager@company.com",
                "body": "We need to discuss the project deadline immediately. Please call me ASAP."
            },
            {
                "subject": "Newsletter: Weekly Updates",
                "sender": "newsletter@company.com",
                "body": "Here are this week's updates and news from our company."
            },
            {
                "subject": "Suspicious: You've won $1000000!",
                "sender": "winner@suspicious.com",
                "body": "Congratulations! You've won a million dollars! Click here to claim your prize now!"
            }
        ]

        for i, email in enumerate(test_emails, 1):
            print(f"\n   📨 Test Email {i}:")
            print(f"      Subject: {email['subject']}")

            response = requests.post(f"{base_url}/emails/classify", json=email, timeout=10)
            if response.status_code == 200:
                data = response.json()
                print(f"      ✅ Category: {data['category']} ({data['confidence']:.1%} confidence)")
            else:
                print(f"      ❌ Classification failed: {response.status_code}")
                print(f"      Response: {response.text}")
    except Exception as e:
        print(f"❌ Email classification error: {e}")

    # Test 4: Monitoring Status
    print("\n📊 Testing Monitoring Status...")
    try:
        response = requests.get(f"{base_url}/monitoring/status", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Monitoring status retrieved")
            print(f"   Active: {data.get('monitoring_active', 'Unknown')}")
            print(f"   Total emails processed: {data.get('total_emails', 0)}")
            print(f"   Important emails: {data.get('important_count', 0)}")
            print(f"   Suspicious emails: {data.get('suspicious_count', 0)}")
        else:
            print(f"❌ Monitoring status failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Monitoring status error: {e}")

    # Test 5: Learning Stats
    print("\n🧠 Testing Learning Stats...")
    try:
        response = requests.get(f"{base_url}/learning/stats", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Learning stats retrieved")
            print(f"   Model version: {data.get('model_version', 'Unknown')}")
            print(f"   Is trained: {data.get('is_trained', False)}")
            print(f"   Available training data: {data.get('available_training_data', 0)}")
            print(f"   Ready for training: {data.get('ready_for_training', False)}")
        else:
            print(f"❌ Learning stats failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Learning stats error: {e}")

    # Test 6: Model Info
    print("\n🤖 Testing Model Info...")
    try:
        response = requests.get(f"{base_url}/model/info", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Model info retrieved")
            print(f"   Current model: {data.get('current_model', 'Unknown')}")
            print(f"   Model name: {data.get('name', 'Unknown')}")
            print(f"   GPU available: {data.get('gpu_available', False)}")
            print(f"   Using GPU: {data.get('using_gpu', False)}")
        else:
            print(f"❌ Model info failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Model info error: {e}")

    print("\n🎉 API testing completed!")
    print("\n📖 View full documentation at: http://localhost:8000/docs")
    print("🔍 Interactive API testing at: http://localhost:8000/docs#/")

    return True


if __name__ == "__main__":
    test_simplified_api()
