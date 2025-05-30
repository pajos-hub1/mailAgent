import asyncio
import logging
from dotenv import load_dotenv
import os
import time
from datetime import datetime, timedelta
import pandas as pd
from typing import List, Dict, Any
from collections import Counter, defaultdict

from email_fetch.fetcher import EmailFetcher
from classifier.email_classifier import EmailClassifier
from notify.notifier import TwilioNotifier
from utils.helpers import setup_logging


class EmailMonitoringAgent:
    def __init__(self):
        """Initialize the Email Monitoring Agent"""
        # Load environment variables
        load_dotenv(os.path.join('config', 'credentials.env'))

        # Setup logging
        setup_logging()
        self.logger = logging.getLogger(__name__)

        # Initialize components
        self.fetcher = EmailFetcher()
        self.classifier = EmailClassifier()

        # Log model information
        model_info = self.classifier.get_model_info()
        self.logger.info(f"Using model: {model_info['name']} ({model_info['current_model']})")

        # Initialize Twilio notifier
        try:
            self.notifier = TwilioNotifier()
            self.logger.info("Twilio notifier initialized successfully")
        except Exception as e:
            self.logger.error(f"Twilio notifier failed to initialize: {e}")
            self.notifier = None

        # Control flags
        self.running = False
        self.monitoring_active = False

        # Configure polling interval (in seconds)
        self.polling_interval = int(os.getenv('POLLING_INTERVAL', 30))

        # Email storage for summaries
        self.emails_processed = []
        self.total_emails = 0
        self.important_count = 0
        self.suspicious_count = 0

    def get_model_info(self):
        """Get information about the current classification model"""
        return self.classifier.get_model_info()

    async def process_new_emails(self, callback=None):
        """Process only new emails in the inbox"""
        try:
            new_emails = await self.fetcher.fetch_new_emails()

            if not new_emails:
                self.logger.info("No new emails found.")
                return []

            self.logger.info(f"{len(new_emails)} new email(s) found.")

            # Process all emails first (classify and display)
            email_classifications = []

            for i, email in enumerate(new_emails):
                try:
                    # Use zero-shot classifier
                    self.logger.debug(
                        f"Classifying email {i + 1}/{len(new_emails)}: {email.get('subject', 'No Subject')}")
                    classification = self.classifier.classify(email)
                    email_classifications.append((email, classification))

                    # Store email data for summaries
                    email_data = {
                        'timestamp': datetime.now(),
                        'from': email.get('from', 'Unknown Sender'),
                        'subject': email.get('subject', 'No Subject'),
                        'category': classification.get('category', 'Unknown'),
                        'confidence': classification.get('confidence', 0.0),
                        'body_preview': email.get('body', '')[:100] + '...' if email.get('body') else '',
                        'details': classification.get('details', {})
                    }
                    self.emails_processed.append(email_data)

                    # Update counters
                    self.total_emails += 1
                    category = classification.get('category', '').lower()
                    if category == 'important':
                        self.important_count += 1
                    elif category == 'suspicious':
                        self.suspicious_count += 1

                    # Call callback for UI updates if provided
                    if callback:
                        self.logger.debug(f"Calling UI callback for email: {email.get('subject', 'No Subject')}")
                        callback(email, classification)

                except Exception as e:
                    self.logger.error(f"Error classifying email: {e}", exc_info=True)
                    continue

            # Send notifications concurrently (non-blocking)
            notification_tasks = []
            for email, classification in email_classifications:
                task = asyncio.create_task(self._send_notification(email, classification))
                notification_tasks.append(task)

            # Wait for all notifications to complete (with timeout)
            if notification_tasks:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*notification_tasks, return_exceptions=True),
                        timeout=30.0
                    )
                except asyncio.TimeoutError:
                    self.logger.warning("Some SMS notifications timed out")

            return email_classifications

        except Exception as e:
            self.logger.error(f"Error in email processing: {e}", exc_info=True)
            return []

    async def _send_notification(self, email, classification):
        """Send SMS notification if needed"""
        if not self.notifier:
            return False

        try:
            category = classification.get('category', '').lower()

            # Send notifications for important and suspicious emails
            if category in ['important', 'suspicious']:
                success = await asyncio.wait_for(
                    self.notifier.send_notification(email, category),
                    timeout=15.0
                )

                if success:
                    self.logger.info(f"SMS sent for {category} email from {email.get('from', 'Unknown')}")
                else:
                    self.logger.error(f"Failed to send SMS for {category} email")

                return success

        except asyncio.TimeoutError:
            self.logger.error(f"SMS notification timed out for {category} email")
            return False
        except Exception as e:
            self.logger.error(f"Error sending notification: {e}")
            return False

        return False

    async def monitor_emails(self, email_callback=None, status_callback=None):
        """Continuous email monitoring"""
        self.monitoring_active = True
        self.running = True

        self.logger.info(f"Starting monitoring (interval: {self.polling_interval}s)")

        if status_callback:
            status_callback("monitoring_started", {
                'interval': self.polling_interval,
                'sms_enabled': self.notifier is not None
            })

        while self.running:
            if self.monitoring_active:
                await self.process_new_emails(email_callback)

            # Wait for the polling interval
            await asyncio.sleep(self.polling_interval)

        self.logger.info("Monitoring stopped")
        if status_callback:
            status_callback("monitoring_stopped", {})

    def pause_monitoring(self):
        """Pause email monitoring"""
        self.monitoring_active = False
        self.logger.info("Monitoring paused")

    def resume_monitoring(self):
        """Resume email monitoring"""
        self.monitoring_active = True
        self.logger.info("Monitoring resumed")

    def stop_monitoring(self):
        """Stop monitoring completely"""
        self.running = False
        self.monitoring_active = False
        self.logger.info("Monitoring stopped")

    def get_status(self):
        """Get current status information"""
        latest_email = None
        if self.emails_processed:
            latest_email = max(self.emails_processed, key=lambda x: x['timestamp'])['timestamp']

        return {
            'monitoring_active': self.monitoring_active,
            'running': self.running,
            'sms_enabled': self.notifier is not None,
            'polling_interval': self.polling_interval,
            'total_emails': self.total_emails,
            'important_count': self.important_count,
            'suspicious_count': self.suspicious_count,
            'latest_email': latest_email
        }

    def get_statistics(self):
        """Get email statistics"""
        if not self.emails_processed:
            return None

        # Category breakdown
        categories = Counter(email['category'] for email in self.emails_processed)

        # Top senders
        senders = Counter(email['from'] for email in self.emails_processed)

        # Time range
        timestamps = [email['timestamp'] for email in self.emails_processed]
        earliest = min(timestamps) if timestamps else None
        latest = max(timestamps) if timestamps else None

        return {
            'total_processed': len(self.emails_processed),
            'categories': dict(categories),
            'top_senders': senders.most_common(5),
            'time_range': {
                'earliest': earliest,
                'latest': latest
            }
        }

    def get_recent_emails(self, limit=10):
        """Get recent emails"""
        if not self.emails_processed:
            return []

        return sorted(self.emails_processed, key=lambda x: x['timestamp'], reverse=True)[:limit]

    def clear_data(self):
        """Clear all stored email data"""
        self.emails_processed = []
        self.total_emails = 0
        self.important_count = 0
        self.suspicious_count = 0
        self.logger.info("All data cleared")

    async def test_sms(self):
        """Test SMS functionality"""
        if not self.notifier:
            return False

        try:
            success = await asyncio.wait_for(
                self.notifier.send_test_sms(),
                timeout=15.0
            )
            return success
        except asyncio.TimeoutError:
            self.logger.error("Test SMS timed out")
            return False
        except Exception as e:
            self.logger.error(f"Test SMS error: {e}")
            return False
