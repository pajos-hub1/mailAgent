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
from analysis.classifier import EmailClassifier
from notify.notifier import TwilioNotifier
from utils.helpers import setup_logging


class EmailMonitoringAgent:
    def __init__(self):
        # Load environment variables
        load_dotenv(os.path.join('config', 'credentials.env'))

        # Setup logging
        setup_logging()
        self.logger = logging.getLogger(__name__)

        # Initialize components
        self.fetcher = EmailFetcher()

        # Initialize classifier with EmailRep.io API key (if available)
        emailrep_api_key = os.getenv('EMAILREP_API_KEY')  # Add this to your .env file
        self.classifier = EmailClassifier(
            rules_file="classification_rules.json",
            api_key=emailrep_api_key
        )

        if emailrep_api_key:
            self.logger.info("EmailRep.io threat intelligence enabled")
        else:
            self.logger.info("EmailRep.io threat intelligence running in free tier mode")

        # Initialize Twilio notifier
        try:
            twilio_sid = os.getenv('TWILIO_ACCOUNT_SID')
            self.logger.info(f"TWILIO_ACCOUNT_SID found: {'Yes' if twilio_sid else 'No'}")
            if twilio_sid:
                self.logger.info(f"TWILIO_ACCOUNT_SID starts with: {twilio_sid[:8]}...")

            self.notifier = TwilioNotifier()
            self.logger.info("Twilio notifier initialized successfully")
        except Exception as e:
            self.logger.error(f"Twilio notifier failed to initialize: {e}")
            self.notifier = None

        # Control flags
        self.running = False
        self.monitoring_active = False

        # Configure polling interval (in seconds)
        self.polling_interval = int(os.getenv('POLLING_INTERVAL', 10))

        # Email storage for summaries
        self.emails_processed = []
        self.total_emails = 0
        self.important_count = 0
        self.suspicious_count = 0
        self.malicious_count = 0  # New counter for malicious emails

    def basic_classify(self, email):
        """Basic classification fallback when ML classifier fails"""
        subject = email.get('subject', '').lower()
        body = email.get('body', '').lower()
        from_addr = email.get('from', '').lower()

        # Simple keyword-based classification
        important_keywords = ['urgent', 'important', 'asap', 'critical', 'deadline']
        suspicious_keywords = ['virus', 'malware', 'phishing', 'scam', 'suspicious', 'click here', 'verify account']

        text_to_check = f"{subject} {body} {from_addr}"

        if any(keyword in text_to_check for keyword in suspicious_keywords):
            return {'category': 'Suspicious', 'confidence': 0.7}
        elif any(keyword in text_to_check for keyword in important_keywords):
            return {'category': 'Important', 'confidence': 0.6}
        else:
            return {'category': 'Normal', 'confidence': 0.5}

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

            for email in new_emails:
                try:
                    # Use classifier if available, otherwise use basic classification
                    if self.classifier:
                        classification = self.classifier.classify(email)
                    else:
                        classification = self.basic_classify(email)

                    email_classifications.append((email, classification))

                    # Store email data for summaries
                    email_data = {
                        'timestamp': datetime.now(),
                        'from': email.get('from', 'Unknown Sender'),
                        'subject': email.get('subject', 'No Subject'),
                        'category': classification.get('category', 'Unknown'),
                        'confidence': classification.get('confidence', 0.0),
                        'body_preview': email.get('body', '')[:100] + '...' if email.get('body') else '',
                        'threat_intelligence': classification.get('details', {}).get('threat_intelligence'),
                        'rule_matches': classification.get('details', {}).get('rule_matches', [])
                    }
                    self.emails_processed.append(email_data)

                    # Update counters
                    self.total_emails += 1
                    category = classification.get('category', '').lower()
                    if category == 'important':
                        self.important_count += 1
                    elif category == 'suspicious':
                        self.suspicious_count += 1

                        # Check if it's malicious based on threat intelligence
                        threat_intel = classification.get('details', {}).get('threat_intelligence')
                        if threat_intel and threat_intel.get('is_malicious', False):
                            self.malicious_count += 1

                    # Call callback for UI updates if provided
                    if callback:
                        callback(email, classification)

                except Exception as e:
                    self.logger.error(f"Error classifying email: {e}")
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
            threat_intel = classification.get('details', {}).get('threat_intelligence')

            # Send notifications for important, suspicious, or malicious emails
            if category in ['important', 'suspicious'] or (threat_intel and threat_intel.get('is_malicious', False)):
                # Determine notification type
                if threat_intel and threat_intel.get('is_malicious', False):
                    notification_type = 'malicious'
                else:
                    notification_type = category

                success = await asyncio.wait_for(
                    self.notifier.send_notification(email, notification_type),
                    timeout=15.0
                )

                if success:
                    self.logger.info(f"SMS sent for {notification_type} email from {email.get('from', 'Unknown')}")
                else:
                    self.logger.error(f"Failed to send SMS for {notification_type} email")

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
            'malicious_count': self.malicious_count,
            'latest_email': latest_email
        }

    def get_statistics(self):
        """Get email statistics"""
        if not self.emails_processed:
            return None

        # Category breakdown
        categories = Counter(email['category'] for email in self.emails_processed)

        # Threat intelligence stats
        threat_emails = [email for email in self.emails_processed if email.get('threat_intelligence')]
        malicious = len([email for email in threat_emails
                         if email['threat_intelligence'].get('is_malicious', False)])
        suspicious_threat = len([email for email in threat_emails
                                 if email['threat_intelligence'].get('is_suspicious', False)])

        # Top senders
        senders = Counter(email['from'] for email in self.emails_processed)

        # Time range
        timestamps = [email['timestamp'] for email in self.emails_processed]
        earliest = min(timestamps) if timestamps else None
        latest = max(timestamps) if timestamps else None

        return {
            'total_processed': len(self.emails_processed),
            'categories': dict(categories),
            'threat_intel': {
                'analyzed': len(threat_emails),
                'malicious': malicious,
                'suspicious': suspicious_threat
            },
            'top_senders': senders.most_common(5),
            'time_range': {
                'earliest': earliest,
                'latest': latest
            }
        }

    def get_threat_summary(self):
        """Get threat intelligence summary"""
        threat_emails = [email for email in self.emails_processed if email.get('threat_intelligence')]

        if not threat_emails:
            return None

        malicious_emails = [email for email in threat_emails
                            if email['threat_intelligence'].get('is_malicious', False)]
        suspicious_emails = [email for email in threat_emails
                             if email['threat_intelligence'].get('is_suspicious', False)]

        # Malicious senders
        malicious_senders = Counter(email['from'] for email in malicious_emails)

        # Common threat indicators
        all_indicators = []
        for email in threat_emails:
            indicators = email['threat_intelligence'].get('threat_indicators', [])
            all_indicators.extend(indicators)

        indicator_counts = Counter(all_indicators)

        return {
            'total_analyzed': len(threat_emails),
            'malicious_count': len(malicious_emails),
            'suspicious_count': len(suspicious_emails),
            'malicious_senders': malicious_senders.most_common(5),
            'threat_indicators': indicator_counts.most_common(5),
            'malicious_emails': malicious_emails,
            'suspicious_emails': suspicious_emails
        }

    def get_recent_emails(self, limit=10):
        """Get recent emails"""
        if not self.emails_processed:
            return []

        return sorted(self.emails_processed, key=lambda x: x['timestamp'], reverse=True)[:limit]

    def generate_weekly_summary(self, emails_data: List[Dict] = None, start_date: datetime = None):
        """Generate a comprehensive weekly summary of email activity with threat intelligence"""
        if emails_data is None:
            emails_data = self.emails_processed

        if not emails_data:
            return {
                'total_emails': 0,
                'summary': "No emails processed this week.",
                'details': {}
            }

        # Default to last 7 days if no start date provided
        if start_date is None:
            start_date = datetime.now() - timedelta(days=7)

        end_date = start_date + timedelta(days=7)

        # Filter emails for the week
        week_emails = [
            email for email in emails_data
            if start_date <= email['timestamp'] <= end_date
        ]

        if not week_emails:
            return {
                'total_emails': 0,
                'summary': f"No emails processed between {start_date.strftime('%Y-%m-%d')} and {end_date.strftime('%Y-%m-%d')}.",
                'details': {}
            }

        # Basic statistics
        total_emails = len(week_emails)
        categories = [email['category'] for email in week_emails]
        category_counts = Counter(categories)

        # Sender analysis
        senders = [email['from'] for email in week_emails]
        sender_counts = Counter(senders)
        top_senders = sender_counts.most_common(5)

        # Daily breakdown
        daily_counts = defaultdict(int)
        daily_categories = defaultdict(lambda: defaultdict(int))

        for email in week_emails:
            day = email['timestamp'].strftime('%Y-%m-%d')
            daily_counts[day] += 1
            daily_categories[day][email['category']] += 1

        # Time analysis
        hourly_distribution = defaultdict(int)
        for email in week_emails:
            hour = email['timestamp'].hour
            hourly_distribution[hour] += 1

        # Peak hour
        peak_hour = max(hourly_distribution.items(), key=lambda x: x[1]) if hourly_distribution else (0, 0)

        # Risk analysis with threat intelligence
        important_emails = [email for email in week_emails if email['category'].lower() == 'important']
        suspicious_emails = [email for email in week_emails if email['category'].lower() == 'suspicious']

        # Count emails with threat intelligence data
        threat_intel_emails = [email for email in week_emails if email.get('threat_intelligence')]
        malicious_emails = [email for email in week_emails
                            if email.get('threat_intelligence', {}).get('is_malicious', False)]

        # Confidence analysis
        avg_confidence = sum(email['confidence'] for email in week_emails) / len(week_emails)
        high_confidence = len([email for email in week_emails if email['confidence'] > 0.8])
        low_confidence = len([email for email in week_emails if email['confidence'] < 0.5])

        # Generate summary text
        summary_parts = []
        summary_parts.append(
            f"📊 Weekly Email Summary ({start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')})")
        summary_parts.append(f"Total emails processed: {total_emails}")

        if category_counts:
            summary_parts.append("\nCategory Breakdown:")
            for category, count in category_counts.most_common():
                percentage = (count / total_emails) * 100
                summary_parts.append(f"• {category}: {count} emails ({percentage:.1f}%)")

        if important_emails:
            summary_parts.append(f"\n🔥 {len(important_emails)} Important emails requiring attention")

        if suspicious_emails:
            summary_parts.append(f"\n⚠️ {len(suspicious_emails)} Suspicious emails detected")

        if malicious_emails:
            summary_parts.append(f"\n🚨 {len(malicious_emails)} MALICIOUS emails detected by threat intelligence")

        if threat_intel_emails:
            summary_parts.append(f"\n🛡️ {len(threat_intel_emails)} emails analyzed with threat intelligence")

        if top_senders:
            summary_parts.append(f"\n📧 Top Senders:")
            for sender, count in top_senders:
                summary_parts.append(f"• {sender}: {count} emails")

        summary_parts.append(f"\n⏰ Peak Activity: {peak_hour[0]:02d}:00 ({peak_hour[1]} emails)")
        summary_parts.append(f"🎯 Average Confidence: {avg_confidence:.1%}")

        if daily_counts:
            busiest_day = max(daily_counts.items(), key=lambda x: x[1])
            summary_parts.append(f"📅 Busiest Day: {busiest_day[0]} ({busiest_day[1]} emails)")

        summary_text = "\n".join(summary_parts)

        return {
            'total_emails': total_emails,
            'summary': summary_text,
            'details': {
                'category_counts': dict(category_counts),
                'daily_counts': dict(daily_counts),
                'daily_categories': dict(daily_categories),
                'hourly_distribution': dict(hourly_distribution),
                'top_senders': top_senders,
                'important_emails': important_emails,
                'suspicious_emails': suspicious_emails,
                'malicious_emails': malicious_emails,
                'threat_intel_emails': threat_intel_emails,
                'avg_confidence': avg_confidence,
                'high_confidence_count': high_confidence,
                'low_confidence_count': low_confidence,
                'peak_hour': peak_hour,
                'date_range': (start_date, end_date)
            }
        }

    def export_weekly_summary_csv(self, summary_data: Dict, emails_data: List[Dict] = None):
        """Export weekly summary data to CSV format with threat intelligence data"""
        if emails_data is None:
            emails_data = self.emails_processed

        if not summary_data or not emails_data:
            return None

        start_date, end_date = summary_data['details']['date_range']

        # Filter emails for the week
        week_emails = [
            email for email in emails_data
            if start_date <= email['timestamp'] <= end_date
        ]

        if not week_emails:
            return None

        # Create DataFrame
        df = pd.DataFrame(week_emails)

        # Add additional columns for analysis
        df['date'] = df['timestamp'].dt.date
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.day_name()

        # Add threat intelligence columns
        df['has_threat_intel'] = df['threat_intelligence'].notna()
        df['is_malicious'] = df['threat_intelligence'].apply(
            lambda x: x.get('is_malicious', False) if x else False
        )
        df['is_suspicious_threat'] = df['threat_intelligence'].apply(
            lambda x: x.get('is_suspicious', False) if x else False
        )
        df['threat_risk_score'] = df['threat_intelligence'].apply(
            lambda x: x.get('risk_score', 0.0) if x else 0.0
        )

        return df

    def export_data_to_csv(self, filename=None):
        """Export email data to CSV"""
        if not self.emails_processed:
            return None

        try:
            # Create DataFrame
            df = pd.DataFrame(self.emails_processed)

            # Add additional columns
            df['date'] = df['timestamp'].dt.date
            df['hour'] = df['timestamp'].dt.hour
            df['day_of_week'] = df['timestamp'].dt.day_name()

            # Generate filename with timestamp if not provided
            if filename is None:
                filename = f"email_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

            # Save to CSV
            df.to_csv(filename, index=False)
            return filename, len(df)

        except Exception as e:
            self.logger.error(f"Export failed: {e}")
            return None

    def clear_data(self):
        """Clear all stored email data"""
        self.emails_processed = []
        self.total_emails = 0
        self.important_count = 0
        self.suspicious_count = 0
        self.malicious_count = 0
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