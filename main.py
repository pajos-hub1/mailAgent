import asyncio
import logging
from dotenv import load_dotenv
import os
import signal
import sys
import threading
import time
from datetime import datetime, timedelta
import pandas as pd
from typing import List, Dict, Any
from collections import Counter, defaultdict

from email_fetch.fetcher import EmailFetcher
from analysis.classifier import EmailClassifier
from notify.notifier import TwilioNotifier
from utils.helpers import setup_logging, display_welcome_message, display_help


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

        # For thread-safe console output
        self.print_lock = threading.Lock()

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

    async def process_new_emails(self):
        """Process only new emails in the inbox"""
        try:
            new_emails = await self.fetcher.fetch_new_emails()

            if not new_emails:
                self.logger.info("No new emails found.")
                return

            self.logger.info(f"{len(new_emails)} new email(s) found.")

            # Thread-safe printing
            with self.print_lock:
                print("\r", end="")
                print(f"\n{len(new_emails)} new email(s) detected:")

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

                    with self.print_lock:
                        self._print_email_summary(email, classification)

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

            # Reprint the prompt
            with self.print_lock:
                print("📩 EmailBot > ", end="", flush=True)

        except Exception as e:
            self.logger.error(f"Error in email processing: {e}", exc_info=True)

    async def _send_notification(self, email, classification):
        """Send SMS notification if needed"""
        if not self.notifier:
            return

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
                    with self.print_lock:
                        if threat_intel and threat_intel.get('threat_indicators'):
                            print(
                                f"📱 SMS sent for {notification_type} email from {email.get('from', 'Unknown')} (Threat detected)")
                        else:
                            print(f"📱 SMS sent for {notification_type} email from {email.get('from', 'Unknown')}")
                else:
                    self.logger.error(f"Failed to send SMS for {notification_type} email")

        except asyncio.TimeoutError:
            self.logger.error(f"SMS notification timed out for {category} email")
            with self.print_lock:
                print(f"⏰ SMS notification timed out for {category} email")
        except Exception as e:
            self.logger.error(f"Error sending notification: {e}")

    def _print_email_summary(self, email, classification):
        """Print enhanced email notification with threat intelligence info"""
        print("\n" + "=" * 50)
        print(f"📨 From: {email.get('from', 'Unknown Sender')}")
        print(f"📝 Subject: {email.get('subject', 'No Subject')}")
        print(f"🏷️ Category: {classification.get('category', 'Unknown')}")
        print(f"🔍 Confidence: {classification.get('confidence', 0.0):.1%}")

        # Display threat intelligence information
        threat_intel = classification.get('details', {}).get('threat_intelligence')
        if threat_intel:
            print(f"🛡️ Threat Intelligence:")
            print(f"   Risk Score: {threat_intel.get('risk_score', 0.0):.2f}")
            if threat_intel.get('is_malicious'):
                print("   ⚠️ MALICIOUS EMAIL DETECTED!")
            elif threat_intel.get('is_suspicious'):
                print("   ⚠️ Suspicious sender detected")

            if threat_intel.get('threat_indicators'):
                print("   Indicators:")
                for indicator in threat_intel['threat_indicators']:
                    print(f"   • {indicator}")

        # Display rule matches
        rule_matches = classification.get('details', {}).get('rule_matches', [])
        if rule_matches:
            print(f"📋 Rule Matches:")
            for match in rule_matches[:3]:  # Show first 3 matches
                print(f"   • {match}")

        print("=" * 50)

    def generate_weekly_summary(self, emails_data: List[Dict], start_date: datetime = None):
        """Generate a comprehensive weekly summary of email activity with threat intelligence"""
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

    def export_weekly_summary_csv(self, summary_data: Dict, emails_data: List[Dict]):
        """Export weekly summary data to CSV format with threat intelligence data"""
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

    def display_weekly_summary(self, start_date: datetime = None):
        """Display weekly summary in console with threat intelligence"""
        summary = self.generate_weekly_summary(self.emails_processed, start_date)

        with self.print_lock:
            print("\n" + "=" * 80)
            print(summary['summary'])

            if summary['total_emails'] > 0:
                details = summary['details']

                # Show malicious emails first (highest priority)
                if details.get('malicious_emails'):
                    print(f"\n🚨 MALICIOUS EMAILS ({len(details['malicious_emails'])}):")
                    print("-" * 50)
                    for email in details['malicious_emails'][:3]:  # Show first 3
                        print(f"• From: {email['from']}")
                        print(f"  Subject: {email['subject']}")
                        print(f"  Time: {email['timestamp'].strftime('%Y-%m-%d %H:%M')}")
                        threat_intel = email.get('threat_intelligence', {})
                        if threat_intel.get('threat_indicators'):
                            print(f"  Threats: {', '.join(threat_intel['threat_indicators'][:2])}")
                        print()

                # Show important emails
                if details['important_emails']:
                    print(f"\n🔥 IMPORTANT EMAILS ({len(details['important_emails'])}):")
                    print("-" * 50)
                    for email in details['important_emails'][:3]:  # Show first 3
                        print(f"• From: {email['from']}")
                        print(f"  Subject: {email['subject']}")
                        print(f"  Time: {email['timestamp'].strftime('%Y-%m-%d %H:%M')}")
                        print()

                # Show suspicious emails
                if details['suspicious_emails']:
                    print(f"\n⚠️ SUSPICIOUS EMAILS ({len(details['suspicious_emails'])}):")
                    print("-" * 50)
                    for email in details['suspicious_emails'][:3]:  # Show first 3
                        print(f"• From: {email['from']}")
                        print(f"  Subject: {email['subject']}")
                        print(f"  Time: {email['timestamp'].strftime('%Y-%m-%d %H:%M')}")
                        print()

                # Show threat intelligence summary
                if details.get('threat_intel_emails'):
                    print(f"\n🛡️ THREAT INTELLIGENCE SUMMARY:")
                    print("-" * 50)
                    print(f"• Emails analyzed: {len(details['threat_intel_emails'])}")
                    if details.get('malicious_emails'):
                        print(f"• Malicious detected: {len(details['malicious_emails'])}")
                    print()

                # Show daily breakdown
                if details['daily_counts']:
                    print("\n📅 DAILY BREAKDOWN:")
                    print("-" * 30)
                    for day, count in sorted(details['daily_counts'].items()):
                        print(f"• {day}: {count} emails")

                # Show hourly distribution (top 5 hours)
                if details['hourly_distribution']:
                    print("\n⏰ TOP ACTIVE HOURS:")
                    print("-" * 30)
                    sorted_hours = sorted(details['hourly_distribution'].items(), key=lambda x: x[1], reverse=True)
                    for hour, count in sorted_hours[:5]:
                        print(f"• {hour:02d}:00: {count} emails")

            print("=" * 80)

    async def monitor_emails(self):
        """Continuous email monitoring"""
        self.monitoring_active = True
        self.running = True

        self.logger.info(f"Starting monitoring (interval: {self.polling_interval}s)")
        with self.print_lock:
            print(f"\n🔍 Monitoring started (checking every {self.polling_interval}s)")
            if self.notifier:
                print("📱 SMS notifications enabled for important/suspicious emails")
            else:
                print("⚠️ SMS notifications disabled (Twilio not configured)")
            print("🛡️ Threat intelligence enabled via EmailRep.io")

        while self.running:
            if self.monitoring_active:
                await self.process_new_emails()

            # Wait for the polling interval
            await asyncio.sleep(self.polling_interval)

        self.logger.info("Monitoring stopped")

    def _handle_shutdown(self, sig, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {sig}, stopping...")
        with self.print_lock:
            print("\n🛑 Shutting down...")
        self.running = False

    def handle_command(self, command):
        """Process user commands"""
        if not command:
            return False

        cmd = command.lower().strip()

        with self.print_lock:
            if cmd == "help":
                self._display_enhanced_help()
            elif cmd == "status":
                self._display_status()
            elif cmd == "pause":
                self.monitoring_active = False
                print("\n⏸ Monitoring paused")
            elif cmd == "resume":
                self.monitoring_active = True
                print("\n▶️ Monitoring resumed")
            elif cmd == "test-sms":
                if self.notifier:
                    asyncio.create_task(self._test_sms())
                else:
                    print("\n❌ SMS notifications not configured")
            elif cmd == "summary":
                self.display_weekly_summary()
            elif cmd.startswith("summary "):
                # Handle date-specific summaries
                date_str = cmd.replace("summary ", "").strip()
                try:
                    if date_str == "week":
                        start_date = datetime.now() - timedelta(days=7)
                    elif date_str == "month":
                        start_date = datetime.now() - timedelta(days=30)
                    elif date_str == "today":
                        start_date = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
                    else:
                        # Try to parse as date (YYYY-MM-DD)
                        start_date = datetime.strptime(date_str, "%Y-%m-%d")

                    self.display_weekly_summary(start_date)
                except ValueError:
                    print(f"\n❌ Invalid date format. Use YYYY-MM-DD, 'week', 'month', or 'today'")
            elif cmd == "stats":
                self._display_stats()
            elif cmd == "threats":
                self._display_threat_summary()
            elif cmd == "list":
                self._display_recent_emails()
            elif cmd == "export":
                self._export_data()
            elif cmd == "clear":
                self._clear_data()
            elif cmd == "exit":
                self.running = False
                print("\n👋 Goodbye!")
                return True
            else:
                print("\n❌ Unknown command. Type 'help' for options.")
        return False

    def _display_enhanced_help(self):
        """Display enhanced help with new commands"""
        print("\n" + "=" * 60)
        print("📧 EMAIL MONITORING AGENT - COMMAND HELP")
        print("=" * 60)
        print("MONITORING CONTROLS:")
        print("  status      - Show current monitoring status")
        print("  pause       - Pause email monitoring")
        print("  resume      - Resume email monitoring")
        print("  test-sms    - Send a test SMS notification")
        print()
        print("DATA & ANALYTICS:")
        print("  stats       - Show email statistics")
        print("  threats     - Show threat intelligence summary")
        print("  summary     - Show weekly email summary (last 7 days)")
        print("  summary week - Show last 7 days summary")
        print("  summary month - Show last 30 days summary")
        print("  summary today - Show today's summary")
        print("  summary YYYY-MM-DD - Show summary from specific date")
        print("  list        - Show recent emails")
        print("  export      - Export data to CSV")
        print("  clear       - Clear all stored data")
        print()
        print("GENERAL:")
        print("  help        - Show this help message")
        print("  exit        - Exit the application")
        print("=" * 60)

    def _display_status(self):
        """Display detailed status information"""
        status = "ACTIVE ✅" if self.monitoring_active else "PAUSED ⏸"
        sms_status = "ENABLED 📱" if self.notifier else "DISABLED ❌"

        print(f"\n📊 SYSTEM STATUS")
        print("-" * 40)
        print(f"Monitoring: {status}")
        print(f"SMS Notifications: {sms_status}")
        print(f"Threat Intelligence: ENABLED 🛡️")
        print(f"Polling Interval: {self.polling_interval} seconds")
        print(f"Total Emails Processed: {self.total_emails}")
        print(f"Important Emails: {self.important_count}")
        print(f"Suspicious Emails: {self.suspicious_count}")
        print(f"Malicious Emails: {self.malicious_count}")

        if self.emails_processed:
            latest = max(self.emails_processed, key=lambda x: x['timestamp'])
            print(f"Last Email: {latest['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")

    def _display_stats(self):
        """Display email statistics"""
        if not self.emails_processed:
            print("\n📊 No email statistics available yet.")
            return

        print(f"\n📊 EMAIL STATISTICS")
        print("-" * 40)
        print(f"Total Processed: {len(self.emails_processed)}")

        # Category breakdown
        categories = Counter(email['category'] for email in self.emails_processed)
        print("\nCategory Breakdown:")
        for category, count in categories.most_common():
            percentage = (count / len(self.emails_processed)) * 100
            print(f"  {category}: {count} ({percentage:.1f}%)")

        # Threat intelligence stats
        threat_emails = [email for email in self.emails_processed if email.get('threat_intelligence')]
        if threat_emails:
            print(f"\n🛡️ Threat Intelligence:")
            print(f"  Emails analyzed: {len(threat_emails)}")
            malicious = len([email for email in threat_emails
                             if email['threat_intelligence'].get('is_malicious', False)])
            suspicious_threat = len([email for email in threat_emails
                                     if email['threat_intelligence'].get('is_suspicious', False)])
            print(f"  Malicious detected: {malicious}")
            print(f"  Suspicious detected: {suspicious_threat}")

        # Top senders
        senders = Counter(email['from'] for email in self.emails_processed)
        print(f"\nTop 5 Senders:")
        for sender, count in senders.most_common(5):
            print(f"  {sender}: {count} emails")

        # Time range
        if self.emails_processed:
            timestamps = [email['timestamp'] for email in self.emails_processed]
            earliest = min(timestamps).strftime('%Y-%m-%d %H:%M')
            latest = max(timestamps).strftime('%Y-%m-%d %H:%M')
            print(f"\nTime Range: {earliest} to {latest}")

    def _display_threat_summary(self):
        """Display threat intelligence summary"""
        if not self.emails_processed:
            print("\n🛡️ No threat intelligence data available yet.")
            return

        threat_emails = [email for email in self.emails_processed if email.get('threat_intelligence')]

        if not threat_emails:
            print("\n🛡️ No emails have been analyzed with threat intelligence yet.")
            return

        print(f"\n🛡️ THREAT INTELLIGENCE SUMMARY")
        print("-" * 50)
        print(f"Total emails analyzed: {len(threat_emails)}")

        malicious_emails = [email for email in threat_emails
                            if email['threat_intelligence'].get('is_malicious', False)]
        suspicious_emails = [email for email in threat_emails
                             if email['threat_intelligence'].get('is_suspicious', False)]

        print(f"Malicious emails detected: {len(malicious_emails)}")
        print(f"Suspicious emails detected: {len(suspicious_emails)}")

        if malicious_emails:
            print(f"\n🚨 MALICIOUS SENDERS:")
            malicious_senders = Counter(email['from'] for email in malicious_emails)
            for sender, count in malicious_senders.most_common(5):
                print(f"  • {sender}: {count} emails")

        # Show most common threat indicators
        all_indicators = []
        for email in threat_emails:
            indicators = email['threat_intelligence'].get('threat_indicators', [])
            all_indicators.extend(indicators)

        if all_indicators:
            print(f"\n⚠️ COMMON THREAT INDICATORS:")
            indicator_counts = Counter(all_indicators)
            for indicator, count in indicator_counts.most_common(5):
                print(f"  • {indicator}: {count} times")

    def _display_recent_emails(self, limit=10):
        """Display recent emails"""
        if not self.emails_processed:
            print("\n📧 No emails to display.")
            return

        recent_emails = sorted(self.emails_processed, key=lambda x: x['timestamp'], reverse=True)[:limit]

        print(f"\n📧 RECENT EMAILS (Last {min(limit, len(recent_emails))})")
        print("=" * 80)

        for i, email in enumerate(recent_emails, 1):
            print(f"{i}. [{email['timestamp'].strftime('%m-%d %H:%M')}] {email['category']}")
            print(f"   From: {email['from']}")
            print(f"   Subject: {email['subject']}")
            print(f"   Confidence: {email['confidence']:.1%}")
            print("-" * 80)

    def _export_data(self):
        """Export email data to CSV"""
        if not self.emails_processed:
            print("\n📤 No data to export.")
            return

        try:
            # Create DataFrame
            df = pd.DataFrame(self.emails_processed)

            # Add additional columns
            df['date'] = df['timestamp'].dt.date
            df['hour'] = df['timestamp'].dt.hour
            df['day_of_week'] = df['timestamp'].dt.day_name()

            # Generate filename with timestamp
            filename = f"email_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

            # Save to CSV
            df.to_csv(filename, index=False)
            print(f"\n📤 Data exported to {filename}")
            print(f"   Total records: {len(df)}")

        except Exception as e:
            print(f"\n❌ Export failed: {e}")

    def _clear_data(self):
        """Clear all stored email data"""
        self.emails_processed = []
        self.total_emails = 0
        self.important_count = 0
        self.suspicious_count = 0
        print("\n🗑️ All data cleared.")

    async def _test_sms(self):
        """Test SMS functionality"""
        try:
            success = await asyncio.wait_for(
                self.notifier.send_test_sms(),
                timeout=15.0
            )
            with self.print_lock:
                if success:
                    print("\n✅ Test SMS sent successfully!")
                else:
                    print("\n❌ Test SMS failed")
        except asyncio.TimeoutError:
            with self.print_lock:
                print("\n⏰ Test SMS timed out")
        except Exception as e:
            self.logger.error(f"Test SMS error: {e}")
            with self.print_lock:
                print(f"\n❌ Test SMS error: {e}")

    def input_listener(self):
        """Handle user input in a separate thread"""
        while self.running:
            try:
                command = input()
                should_exit = self.handle_command(command)

                if not should_exit:
                    with self.print_lock:
                        print("📩 EmailBot > ", end="", flush=True)
                else:
                    break

            except EOFError:
                with self.print_lock:
                    print("\n👋 Goodbye!")
                self.running = False
                break
            except KeyboardInterrupt:
                with self.print_lock:
                    print("\n👋 Goodbye!")
                self.running = False
                break

    async def run(self, continuous=True):
        """Main run method"""
        self.logger.info("Starting Email Monitoring Agent")
        self.running = True

        # Setup signal handlers
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, self._handle_shutdown)

        display_welcome_message()
        self._display_enhanced_help()

        with self.print_lock:
            print("\n📩 EmailBot > ", end="", flush=True)

        if continuous:
            # Start input listener in a separate thread
            input_thread = threading.Thread(target=self.input_listener)
            input_thread.daemon = True
            input_thread.start()

            # Run email monitoring in the main asyncio loop
            await self.monitor_emails()

            # If we exit the monitoring loop, wait for the input thread to finish
            input_thread.join(timeout=1.0)
        else:
            await self.process_new_emails()


async def main():
    """Entry point"""
    import argparse
    parser = argparse.ArgumentParser(description='AI Email Monitoring Agent')
    parser.add_argument('--once', action='store_true', help='Run once and exit')
    args = parser.parse_args()

    agent = EmailMonitoringAgent()
    await agent.run(continuous=not args.once)


if __name__ == "__main__":
    asyncio.run(main())