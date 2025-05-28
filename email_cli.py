import asyncio
import signal
import sys
import threading
from datetime import datetime, timedelta
from collections import Counter

from email_agent import EmailMonitoringAgent
from utils.helpers import display_welcome_message


class EmailMonitoringCLI:
    def __init__(self):
        self.agent = EmailMonitoringAgent()
        self.print_lock = threading.Lock()

    def _handle_shutdown(self, sig, frame):
        """Handle shutdown signals"""
        self.agent.logger.info(f"Received signal {sig}, stopping...")
        with self.print_lock:
            print("\n🛑 Shutting down...")
        self.agent.stop_monitoring()

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

    def _print_sms_notification(self, email, notification_type, success, threat_intel=None):
        """Print SMS notification status"""
        if success:
            if threat_intel and threat_intel.get('threat_indicators'):
                print(
                    f"📱 SMS sent for {notification_type} email from {email.get('from', 'Unknown')} (Threat detected)")
            else:
                print(f"📱 SMS sent for {notification_type} email from {email.get('from', 'Unknown')}")
        else:
            print(f"❌ Failed to send SMS for {notification_type} email")

    def email_callback(self, email, classification):
        """Callback for new emails - handles UI updates"""
        with self.print_lock:
            print("\r", end="")  # Clear current line
            self._print_email_summary(email, classification)

    def status_callback(self, status_type, data):
        """Callback for status updates - handles monitoring status"""
        with self.print_lock:
            if status_type == "monitoring_started":
                print(f"\n🔍 Monitoring started (checking every {data['interval']}s)")
                if data['sms_enabled']:
                    print("📱 SMS notifications enabled for important/suspicious emails")
                else:
                    print("⚠️ SMS notifications disabled (Twilio not configured)")
                print("🛡️ Threat intelligence enabled via EmailRep.io")
            elif status_type == "monitoring_stopped":
                print("\n🛑 Monitoring stopped")

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
                self.agent.pause_monitoring()
                print("\n⏸ Monitoring paused")
            elif cmd == "resume":
                self.agent.resume_monitoring()
                print("\n▶️ Monitoring resumed")
            elif cmd == "test-sms":
                asyncio.create_task(self._test_sms())
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
                self.agent.stop_monitoring()
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
        status = self.agent.get_status()

        monitoring_status = "ACTIVE ✅" if status['monitoring_active'] else "PAUSED ⏸"
        sms_status = "ENABLED 📱" if status['sms_enabled'] else "DISABLED ❌"

        print(f"\n📊 SYSTEM STATUS")
        print("-" * 40)
        print(f"Monitoring: {monitoring_status}")
        print(f"SMS Notifications: {sms_status}")
        print(f"Threat Intelligence: ENABLED 🛡️")
        print(f"Polling Interval: {status['polling_interval']} seconds")
        print(f"Total Emails Processed: {status['total_emails']}")
        print(f"Important Emails: {status['important_count']}")
        print(f"Suspicious Emails: {status['suspicious_count']}")
        print(f"Malicious Emails: {status['malicious_count']}")

        if status['latest_email']:
            print(f"Last Email: {status['latest_email'].strftime('%Y-%m-%d %H:%M:%S')}")

    def _display_stats(self):
        """Display email statistics"""
        stats = self.agent.get_statistics()

        if not stats:
            print("\n📊 No email statistics available yet.")
            return

        print(f"\n📊 EMAIL STATISTICS")
        print("-" * 40)
        print(f"Total Processed: {stats['total_processed']}")

        # Category breakdown
        print("\nCategory Breakdown:")
        for category, count in stats['categories'].items():
            percentage = (count / stats['total_processed']) * 100
            print(f"  {category}: {count} ({percentage:.1f}%)")

        # Threat intelligence stats
        if stats['threat_intel']['analyzed'] > 0:
            print(f"\n🛡️ Threat Intelligence:")
            print(f"  Emails analyzed: {stats['threat_intel']['analyzed']}")
            print(f"  Malicious detected: {stats['threat_intel']['malicious']}")
            print(f"  Suspicious detected: {stats['threat_intel']['suspicious']}")

        # Top senders
        print(f"\nTop 5 Senders:")
        for sender, count in stats['top_senders']:
            print(f"  {sender}: {count} emails")

        # Time range
        if stats['time_range']['earliest'] and stats['time_range']['latest']:
            earliest = stats['time_range']['earliest'].strftime('%Y-%m-%d %H:%M')
            latest = stats['time_range']['latest'].strftime('%Y-%m-%d %H:%M')
            print(f"\nTime Range: {earliest} to {latest}")

    def _display_threat_summary(self):
        """Display threat intelligence summary"""
        threat_data = self.agent.get_threat_summary()

        if not threat_data:
            print("\n🛡️ No threat intelligence data available yet.")
            return

        print(f"\n🛡️ THREAT INTELLIGENCE SUMMARY")
        print("-" * 50)
        print(f"Total emails analyzed: {threat_data['total_analyzed']}")
        print(f"Malicious emails detected: {threat_data['malicious_count']}")
        print(f"Suspicious emails detected: {threat_data['suspicious_count']}")

        if threat_data['malicious_senders']:
            print(f"\n🚨 MALICIOUS SENDERS:")
            for sender, count in threat_data['malicious_senders']:
                print(f"  • {sender}: {count} emails")

        # Show most common threat indicators
        if threat_data['threat_indicators']:
            print(f"\n⚠️ COMMON THREAT INDICATORS:")
            for indicator, count in threat_data['threat_indicators']:
                print(f"  • {indicator}: {count} times")

    def _display_recent_emails(self, limit=10):
        """Display recent emails"""
        recent_emails = self.agent.get_recent_emails(limit)

        if not recent_emails:
            print("\n📧 No emails to display.")
            return

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
        result = self.agent.export_data_to_csv()

        if not result:
            print("\n📤 No data to export.")
            return

        filename, record_count = result
        print(f"\n📤 Data exported to {filename}")
        print(f"   Total records: {record_count}")

    def _clear_data(self):
        """Clear all stored email data"""
        self.agent.clear_data()
        print("\n🗑️ All data cleared.")

    async def _test_sms(self):
        """Test SMS functionality"""
        if not self.agent.notifier:
            with self.print_lock:
                print("\n❌ SMS notifications not configured")
            return

        try:
            success = await self.agent.test_sms()
            with self.print_lock:
                if success:
                    print("\n✅ Test SMS sent successfully!")
                else:
                    print("\n❌ Test SMS failed")
        except Exception as e:
            with self.print_lock:
                print(f"\n❌ Test SMS error: {e}")

    def display_weekly_summary(self, start_date: datetime = None):
        """Display weekly summary in console with threat intelligence"""
        summary = self.agent.generate_weekly_summary(start_date=start_date)

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

    def input_listener(self):
        """Handle user input in a separate thread"""
        while self.agent.running:
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
                self.agent.stop_monitoring()
                break
            except KeyboardInterrupt:
                with self.print_lock:
                    print("\n👋 Goodbye!")
                self.agent.stop_monitoring()
                break

    async def run(self, continuous=True):
        """Main run method"""
        self.agent.logger.info("Starting Email Monitoring Agent")

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
            await self.agent.monitor_emails(
                email_callback=self.email_callback,
                status_callback=self.status_callback
            )

            # If we exit the monitoring loop, wait for the input thread to finish
            input_thread.join(timeout=1.0)
        else:
            # Run once mode
            new_emails = await self.agent.process_new_emails(self.email_callback)
            with self.print_lock:
                if new_emails:
                    print(f"\n✅ Processed {len(new_emails)} new emails")
                else:
                    print("\n✅ No new emails found")


async def main():
    """Entry point"""
    import argparse
    parser = argparse.ArgumentParser(description='AI Email Monitoring Agent')
    parser.add_argument('--once', action='store_true', help='Run once and exit')
    args = parser.parse_args()

    cli = EmailMonitoringCLI()
    await cli.run(continuous=not args.once)


if __name__ == "__main__":
    asyncio.run(main())