import asyncio
import signal
import sys
import threading
from datetime import datetime, timedelta
from collections import Counter

from core.email_agent import EmailMonitoringAgent
from utils.helpers import display_welcome_message


class EmailMonitoringCLI:
    def __init__(self):
        self.agent = EmailMonitoringAgent()
        self.print_lock = threading.Lock()
        self.pending_feedback = {}  # Store emails waiting for feedback

    def _handle_shutdown(self, sig, frame):
        """Handle shutdown signals"""
        self.agent.logger.info(f"Received signal {sig}, stopping...")
        with self.print_lock:
            print("\n🛑 Shutting down...")
        self.agent.stop_monitoring()

    def _print_email_summary(self, email, classification):
        """Print email notification"""
        email_id = email.get('id', 'unknown')

        print("\n" + "=" * 50)
        print(f"📨 From: {email.get('from', 'Unknown Sender')}")
        print(f"📝 Subject: {email.get('subject', 'No Subject')}")
        print(f"🏷️ Category: {classification.get('category', 'Unknown')}")
        print(f"🔍 Confidence: {classification.get('confidence', 0.0):.1%}")

        # Display classification details
        details = classification.get('details', {})
        if details.get('all_scores'):
            print("📊 All Scores:")
            for category, score in details.get('all_scores', {}).items():
                print(f"   • {category}: {score:.2%}")

        # Add feedback prompt
        print("-" * 50)
        print("✅ Feedback Options:")
        print("   1. Correct classification")
        print("   2. Should be 'important'")
        print("   3. Should be 'suspicious'")
        print("   4. Should be 'normal'")
        print("   (Press Enter to skip feedback)")

        # Store in pending feedback
        self.pending_feedback[email_id] = {
            'email': email,
            'classification': classification,
            'timestamp': datetime.now()
        }

        print("=" * 50)

    def email_callback(self, email, classification):
        """Callback for new emails - handles UI updates"""
        with self.print_lock:
            print("\r", end="")  # Clear current line
            self._print_email_summary(email, classification)
            print("📩 EmailBot > ", end="", flush=True)

    def status_callback(self, status_type, data):
        """Callback for status updates - handles monitoring status"""
        with self.print_lock:
            if status_type == "monitoring_started":
                print(f"\n🔍 Monitoring started (checking every {data['interval']}s)")
                if data['sms_enabled']:
                    print("📱 SMS notifications enabled for important/suspicious emails")
                else:
                    print("⚠️ SMS notifications disabled (Twilio not configured)")
                print("🤖 Zero-shot classification enabled")
                print("🧠 Learning system active")
            elif status_type == "monitoring_stopped":
                print("\n🛑 Monitoring stopped")

    def handle_command(self, command):
        """Process user commands"""
        if not command:
            return False

        # Check if this is feedback for a pending email
        if command.isdigit() and 1 <= int(command) <= 4:
            return self._handle_feedback(int(command))

        cmd = command.lower().strip()

        with self.print_lock:
            if cmd == "help":
                self._display_help()
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
            elif cmd == "stats":
                self._display_stats()
            elif cmd == "list":
                self._display_recent_emails()
            elif cmd == "clear":
                self._clear_data()
            elif cmd == "learning":
                self._display_learning_stats()
            elif cmd == "exit":
                self.agent.stop_monitoring()
                print("\n👋 Goodbye!")
                return True
            else:
                print("\n❌ Unknown command. Type 'help' for options.")
        return False

    def _handle_feedback(self, choice):
        """Handle user feedback on email classification"""
        if not self.pending_feedback:
            print("\n❌ No emails waiting for feedback")
            return False

        # Get the most recent pending feedback
        email_id, data = sorted(
            self.pending_feedback.items(),
            key=lambda x: x[1]['timestamp'],
            reverse=True
        )[0]

        email = data['email']
        classification = data['classification']

        # Process feedback
        if choice == 1:
            # Correct classification
            is_correct = True
            user_category = classification['category']
            feedback_msg = "✅ Marked as correct"
        else:
            # Incorrect classification
            is_correct = False
            if choice == 2:
                user_category = 'important'
            elif choice == 3:
                user_category = 'suspicious'
            else:  # choice == 4
                user_category = 'normal'
            feedback_msg = f"✅ Corrected to '{user_category}'"

        # Save feedback
        success = self.agent.classifier.collect_user_feedback(
            email, classification, user_category, is_correct
        )

        if success:
            print(f"\n{feedback_msg} - Feedback saved!")
            # Remove from pending feedback
            del self.pending_feedback[email_id]
        else:
            print("\n❌ Failed to save feedback")

        return False

    def _display_help(self):
        """Display help with commands"""
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
        print("  list        - Show recent emails")
        print("  learning    - Show learning system statistics")
        print("  clear       - Clear all stored data")
        print()
        print("FEEDBACK:")
        print("  1-4         - Provide feedback on the most recent email")
        print("                1: Correct classification")
        print("                2: Should be 'important'")
        print("                3: Should be 'suspicious'")
        print("                4: Should be 'normal'")
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

        # Get model info
        model_info = self.agent.classifier.get_model_info()
        print(f"Base Model: {model_info['name']}")
        print(f"Learning: {'Enabled ✅' if model_info.get('learning_enabled') else 'Disabled ❌'}")

        if model_info.get('learned_model_trained'):
            print(f"Learned Model: v{model_info.get('learned_model_version')} (Trained)")
        else:
            print("Learned Model: Not yet trained")

        print(f"Polling Interval: {status['polling_interval']} seconds")
        print(f"Total Emails Processed: {status['total_emails']}")
        print(f"Important Emails: {status['important_count']}")
        print(f"Suspicious Emails: {status['suspicious_count']}")

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

        # Top senders
        print(f"\nTop 5 Senders:")
        for sender, count in stats['top_senders']:
            print(f"  {sender}: {count} emails")

        # Time range
        if stats['time_range']['earliest'] and stats['time_range']['latest']:
            earliest = stats['time_range']['earliest'].strftime('%Y-%m-%d %H:%M')
            latest = stats['time_range']['latest'].strftime('%Y-%m-%d %H:%M')
            print(f"\nTime Range: {earliest} to {latest}")

    def _display_learning_stats(self):
        """Display learning system statistics"""
        stats = self.agent.classifier.get_learning_stats()

        print(f"\n🧠 LEARNING SYSTEM STATISTICS")
        print("-" * 40)
        print(f"Model Version: {stats['model_version']}")
        print(f"Model Trained: {'Yes ✅' if stats['is_trained'] else 'No ❌'}")

        feedback_stats = stats.get('feedback_stats', {})

        if feedback_stats:
            print(f"\nFeedback Statistics:")
            print(f"  Total Feedback: {feedback_stats.get('total_feedback', 0)}")
            print(f"  Overall Accuracy: {feedback_stats.get('overall_accuracy', 0):.1f}%")

            print(f"\nCategory Accuracy:")
            for category, cat_stats in feedback_stats.get('category_stats', {}).items():
                print(
                    f"  {category}: {cat_stats.get('accuracy', 0):.1f}% ({cat_stats.get('correct', 0)}/{cat_stats.get('total', 0)})")

            print(f"\nTraining Examples: {feedback_stats.get('training_examples', 0)}")
            print(f"New Examples Available: {stats.get('available_training_data', 0)}")
        else:
            print("\nNo feedback collected yet.")

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
        self._display_help()

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
            print("Checking for new emails...")
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
