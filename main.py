import asyncio
import logging
from dotenv import load_dotenv
import os
import signal
import sys
import threading
import time

from email_fetch.fetcher import EmailFetcher
from analysis.classifier import EmailClassifier
from notify.notifier import TwilioNotifier  # Add this import
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
        self.classifier = EmailClassifier()

        # Initialize Twilio notifier
        try:
            # Debug: Check if environment variables are loaded
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
        self.polling_interval = int(os.getenv('POLLING_INTERVAL', 10))  # Default: 10 seconds

        # For thread-safe console output
        self.print_lock = threading.Lock()

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
                # Clear the current line
                print("\r", end="")
                print(f"\n{len(new_emails)} new email(s) detected:")

            # Process all emails first (classify and display)
            email_classifications = []

            for email in new_emails:
                try:
                    classification = self.classifier.classify(email)
                    email_classifications.append((email, classification))

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
                        timeout=30.0  # 30 second timeout for all notifications
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
            if category in ['important', 'suspicious']:
                # Add timeout to prevent hanging
                success = await asyncio.wait_for(
                    self.notifier.send_notification(email, category),
                    timeout=15.0  # 15 second timeout per SMS
                )

                if success:
                    with self.print_lock:
                        print(f"📱 SMS sent for {category} email from {email.get('from', 'Unknown')}")
                else:
                    self.logger.error(f"Failed to send SMS for {category} email")

        except asyncio.TimeoutError:
            self.logger.error(f"SMS notification timed out for {category} email")
            with self.print_lock:
                print(f"⏰ SMS notification timed out for {category} email")
        except Exception as e:
            self.logger.error(f"Error sending notification: {e}")

    def _print_email_summary(self, email, classification):
        """Print simplified email notification without actions"""
        print("\n" + "=" * 50)
        print(f"📨 From: {email.get('from', 'Unknown Sender')}")
        print(f"📝 Subject: {email.get('subject', 'No Subject')}")
        print(f"🏷️ Category: {classification.get('category', 'Unknown')}")
        print(f"🔍 Confidence: {classification.get('confidence', 0.0):.1%}")
        print("=" * 50)

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
        if not command:  # Handle empty input
            return False

        cmd = command.lower().strip()

        with self.print_lock:
            if cmd == "help":
                display_help()
            elif cmd == "status":
                status = "ACTIVE ✅" if self.monitoring_active else "PAUSED ⏸"
                sms_status = "ENABLED 📱" if self.notifier else "DISABLED ❌"
                print(f"\nCurrent Status: {status}")
                print(f"SMS Notifications: {sms_status}")
                print(f"Polling Interval: {self.polling_interval} seconds")
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
            elif cmd == "exit":
                self.running = False
                print("\n👋 Goodbye!")
                return True
            else:
                print("\n❌ Unknown command. Type 'help' for options.")
        return False

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
                # Get input in a blocking way (this is in a separate thread)
                command = input()

                # Process the command
                should_exit = self.handle_command(command)

                # If not exiting, print the prompt again
                if not should_exit:
                    with self.print_lock:
                        print("📩 EmailBot > ", end="", flush=True)
                else:
                    break

            except EOFError:
                # Handle EOF (Ctrl+D)
                with self.print_lock:
                    print("\n👋 Goodbye!")
                self.running = False
                break
            except KeyboardInterrupt:
                # Handle Ctrl+C
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
        display_help()

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