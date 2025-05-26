import asyncio
import logging
import os
from dotenv import load_dotenv
from twilio.rest import Client
from twilio.base.exceptions import TwilioException


class TwilioNotifier:
    def __init__(self):
        """Initialize Twilio SMS notifier for important and suspicious emails only"""
        self.logger = logging.getLogger(__name__)

        # Load environment variables from config directory
        from pathlib import Path

        # Get the absolute path to the credentials.env file
        BASE_DIR = Path(__file__).resolve().parent  # current script's dir (mailAgent/notify/)
        ENV_PATH = BASE_DIR.parent / 'config' / 'credentials.env'  # go one up, into config

        # Load the .env file
        load_dotenv(ENV_PATH)
        self.logger.info(f"Loaded .env from: {ENV_PATH}")
        self._init_twilio()

    def _init_twilio(self):
        """Initialize Twilio client"""
        try:
            self.account_sid = os.getenv('TWILIO_ACCOUNT_SID')
            self.auth_token = os.getenv('TWILIO_AUTH_TOKEN')
            self.from_number = os.getenv('TWILIO_PHONE_NUMBER')
            self.to_number = os.getenv('RECIPIENT_PHONE_NUMBER')

            # Debug logging
            self.logger.info(f"Environment variables check:")
            self.logger.info(f"  TWILIO_ACCOUNT_SID: {'Found' if self.account_sid else 'Missing'}")
            self.logger.info(f"  TWILIO_AUTH_TOKEN: {'Found' if self.auth_token else 'Missing'}")
            self.logger.info(f"  TWILIO_PHONE_NUMBER: {'Found' if self.from_number else 'Missing'}")
            self.logger.info(f"  RECIPIENT_PHONE_NUMBER: {'Found' if self.to_number else 'Missing'}")

            if not all([self.account_sid, self.auth_token, self.from_number, self.to_number]):
                missing = [var for var, val in [
                    ('TWILIO_ACCOUNT_SID', self.account_sid),
                    ('TWILIO_AUTH_TOKEN', self.auth_token),
                    ('TWILIO_PHONE_NUMBER', self.from_number),
                    ('RECIPIENT_PHONE_NUMBER', self.to_number)
                ] if not val]
                raise ValueError(f"Missing environment variables: {', '.join(missing)}")

            self.client = Client(self.account_sid, self.auth_token)
            self.logger.info("Twilio client initialized successfully")

        except Exception as e:
            self.logger.error(f"Failed to initialize Twilio: {e}")
            self.client = None
            raise

    async def send_notification(self, email_data, classification):
        """
        Send SMS notification for important and suspicious emails only

        Args:
            email_data: Dictionary with email info (subject, from, etc.)
            classification: String classification result from your classifier

        Returns:
            bool: True if SMS sent or not needed, False if failed
        """
        if not self.client:
            self.logger.error("Twilio client not available")
            return False

        # Only send SMS for important and suspicious emails
        category = classification.lower()
        if category not in ['important', 'suspicious']:
            self.logger.debug(f"Skipping SMS for category: {category}")
            return True  # Not an error, just not needed

        try:
            message = self._create_message(email_data, category)

            sms = self.client.messages.create(
                body=message,
                from_=self.from_number,
                to=self.to_number
            )

            self.logger.info(f"SMS sent for {category} email. SID: {sms.sid}")
            return True

        except TwilioException as e:
            self.logger.error(f"Twilio error sending SMS: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error sending SMS notification: {e}")
            return False

    def _create_message(self, email_data, category):
        """Create SMS message content"""
        subject = email_data.get('subject', 'No Subject')[:50]
        sender = email_data.get('from', 'Unknown Sender')[:30]

        if category == 'important':
            prefix = "📧 IMPORTANT"
        elif category == 'suspicious':
            prefix = "⚠️ SUSPICIOUS"
        else:
            prefix = "📬"

        message = f"{prefix}: {subject} from {sender}"

        # Ensure message fits in SMS limit
        if len(message) > 160:
            message = message[:157] + "..."

        return message

    async def send_test_sms(self):
        """Send a test SMS"""
        if not self.client:
            return False

        try:
            test_sms = self.client.messages.create(
                body="Test SMS from Email Notifier",
                from_=self.from_number,
                to=self.to_number
            )
            self.logger.info(f"Test SMS sent. SID: {test_sms.sid}")
            return True
        except Exception as e:
            self.logger.error(f"Test SMS failed: {e}")
            return False


# Usage example:
async def main():
    notifier = TwilioNotifier()

    # Example email data
    email = {
        'subject': 'Urgent: Server Down',
        'from': 'admin@company.com'
    }

    # This will send SMS
    await notifier.send_notification(email, 'important')

    # This will send SMS
    await notifier.send_notification(email, 'suspicious')

    # This will NOT send SMS
    await notifier.send_notification(email, 'newsletter')


if __name__ == "__main__":
    asyncio.run(main())