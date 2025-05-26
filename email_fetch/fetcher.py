import asyncio
import logging
import os
from datetime import datetime, timedelta
import email.utils
import time

import google.auth
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build


class EmailFetcher:
    def __init__(self):
        """
        Initialize email fetcher with Gmail credentials
        """
        self.logger = logging.getLogger(__name__)

        # Gmail OAuth scopes
        self.GMAIL_SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

        # Credentials
        self.gmail_service = self._get_gmail_service()

        # Track last fetch time
        self.last_fetch_time = None

        # Track already processed message IDs to avoid duplicates
        self.processed_ids = set()

    def _get_gmail_service(self):
        """
        Authenticate and create Gmail API service

        :return: Gmail API service object
        """
        creds = None

        # The file token.json stores the user's access and refresh tokens
        token_path = 'gmail_token.json'
        credentials_path = 'gmail_credentials.json'

        # Try to load existing credentials
        if os.path.exists(token_path):
            from google.oauth2.credentials import Credentials
            creds = Credentials.from_authorized_user_file(token_path, self.GMAIL_SCOPES)

        # If there are no (valid) credentials available, let the user log in
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    credentials_path, self.GMAIL_SCOPES)
                creds = flow.run_local_server(port=0)

            # Save the credentials for the next run
            with open(token_path, 'w') as token:
                token.write(creds.to_json())

        return build('gmail', 'v1', credentials=creds)

    async def fetch_new_emails(self, max_results=20):
        """
        Fetch only new emails since last fetch

        :param max_results: Maximum number of emails to fetch
        :return: List of new email dictionaries
        """
        try:
            # Determine the time range for new emails
            if not self.last_fetch_time:
                # If first fetch, get emails from last hour
                query_time = datetime.now() - timedelta(hours=1)
                self.logger.info("First fetch, getting emails from the last hour")

                # Use a less restrictive query for first fetch
                query = 'newer_than:1h'
            else:
                # For subsequent fetches, use a less restrictive query
                # and rely on message ID filtering instead of date filtering
                query_time = self.last_fetch_time
                self.logger.info(f"Fetching emails since {query_time.isoformat()}")

                # Use a wider time window to ensure we don't miss any emails
                # We'll filter by ID later
                query = 'newer_than:1m'  # Get emails from the last minute

            self.logger.debug(f"Using Gmail query: {query}")

            # Fetch emails with higher max_results to ensure we don't miss any
            results = self.gmail_service.users().messages().list(
                userId='me',
                q=query,
                maxResults=max_results
            ).execute()

            messages = results.get('messages', [])

            # No messages found
            if not messages:
                self.logger.info("No messages found matching the query")
                return []

            # Keep track of the current time before processing
            current_time = datetime.now()

            # Fetch full details for each message and filter by IDs
            new_emails = []
            for message in messages:
                # Skip already processed messages
                if message['id'] in self.processed_ids:
                    self.logger.debug(f"Skipping already processed message ID: {message['id']}")
                    continue

                # Get the full message details
                msg = self.gmail_service.users().messages().get(
                    userId='me',
                    id=message['id'],
                    format='full'
                ).execute()

                # Parse the email and add to new emails list
                email_data = self._parse_gmail_message(msg)
                new_emails.append(email_data)

                # Add to processed IDs
                self.processed_ids.add(message['id'])
                self.logger.debug(f"Added new email: {email_data.get('subject')}")

            # Update last fetch time to current time
            self.last_fetch_time = current_time
            self.logger.info(f"Updated last fetch time to {current_time.isoformat()}")
            self.logger.info(f"Found {len(new_emails)} genuinely new emails")

            # Keep the processed IDs set from growing too large (keep last 1000)
            if len(self.processed_ids) > 1000:
                self.logger.debug(f"Trimming processed IDs set from {len(self.processed_ids)} items")
                self.processed_ids = set(list(self.processed_ids)[-1000:])
                self.logger.debug(f"Processed IDs set now contains {len(self.processed_ids)} items")

            return new_emails

        except Exception as e:
            self.logger.error(f"Error fetching new emails: {e}", exc_info=True)
            return []

    def _parse_gmail_message(self, msg):
        """
        Parse a Gmail message into a standardized email dictionary

        :param msg: Gmail API message object
        :return: Parsed email dictionary
        """
        # Extract headers
        headers = {h['name'].lower(): h['value'] for h in msg['payload']['headers']}

        # Extract email body
        body = self._get_email_body(msg['payload'])

        # Get received timestamp from internalDate
        received_timestamp = int(msg.get('internalDate', 0)) / 1000  # Convert from ms to seconds
        received_time = datetime.fromtimestamp(received_timestamp)

        # Parse date header as backup
        date_str = headers.get('date', '')
        parsed_date = None
        if date_str:
            try:
                # Parse email date format
                parsed_time_tuple = email.utils.parsedate_tz(date_str)
                if parsed_time_tuple:
                    parsed_date = datetime.fromtimestamp(email.utils.mktime_tz(parsed_time_tuple))
            except Exception as e:
                self.logger.warning(f"Could not parse email date: {date_str}, {e}")

        # Use either parsed date or received timestamp
        email_date = parsed_date or received_time

        return {
            'id': msg['id'],
            'thread_id': msg.get('threadId', ''),
            'subject': headers.get('subject', 'No Subject'),
            'from': headers.get('from', 'Unknown Sender'),
            'to': headers.get('to', ''),
            'date': date_str,
            'date_parsed': email_date,
            'received_time': received_time,
            'body': body,
            'labels': msg.get('labelIds', []),
            'snippet': msg.get('snippet', '')
        }

    def _get_email_body(self, payload):
        """
        Extract email body from Gmail message payload

        :param payload: Gmail message payload
        :return: Email body as string
        """

        def decode_payload(part):
            """Helper to decode payload"""
            import base64
            try:
                # Try to decode base64 encoded body
                body_data = part['body'].get('data', '')
                return base64.urlsafe_b64decode(body_data).decode('utf-8')
            except Exception:
                return ''

        body = ''

        # Check if it's a multipart message
        if 'parts' in payload:
            for part in payload['parts']:
                if part['mimeType'] in ['text/plain', 'text/html']:
                    body += decode_payload(part)
        else:
            # Single part message
            body = decode_payload(payload)

        return body.strip()