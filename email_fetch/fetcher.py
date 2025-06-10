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

        # NEW: Track backfill progress
        self.backfill_page_token = None
        self.backfill_active = False
        self.total_emails_estimate = None

    def _get_gmail_service(self):
        """
        Authenticate and create Gmail API service

        :return: Gmail API service object
        """
        creds = None

        # The file token.json stores the user's access and refresh tokens
        from pathlib import Path
        BASE_DIR = Path(__file__).resolve().parent.parent
        token_path = BASE_DIR / 'config' / 'gmail_token.json'
        credentials_path = BASE_DIR / 'config' / 'gmail_credentials.json'

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

    async def fetch_new_emails(self, max_results=20, backfill_batch_size=10):
        """
        Fetch new emails with intelligent backfill strategy

        Strategy:
        1. Always check for new emails first
        2. If no new emails found, fetch next batch of old unprocessed emails
        3. Continue backfill until all historical emails are processed

        :param max_results: Maximum number of new emails to fetch
        :param backfill_batch_size: Number of old emails to fetch when backfilling
        :return: List of email dictionaries
        """
        try:
            # Step 1: Always check for new emails first
            new_emails = await self._fetch_recent_emails(max_results)

            if new_emails:
                self.logger.info(f"Found {len(new_emails)} new emails")
                return new_emails

            # Step 2: No new emails found, try backfill
            self.logger.info("No new emails found, attempting backfill of old emails")
            backfill_emails = await self._fetch_backfill_emails(backfill_batch_size)

            if backfill_emails:
                self.logger.info(f"Backfilled {len(backfill_emails)} old emails")
                return backfill_emails

            # Step 3: No emails at all
            self.logger.info("No new or backfill emails available")
            return []

        except Exception as e:
            self.logger.error(f"Error in fetch_new_emails: {e}", exc_info=True)
            return []

    async def _fetch_recent_emails(self, max_results):
        """
        Fetch only recent new emails since last fetch
        """
        try:
            # Determine query for recent emails
            if not self.last_fetch_time:
                # First fetch - get emails from last hour
                query = 'newer_than:1h'
                self.logger.info("First fetch, getting emails from the last hour")
            else:
                # Subsequent fetches - get very recent emails
                query = 'newer_than:1m'
                self.logger.debug("Fetching emails from the last minute")

            # Fetch recent emails
            results = self.gmail_service.users().messages().list(
                userId='me',
                q=query,
                maxResults=max_results
            ).execute()

            messages = results.get('messages', [])

            if not messages:
                return []

            # Process messages and filter by ID
            new_emails = []
            current_time = datetime.now()

            for message in messages:
                if message['id'] in self.processed_ids:
                    continue

                # Get full message details
                msg = self.gmail_service.users().messages().get(
                    userId='me',
                    id=message['id'],
                    format='full'
                ).execute()

                # Parse and add to results
                email_data = self._parse_gmail_message(msg)
                new_emails.append(email_data)
                self.processed_ids.add(message['id'])

            # Update last fetch time
            if new_emails:
                self.last_fetch_time = current_time
                self.logger.info(f"Updated last fetch time to {current_time.isoformat()}")

            return new_emails

        except Exception as e:
            self.logger.error(f"Error fetching recent emails: {e}", exc_info=True)
            return []

    async def _fetch_backfill_emails(self, batch_size):
        """
        Fetch old emails that haven't been processed yet
        Uses pagination to systematically work through historical emails
        """
        try:
            # Build query for backfill (no time restrictions)
            query = 'in:inbox OR in:sent'  # Adjust based on what emails you want

            # Use pagination to get different batches of old emails
            list_params = {
                'userId': 'me',
                'q': query,
                'maxResults': batch_size
            }

            # Add page token if we have one (for continuing where we left off)
            if self.backfill_page_token:
                list_params['pageToken'] = self.backfill_page_token

            results = self.gmail_service.users().messages().list(**list_params).execute()

            messages = results.get('messages', [])
            next_page_token = results.get('nextPageToken')

            if not messages:
                self.logger.info("No more emails available for backfill")
                self.backfill_page_token = None
                return []

            # Process messages, filtering out already processed ones
            backfill_emails = []

            for message in messages:
                if message['id'] in self.processed_ids:
                    self.logger.debug(f"Skipping already processed email: {message['id']}")
                    continue

                # Get full message details
                msg = self.gmail_service.users().messages().get(
                    userId='me',
                    id=message['id'],
                    format='full'
                ).execute()

                # Parse and add to results
                email_data = self._parse_gmail_message(msg)
                backfill_emails.append(email_data)
                self.processed_ids.add(message['id'])

            # Update pagination token for next backfill
            self.backfill_page_token = next_page_token

            # If we didn't find any unprocessed emails in this batch, try next page
            if not backfill_emails and next_page_token:
                self.logger.debug("No unprocessed emails in current batch, trying next page")
                return await self._fetch_backfill_emails(batch_size)

            # If no next page token, we've reached the end
            if not next_page_token:
                self.logger.info("Reached end of email backfill")
                self.backfill_page_token = None

            return backfill_emails

        except Exception as e:
            self.logger.error(f"Error during backfill: {e}", exc_info=True)
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
        received_timestamp = int(msg.get('internalDate', 0)) / 1000
        received_time = datetime.fromtimestamp(received_timestamp)

        # Parse date header as backup
        date_str = headers.get('date', '')
        parsed_date = None
        if date_str:
            try:
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
            'snippet': msg.get('snippet', ''),
            'is_backfill': not self.last_fetch_time or 'backfill' in str(self.backfill_page_token or '')
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

    def get_processing_stats(self):
        """
        Get statistics about processing progress
        """
        return {
            'processed_emails_count': len(self.processed_ids),
            'last_fetch_time': self.last_fetch_time.isoformat() if self.last_fetch_time else None,
            'backfill_active': bool(self.backfill_page_token),
            'backfill_page_token': self.backfill_page_token
        }

    def reset_backfill(self):
        """
        Reset backfill progress to start over
        """
        self.backfill_page_token = None
        self.logger.info("Backfill progress reset")

    def clear_processed_ids(self):
        """
        Clear processed IDs (use with caution - will cause duplicates)
        """
        self.processed_ids.clear()
        self.logger.warning("Processed IDs cleared - may cause duplicate processing")