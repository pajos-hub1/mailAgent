import streamlit as st
import asyncio
import logging
from dotenv import load_dotenv
import os
import threading
import time
from datetime import datetime, timedelta
import pandas as pd
from typing import List, Dict, Any
import sys
import html  # Add this import for HTML escaping
from collections import Counter, defaultdict

# Import your existing modules
try:
    from email_fetch.fetcher import EmailFetcher
    from analysis.classifier import EmailClassifier
    from notify.notifier import TwilioNotifier
    from utils.helpers import setup_logging
except ImportError as e:
    st.error(f"Import error: {e}")
    st.stop()


class StreamlitEmailAgent:
    def __init__(self):
        # Only initialize once per session
        if hasattr(self, '_initialized'):
            return

        try:
            # Load environment variables
            load_dotenv(os.path.join('config', 'credentials.env'))

            # Setup logging with streamlit-friendly config
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                handlers=[logging.StreamHandler(sys.stdout)]
            )
            self.logger = logging.getLogger(__name__)

            # Initialize components with error handling
            self.fetcher = None
            self.classifier = None
            self.notifier = None

            # Initialize email fetcher
            try:
                self.fetcher = EmailFetcher()
                self.logger.info("Email fetcher initialized successfully")
            except Exception as e:
                self.logger.error(f"Email fetcher failed to initialize: {e}")
                st.error(f"Failed to initialize email fetcher: {e}")

            # Initialize classifier
            try:
                self.classifier = EmailClassifier()
                self.logger.info("Email classifier initialized successfully")
            except Exception as e:
                self.logger.error(f"Email classifier failed to initialize: {e}")
                st.warning(f"Email classifier failed to initialize: {e}. Using basic classification.")

            # Initialize Twilio notifier
            try:
                self.notifier = TwilioNotifier()
                self.logger.info("Twilio notifier initialized successfully")
            except Exception as e:
                self.logger.error(f"Twilio notifier failed to initialize: {e}")
                st.warning(f"SMS notifications disabled: {e}")

            # Configure polling interval
            self.polling_interval = int(os.getenv('POLLING_INTERVAL', 30))  # Increased default

            self._initialized = True

        except Exception as e:
            self.logger.error(f"Agent initialization failed: {e}")
            st.error(f"Agent initialization failed: {e}")

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
        if not self.fetcher:
            self.add_log("Email fetcher not available")
            return []

        try:
            # Run the async function in a way that works with Streamlit
            new_emails = await self.fetcher.fetch_new_emails()

            if not new_emails:
                self.add_log("No new emails found.")
                return []

            self.add_log(f"{len(new_emails)} new email(s) found.")

            # Process all emails
            processed_emails = []

            for email in new_emails:
                try:
                    # Use classifier if available, otherwise use basic classification
                    if self.classifier:
                        classification = self.classifier.classify(email)
                    else:
                        classification = self.basic_classify(email)

                    email_data = {
                        'timestamp': datetime.now(),
                        'from': email.get('from', 'Unknown Sender'),
                        'subject': email.get('subject', 'No Subject'),
                        'category': classification.get('category', 'Unknown'),
                        'confidence': classification.get('confidence', 0.0),
                        'body_preview': email.get('body', '')[:100] + '...' if email.get('body') else ''
                    }

                    processed_emails.append(email_data)

                    # Update counters
                    st.session_state.total_emails += 1
                    category = classification.get('category', '').lower()
                    if category == 'important':
                        st.session_state.important_count += 1
                    elif category == 'suspicious':
                        st.session_state.suspicious_count += 1

                    # Send notification if needed (non-blocking)
                    if category in ['important', 'suspicious'] and self.notifier:
                        try:
                            # Create task but don't await it to avoid blocking
                            asyncio.create_task(self._send_notification(email, classification))
                        except Exception as e:
                            self.add_log(f"Error creating notification task: {str(e)}")

                except Exception as e:
                    self.logger.error(f"Error classifying email: {e}")
                    self.add_log(f"Error processing email: {str(e)}")
                    continue

            # Add to session state
            st.session_state.emails_processed.extend(processed_emails)
            st.session_state.last_check_time = datetime.now()

            return processed_emails

        except Exception as e:
            self.logger.error(f"Error in email processing: {e}")
            self.add_log(f"Error in email processing: {str(e)}")
            return []

    async def _send_notification(self, email, classification):
        """Send SMS notification if needed"""
        if not self.notifier:
            return

        try:
            category = classification.get('category', '').lower()
            success = await asyncio.wait_for(
                self.notifier.send_notification(email, category),
                timeout=15.0
            )

            if success:
                self.add_log(f"📱 SMS sent for {category} email from {email.get('from', 'Unknown')}")
            else:
                self.add_log(f"Failed to send SMS for {category} email")

        except asyncio.TimeoutError:
            self.add_log(f"SMS notification timed out for {category} email")
        except Exception as e:
            self.logger.error(f"Error sending notification: {e}")
            self.add_log(f"Error sending notification: {str(e)}")

    def add_log(self, message):
        """Add a log message to session state"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        st.session_state.log_messages.append(log_entry)
        # Keep only last 50 log messages
        if len(st.session_state.log_messages) > 50:
            st.session_state.log_messages = st.session_state.log_messages[-50:]

    async def test_sms(self):
        """Test SMS functionality"""
        if not self.notifier:
            return False, "SMS notifications not configured"

        try:
            success = await asyncio.wait_for(
                self.notifier.send_test_sms(),
                timeout=15.0
            )
            if success:
                return True, "Test SMS sent successfully!"
            else:
                return False, "Test SMS failed"
        except asyncio.TimeoutError:
            return False, "Test SMS timed out"
        except Exception as e:
            return False, f"Test SMS error: {str(e)}"

    def generate_weekly_summary(self, emails_data: List[Dict], start_date: datetime = None):
        """Generate a comprehensive weekly summary of email activity"""
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

        # Risk analysis
        important_emails = [email for email in week_emails if email['category'].lower() == 'important']
        suspicious_emails = [email for email in week_emails if email['category'].lower() == 'suspicious']

        # Confidence analysis
        avg_confidence = sum(email['confidence'] for email in week_emails) / len(week_emails)
        high_confidence = len([email for email in week_emails if email['confidence'] > 0.8])
        low_confidence = len([email for email in week_emails if email['confidence'] < 0.5])

        # Generate summary text
        summary_parts = []
        summary_parts.append(
            f"📊 **Weekly Email Summary ({start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')})**")
        summary_parts.append(f"Total emails processed: **{total_emails}**")

        if category_counts:
            summary_parts.append("\n**Category Breakdown:**")
            for category, count in category_counts.most_common():
                percentage = (count / total_emails) * 100
                summary_parts.append(f"• {category}: {count} emails ({percentage:.1f}%)")

        if important_emails:
            summary_parts.append(f"\n🔥 **{len(important_emails)} Important emails** requiring attention")

        if suspicious_emails:
            summary_parts.append(f"\n⚠️ **{len(suspicious_emails)} Suspicious emails** detected")

        if top_senders:
            summary_parts.append(f"\n📧 **Top Senders:**")
            for sender, count in top_senders:
                summary_parts.append(f"• {sender}: {count} emails")

        summary_parts.append(f"\n⏰ **Peak Activity:** {peak_hour[0]:02d}:00 ({peak_hour[1]} emails)")
        summary_parts.append(f"🎯 **Average Confidence:** {avg_confidence:.1%}")

        if daily_counts:
            busiest_day = max(daily_counts.items(), key=lambda x: x[1])
            summary_parts.append(f"📅 **Busiest Day:** {busiest_day[0]} ({busiest_day[1]} emails)")

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
                'avg_confidence': avg_confidence,
                'high_confidence_count': high_confidence,
                'low_confidence_count': low_confidence,
                'peak_hour': peak_hour,
                'date_range': (start_date, end_date)
            }
        }

    def export_weekly_summary_csv(self, summary_data: Dict, emails_data: List[Dict]):
        """Export weekly summary data to CSV format"""
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

        return df


def run_async_function(func):
    """Helper to run async functions in Streamlit"""
    try:
        # Try to get existing event loop
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If loop is running, create a new thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(asyncio.run, func)
                return future.result(timeout=30)
        else:
            return loop.run_until_complete(func)
    except RuntimeError:
        # No event loop, create new one
        return asyncio.run(func)


def initialize_session_state():
    """Initialize all session state variables"""
    if 'monitoring_active' not in st.session_state:
        st.session_state.monitoring_active = False
    if 'emails_processed' not in st.session_state:
        st.session_state.emails_processed = []
    if 'last_check_time' not in st.session_state:
        st.session_state.last_check_time = None
    if 'total_emails' not in st.session_state:
        st.session_state.total_emails = 0
    if 'important_count' not in st.session_state:
        st.session_state.important_count = 0
    if 'suspicious_count' not in st.session_state:
        st.session_state.suspicious_count = 0
    if 'log_messages' not in st.session_state:
        st.session_state.log_messages = []
    if 'agent' not in st.session_state:
        with st.spinner("Initializing Email Agent..."):
            st.session_state.agent = StreamlitEmailAgent()
    if 'weekly_summary' not in st.session_state:
        st.session_state.weekly_summary = None
    if 'summary_date_range' not in st.session_state:
        st.session_state.summary_date_range = None


def safe_html_escape(text):
    """Safely escape HTML characters in text"""
    if text is None:
        return "Unknown"
    return html.escape(str(text))


def main():
    st.set_page_config(
        page_title="📧 Email Monitoring Agent",
        page_icon="📧",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Initialize session state
    initialize_session_state()
    agent = st.session_state.agent

    # Title and header
    st.title("📧 Email Monitoring Agent")
    st.markdown("---")

    # Check if agent components are available
    components_status = []
    if agent.fetcher:
        components_status.append("✅ Email Fetcher")
    else:
        components_status.append("❌ Email Fetcher")

    if agent.classifier:
        components_status.append("✅ ML Classifier")
    else:
        components_status.append("⚠️ Basic Classifier")

    if agent.notifier:
        components_status.append("✅ SMS Notifier")
    else:
        components_status.append("❌ SMS Notifier")

    # Display component status
    with st.expander("System Status", expanded=False):
        for status in components_status:
            st.write(status)

    # Sidebar controls
    with st.sidebar:
        st.header("🔧 Controls")

        # Status indicators
        st.subheader("📊 Status")
        col1, col2 = st.columns(2)

        with col1:
            if st.session_state.monitoring_active:
                st.success("✅ ACTIVE")
            else:
                st.error("⏸️ PAUSED")

        with col2:
            if agent.notifier:
                st.success("📱 SMS ON")
            else:
                st.warning("📱 SMS OFF")

        # Control buttons
        st.markdown("---")

        col1, col2 = st.columns(2)
        with col1:
            if st.button("▶️ Start"):
                if not agent.fetcher:
                    st.error("Email fetcher not available!")
                else:
                    st.session_state.monitoring_active = True
                    st.success("Monitoring started!")
                    st.rerun()

        with col2:
            if st.button("⏸️ Pause"):
                st.session_state.monitoring_active = False
                st.info("Monitoring paused")
                st.rerun()

        # Manual check
        if st.button("🔍 Check Now"):
            if not agent.fetcher:
                st.error("Email fetcher not available!")
            else:
                with st.spinner("Checking for new emails..."):
                    try:
                        new_emails = run_async_function(agent.process_new_emails())
                        if new_emails:
                            st.success(f"Found {len(new_emails)} new emails!")
                        else:
                            st.info("No new emails found")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error checking emails: {e}")

        # Test SMS
        if st.button("📱 Test SMS"):
            if agent.notifier:
                with st.spinner("Sending test SMS..."):
                    try:
                        success, message = run_async_function(agent.test_sms())
                        if success:
                            st.success(message)
                        else:
                            st.error(message)
                    except Exception as e:
                        st.error(f"Error testing SMS: {e}")
            else:
                st.error("SMS not configured")

        # Settings
        st.markdown("---")
        st.subheader("⚙️ Settings")

        # Polling interval
        new_interval = st.slider(
            "Polling Interval (seconds)",
            min_value=10,
            max_value=300,
            value=agent.polling_interval,
            step=10,
            help="How often to check for new emails"
        )
        if new_interval != agent.polling_interval:
            agent.polling_interval = new_interval
            st.success(f"Interval updated to {new_interval}s")

        # Clear data
        if st.button("🗑️ Clear Data"):
            st.session_state.emails_processed = []
            st.session_state.log_messages = []
            st.session_state.total_emails = 0
            st.session_state.important_count = 0
            st.session_state.suspicious_count = 0
            st.success("Data cleared!")
            st.rerun()

    # Main content area with tabs
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Dashboard", "📧 Email List", "📈 Weekly Summary", "📝 Logs"])

    with tab1:
        # Statistics
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Total Emails", st.session_state.total_emails)

        with col2:
            st.metric("Important", st.session_state.important_count)

        with col3:
            st.metric("Suspicious", st.session_state.suspicious_count)

        with col4:
            if st.session_state.last_check_time:
                time_diff = datetime.now() - st.session_state.last_check_time
                st.metric("Last Check", f"{int(time_diff.total_seconds())}s ago")
            else:
                st.metric("Last Check", "Never")

        # Charts
        if st.session_state.emails_processed:
            st.subheader("📈 Email Analytics")

            col1, col2 = st.columns(2)

            with col1:
                st.write("**Categories Distribution**")
                categories = [email['category'] for email in st.session_state.emails_processed]
                category_counts = pd.Series(categories).value_counts()
                st.bar_chart(category_counts)

            with col2:
                st.write("**Emails Over Time**")
                if len(st.session_state.emails_processed) > 1:
                    df = pd.DataFrame(st.session_state.emails_processed)
                    df['hour'] = df['timestamp'].dt.hour
                    hourly_counts = df.groupby('hour').size()
                    st.line_chart(hourly_counts)
                else:
                    st.info("Need more emails for timeline chart")
        else:
            st.info("📭 No emails processed yet. Start monitoring or check manually to see analytics.")

    with tab2:
        # Email list header with controls
        col1, col2, col3 = st.columns([2, 1, 1])
        with col1:
            st.subheader("📧 Email Inbox")
        with col2:
            # Filter by category
            categories = ['All'] + list(set([email['category'] for email in st.session_state.emails_processed]))
            selected_category = st.selectbox("Filter by Category", categories, key="category_filter")
        with col3:
            # Sort options
            sort_option = st.selectbox("Sort by", ["Newest First", "Oldest First", "Category", "Sender"],
                                       key="sort_option")

        if st.session_state.emails_processed:
            # Filter emails based on selection
            filtered_emails = st.session_state.emails_processed
            if selected_category != 'All':
                filtered_emails = [email for email in filtered_emails if email['category'] == selected_category]

            # Sort emails based on selection
            if sort_option == "Newest First":
                filtered_emails = sorted(filtered_emails, key=lambda x: x['timestamp'], reverse=True)
            elif sort_option == "Oldest First":
                filtered_emails = sorted(filtered_emails, key=lambda x: x['timestamp'])
            elif sort_option == "Category":
                filtered_emails = sorted(filtered_emails, key=lambda x: x['category'])
            elif sort_option == "Sender":
                filtered_emails = sorted(filtered_emails, key=lambda x: x['from'])

            # Show email count
            st.write(f"Showing {len(filtered_emails)} of {len(st.session_state.emails_processed)} emails")

            # Display emails with improved UI
            for i, email in enumerate(filtered_emails):
                # Create a card-like container with better styling
                category = email['category'].lower()

                # Define colors and icons based on category
                if category == 'important':
                    border_color = "#ff6b6b"
                    bg_color = "#fff5f5"
                    icon = "🔥"
                    category_color = "#ff6b6b"
                elif category == 'suspicious':
                    border_color = "#feca57"
                    bg_color = "#fffbf0"
                    icon = "⚠️"
                    category_color = "#feca57"
                else:
                    border_color = "#48cae4"
                    bg_color = "#f0fbff"
                    icon = "📄"
                    category_color = "#48cae4"

                # Safely escape HTML content
                safe_subject = safe_html_escape(email['subject'])
                safe_from = safe_html_escape(email['from'])
                safe_category = safe_html_escape(email['category'])

                # Create the email card
                with st.container():
                    # Use HTML/CSS for better styling with escaped content
                    st.markdown(f"""
                    <div style="
                        border-left: 4px solid {border_color};
                        background-color: {bg_color};
                        padding: 15px;
                        margin: 10px 0;
                        border-radius: 8px;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    ">
                        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;">
                            <div style="flex: 1;">
                                <h4 style="margin: 0; color: #2c3e50; font-size: 16px; font-weight: 600;">
                                    {icon} {safe_subject}
                                </h4>
                                <p style="margin: 5px 0; color: #7f8c8d; font-size: 14px;">
                                    <strong>From:</strong> {safe_from}
                                </p>
                            </div>
                            <div style="text-align: right; min-width: 120px;">
                                <span style="
                                    background-color: {category_color};
                                    color: white;
                                    padding: 4px 8px;
                                    border-radius: 12px;
                                    font-size: 12px;
                                    font-weight: 600;
                                ">
                                    {safe_category}
                                </span>
                                <p style="margin: 5px 0; color: #95a5a6; font-size: 12px;">
                                    {email['timestamp'].strftime("%H:%M:%S")}
                                </p>
                            </div>
                        </div>
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div style="color: #7f8c8d; font-size: 13px;">
                                <strong>Confidence:</strong> {email['confidence']:.1%}
                            </div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                    # Expandable sections
                    col1, col2, col3 = st.columns([1, 1, 1])

                    with col1:
                        if st.button("📖 Preview", key=f"preview_{i}", help="View email preview"):
                            st.session_state[f"show_preview_{i}"] = not st.session_state.get(f"show_preview_{i}", False)

                    with col2:
                        if st.button("📊 Details", key=f"details_{i}", help="View detailed information"):
                            st.session_state[f"show_details_{i}"] = not st.session_state.get(f"show_details_{i}", False)

                    with col3:
                        if category in ['important', 'suspicious'] and agent.notifier:
                            if st.button("📱 Resend SMS", key=f"sms_{i}", help="Resend SMS notification"):
                                with st.spinner("Sending SMS..."):
                                    try:
                                        # Create a mock email object for notification
                                        mock_email = {
                                            'from': email['from'],
                                            'subject': email['subject'],
                                            'body': email['body_preview']
                                        }
                                        success = run_async_function(
                                            agent.notifier.send_notification(mock_email, category)
                                        )
                                        if success:
                                            st.success("SMS sent!")
                                        else:
                                            st.error("SMS failed")
                                    except Exception as e:
                                        st.error(f"SMS error: {e}")

                    # Show preview if toggled
                    if st.session_state.get(f"show_preview_{i}", False) and email['body_preview']:
                        with st.expander("📖 Email Preview", expanded=True):
                            # Use safe text display instead of HTML
                            st.text_area(
                                "Email Content Preview",
                                value=email['body_preview'],
                                height=200,
                                key=f"preview_text_{i}",
                                disabled=True
                            )

                    # Show details if toggled
                    if st.session_state.get(f"show_details_{i}", False):
                        with st.expander("📊 Detailed Information", expanded=True):
                            detail_col1, detail_col2 = st.columns(2)

                            with detail_col1:
                                st.write("**Email Information:**")
                                st.write(f"• **Sender:** {email['from']}")
                                st.write(f"• **Subject:** {email['subject']}")
                                st.write(f"• **Received:** {email['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")

                            with detail_col2:
                                st.write("**Classification:**")
                                st.write(f"• **Category:** {email['category']}")
                                st.write(f"• **Confidence:** {email['confidence']:.2%}")
                                st.write(
                                    f"• **Risk Level:** {'High' if category in ['important', 'suspicious'] else 'Low'}")

                    st.markdown("<br>", unsafe_allow_html=True)
        else:
            # Empty state with better design
            st.markdown("""
            <div style="
                text-align: center;
                padding: 60px 20px;
                background-color: #f8f9fa;
                border-radius: 10px;
                border: 2px dashed #dee2e6;
                margin: 20px 0;
            ">
                <h2 style="color: #6c757d; margin-bottom: 10px;">📭 No Emails Yet</h2>
                <p style="color: #868e96; font-size: 16px; margin-bottom: 20px;">
                    Start monitoring or check manually to see your emails here
                </p>
                <div style="margin-top: 20px;">
                    <span style="font-size: 24px;">🔍</span>
                    <span style="font-size: 24px; margin: 0 10px;">📧</span>
                    <span style="font-size: 24px;">📊</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

    with tab3:
        st.subheader("📈 Weekly Email Summary")

        # Date range selector
        col1, col2, col3 = st.columns([2, 2, 1])

        with col1:
            # Default to last week
            default_start = datetime.now() - timedelta(days=7)
            start_date = st.date_input(
                "Start Date",
                value=default_start.date(),
                max_value=datetime.now().date(),
                help="Select the start date for the weekly summary"
            )

        with col2:
            # End date (7 days after start)
            end_date = st.date_input(
                "End Date",
                value=(datetime.combine(start_date, datetime.min.time()) + timedelta(days=7)).date(),
                max_value=datetime.now().date(),
                help="Select the end date for the weekly summary"
            )

        with col3:
            if st.button("📊 Generate Summary", type="primary"):
                if start_date and end_date:
                    start_datetime = datetime.combine(start_date, datetime.min.time())

                    with st.spinner("Generating weekly summary..."):
                        summary = agent.generate_weekly_summary(
                            st.session_state.emails_processed,
                            start_datetime
                        )
                        st.session_state.weekly_summary = summary
                        st.session_state.summary_date_range = (start_date, end_date)

                    if summary['total_emails'] > 0:
                        st.success(f"Summary generated for {summary['total_emails']} emails!")
                    else:
                        st.info("No emails found in the selected date range.")
                else:
                    st.error("Please select both start and end dates.")

        # Quick date range buttons
        st.write("**Quick Select:**")
        quick_col1, quick_col2, quick_col3, quick_col4 = st.columns(4)

        with quick_col1:
            if st.button("📅 Last 7 Days"):
                st.session_state.summary_date_range = (
                    (datetime.now() - timedelta(days=7)).date(),
                    datetime.now().date()
                )
                summary = agent.generate_weekly_summary(
                    st.session_state.emails_processed,
                    datetime.now() - timedelta(days=7)
                )
                st.session_state.weekly_summary = summary
                st.rerun()

        with quick_col2:
            if st.button("📅 This Week"):
                # Get Monday of current week
                today = datetime.now()
                monday = today - timedelta(days=today.weekday())
                st.session_state.summary_date_range = (monday.date(), today.date())
                summary = agent.generate_weekly_summary(
                    st.session_state.emails_processed,
                    monday
                )
                st.session_state.weekly_summary = summary
                st.rerun()

        with quick_col3:
            if st.button("📅 Last Week"):
                today = datetime.now()
                last_monday = today - timedelta(days=today.weekday() + 7)
                last_sunday = last_monday + timedelta(days=6)
                st.session_state.summary_date_range = (last_monday.date(), last_sunday.date())
                summary = agent.generate_weekly_summary(
                    st.session_state.emails_processed,
                    last_monday
                )
                st.session_state.weekly_summary = summary
                st.rerun()

        with quick_col4:
            if st.button("📅 Last 30 Days"):
                start_30 = datetime.now() - timedelta(days=30)
                st.session_state.summary_date_range = (start_30.date(), datetime.now().date())
                summary = agent.generate_weekly_summary(
                    st.session_state.emails_processed,
                    start_30
                )
                st.session_state.weekly_summary = summary
                st.rerun()

        st.markdown("---")

        # Display summary if available
        if st.session_state.weekly_summary:
            summary = st.session_state.weekly_summary

            if summary['total_emails'] > 0:
                # Summary text
                st.markdown(summary['summary'])

                st.markdown("---")

                # Detailed analytics
                col1, col2 = st.columns(2)

                with col1:
                    st.subheader("📊 Category Distribution")
                    if summary['details']['category_counts']:
                        category_df = pd.DataFrame(
                            list(summary['details']['category_counts'].items()),
                            columns=['Category', 'Count']
                        )
                        st.bar_chart(category_df.set_index('Category'))
                    else:
                        st.info("No category data available")

                    st.subheader("📅 Daily Activity")
                    if summary['details']['daily_counts']:
                        daily_df = pd.DataFrame(
                            list(summary['details']['daily_counts'].items()),
                            columns=['Date', 'Emails']
                        )
                        daily_df['Date'] = pd.to_datetime(daily_df['Date'])
                        daily_df = daily_df.sort_values('Date')
                        st.line_chart(daily_df.set_index('Date'))
                    else:
                        st.info("No daily data available")

                with col2:
                    st.subheader("⏰ Hourly Distribution")
                    if summary['details']['hourly_distribution']:
                        hourly_df = pd.DataFrame(
                            list(summary['details']['hourly_distribution'].items()),
                            columns=['Hour', 'Emails']
                        )
                        hourly_df = hourly_df.sort_values('Hour')
                        st.bar_chart(hourly_df.set_index('Hour'))
                    else:
                        st.info("No hourly data available")

                    st.subheader("👥 Top Senders")
                    if summary['details']['top_senders']:
                        for i, (sender, count) in enumerate(summary['details']['top_senders'], 1):
                            st.write(f"{i}. **{sender}** ({count} emails)")
                    else:
                        st.info("No sender data available")

                # Important and Suspicious emails sections
                if summary['details']['important_emails'] or summary['details']['suspicious_emails']:
                    st.markdown("---")
                    st.subheader("🔍 Attention Required")

                    alert_col1, alert_col2 = st.columns(2)

                    with alert_col1:
                        if summary['details']['important_emails']:
                            st.write(f"**🔥 Important Emails ({len(summary['details']['important_emails'])})**")
                            with st.expander("View Important Emails", expanded=False):
                                for email in summary['details']['important_emails'][:5]:  # Show first 5
                                    st.write(f"• **From:** {email['from']}")
                                    st.write(f"  **Subject:** {email['subject']}")
                                    st.write(f"  **Time:** {email['timestamp'].strftime('%Y-%m-%d %H:%M')}")
                                    st.write("---")

                    with alert_col2:
                        if summary['details']['suspicious_emails']:
                            st.write(f"**⚠️ Suspicious Emails ({len(summary['details']['suspicious_emails'])})**")
                            with st.expander("View Suspicious Emails", expanded=False):
                                for email in summary['details']['suspicious_emails'][:5]:  # Show first 5
                                    st.write(f"• **From:** {email['from']}")
                                    st.write(f"  **Subject:** {email['subject']}")
                                    st.write(f"  **Time:** {email['timestamp'].strftime('%Y-%m-%d %H:%M')}")
                                    st.write("---")

                # Export options
                st.markdown("---")
                st.subheader("📤 Export Options")

                export_col1, export_col2, export_col3 = st.columns(3)

                with export_col1:
                    if st.button("📋 Copy Summary"):
                        # Create a simplified text version
                        text_summary = summary['summary'].replace('**', '').replace('*', '')
                        st.text_area(
                            "Copy this summary:",
                            value=text_summary,
                            height=200,
                            key="copy_summary"
                        )

                with export_col2:
                    if st.button("📊 Download CSV"):
                        csv_data = agent.export_weekly_summary_csv(summary, st.session_state.emails_processed)
                        if csv_data is not None:
                            csv_string = csv_data.to_csv(index=False)
                            st.download_button(
                                label="💾 Download Email Data",
                                data=csv_string,
                                file_name=f"email_summary_{start_date}_to_{end_date}.csv",
                                mime="text/csv"
                            )
                        else:
                            st.error("No data available for export")

                with export_col3:
                    if st.button("📧 Email Summary"):
                        if agent.notifier:
                            # Send summary via SMS (truncated version)
                            short_summary = f"📊 Email Summary: {summary['total_emails']} emails processed. "
                            if summary['details']['category_counts']:
                                categories = ", ".join(
                                    [f"{k}: {v}" for k, v in summary['details']['category_counts'].items()])
                                short_summary += f"Categories: {categories}. "

                            st.info("SMS summary feature would send: " + short_summary[:160] + "...")
                        else:
                            st.error("SMS notifications not configured")

                # Statistics cards
                st.markdown("---")
                st.subheader("📈 Summary Statistics")

                stat_col1, stat_col2, stat_col3, stat_col4 = st.columns(4)

                with stat_col1:
                    st.metric(
                        "Total Emails",
                        summary['total_emails']
                    )

                with stat_col2:
                    st.metric(
                        "Avg Confidence",
                        f"{summary['details']['avg_confidence']:.1%}"
                    )

                with stat_col3:
                    high_conf = summary['details']['high_confidence_count']
                    st.metric(
                        "High Confidence",
                        high_conf,
                        delta=f"{(high_conf / summary['total_emails'] * 100):.1f}%" if summary[
                                                                                           'total_emails'] > 0 else "0%"
                    )

                with stat_col4:
                    peak_hour, peak_count = summary['details']['peak_hour']
                    st.metric(
                        "Peak Hour",
                        f"{peak_hour:02d}:00",
                        delta=f"{peak_count} emails"
                    )
            else:
                st.info("No emails found in the selected date range.")
        else:
            # First time user guidance
            st.info("👆 Select a date range and click 'Generate Summary' to see your weekly email analytics.")

            if st.session_state.emails_processed:
                # Show some basic stats to encourage usage
                st.write("**Available Data:**")
                total_emails = len(st.session_state.emails_processed)
                if total_emails > 0:
                    earliest = min(email['timestamp'] for email in st.session_state.emails_processed)
                    latest = max(email['timestamp'] for email in st.session_state.emails_processed)
                    st.write(f"• {total_emails} emails processed")
                    st.write(f"• Date range: {earliest.strftime('%Y-%m-%d')} to {latest.strftime('%Y-%m-%d')}")

                    # Quick stats
                    categories = Counter(email['category'] for email in st.session_state.emails_processed)
                    st.write("• Categories:", ", ".join([f"{k}: {v}" for k, v in categories.items()]))
            else:
                st.write("Start monitoring emails to generate summaries!")

    with tab4:
        st.subheader("📝 Activity Logs")

        if st.session_state.log_messages:
            # Create a container for logs with scrolling
            log_container = st.container()
            with log_container:
                # Display logs in reverse order (newest first)
                for log_msg in reversed(st.session_state.log_messages[-20:]):  # Show last 20
                    st.text(log_msg)
        else:
            st.info("No log messages yet.")

    # Auto-refresh functionality
    if st.session_state.monitoring_active and agent.fetcher:
        # Check if it's time for the next poll
        should_check = False

        if st.session_state.last_check_time is None:
            should_check = True
        else:
            time_since_last = (datetime.now() - st.session_state.last_check_time).total_seconds()
            should_check = time_since_last >= agent.polling_interval

        if should_check:
            # Process emails automatically
            try:
                new_emails = run_async_function(agent.process_new_emails())
                if new_emails:
                    st.toast(f"📧 {len(new_emails)} new emails detected!")
            except Exception as e:
                agent.add_log(f"Auto-check error: {str(e)}")

            # Rerun to update the display
            time.sleep(2)  # Brief pause before rerun
            st.rerun()
        else:
            # Show countdown and auto-refresh
            time_since_last = (datetime.now() - st.session_state.last_check_time).total_seconds()
            time_remaining = agent.polling_interval - time_since_last

            # Add a status bar at the bottom
            with st.container():
                st.write(f"⏰ Next check in {int(time_remaining)} seconds...")
                progress = time_since_last / agent.polling_interval
                st.progress(progress)

            # Auto-refresh every 5 seconds to update countdown
            time.sleep(5)
            st.rerun()


if __name__ == "__main__":
    main()