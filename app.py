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
    from email_agent import EmailMonitoringAgent  # Import the new agent
    from utils.helpers import setup_logging
except ImportError as e:
    st.error(f"Import error: {e}")
    st.stop()


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
    if 'malicious_count' not in st.session_state:
        st.session_state.malicious_count = 0
    if 'log_messages' not in st.session_state:
        st.session_state.log_messages = []
    if 'agent' not in st.session_state:
        with st.spinner("Initializing Email Agent..."):
            st.session_state.agent = EmailMonitoringAgent()  # Use the new agent
    if 'weekly_summary' not in st.session_state:
        st.session_state.weekly_summary = None
    if 'summary_date_range' not in st.session_state:
        st.session_state.summary_date_range = None


def safe_html_escape(text):
    """Safely escape HTML characters in text"""
    if text is None:
        return "Unknown"
    return html.escape(str(text))


def add_log(message):
    """Add a log message to session state"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    log_entry = f"[{timestamp}] {message}"
    st.session_state.log_messages.append(log_entry)
    # Keep only last 50 log messages
    if len(st.session_state.log_messages) > 50:
        st.session_state.log_messages = st.session_state.log_messages[-50:]


async def process_emails_for_streamlit():
    """Wrapper function to process emails and update Streamlit session state"""
    agent = st.session_state.agent

    try:
        # Process new emails
        email_classifications = await agent.process_new_emails()

        if not email_classifications:
            add_log("No new emails found.")
            return []

        add_log(f"{len(email_classifications)} new email(s) found.")

        # Update session state with processed emails
        processed_emails = []
        for email, classification in email_classifications:
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
            processed_emails.append(email_data)

            # Update counters in session state
            st.session_state.total_emails += 1
            category = classification.get('category', '').lower()
            if category == 'important':
                st.session_state.important_count += 1
            elif category == 'suspicious':
                st.session_state.suspicious_count += 1

                # Check if it's malicious based on threat intelligence
                threat_intel = classification.get('details', {}).get('threat_intelligence')
                if threat_intel and threat_intel.get('is_malicious', False):
                    st.session_state.malicious_count += 1

        # Add to session state
        st.session_state.emails_processed.extend(processed_emails)
        st.session_state.last_check_time = datetime.now()

        return processed_emails

    except Exception as e:
        add_log(f"Error in email processing: {str(e)}")
        return []


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
                    agent.monitoring_active = True
                    st.success("Monitoring started!")
                    st.rerun()

        with col2:
            if st.button("⏸️ Pause"):
                st.session_state.monitoring_active = False
                agent.pause_monitoring()
                st.info("Monitoring paused")
                st.rerun()

        # Manual check
        if st.button("🔍 Check Now"):
            if not agent.fetcher:
                st.error("Email fetcher not available!")
            else:
                with st.spinner("Checking for new emails..."):
                    try:
                        new_emails = run_async_function(process_emails_for_streamlit())
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
                        success = run_async_function(agent.test_sms())
                        if success:
                            st.success("Test SMS sent successfully!")
                        else:
                            st.error("Test SMS failed")
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
            st.session_state.malicious_count = 0
            agent.clear_data()  # Also clear data in the agent
            st.success("Data cleared!")
            st.rerun()

    # Main content area with tabs
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Dashboard", "📧 Email List", "📈 Weekly Summary", "📝 Logs"])

    with tab1:
        # Statistics
        col1, col2, col3, col4, col5 = st.columns(5)

        with col1:
            st.metric("Total Emails", st.session_state.total_emails)

        with col2:
            st.metric("Important", st.session_state.important_count)

        with col3:
            st.metric("Suspicious", st.session_state.suspicious_count)

        with col4:
            st.metric("Malicious", st.session_state.malicious_count)

        with col5:
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

            # Threat Intelligence Summary
            threat_summary = agent.get_threat_summary()
            if threat_summary:
                st.subheader("🛡️ Threat Intelligence Summary")

                threat_col1, threat_col2, threat_col3 = st.columns(3)

                with threat_col1:
                    st.metric("Analyzed", threat_summary['total_analyzed'])

                with threat_col2:
                    st.metric("Malicious", threat_summary['malicious_count'])

                with threat_col3:
                    st.metric("Suspicious", threat_summary['suspicious_count'])

                if threat_summary['threat_indicators']:
                    st.write("**Top Threat Indicators:**")
                    for indicator, count in threat_summary['threat_indicators']:
                        st.write(f"• {indicator}: {count}")
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

                # Check for malicious threat intelligence
                threat_intel = email.get('threat_intelligence')
                if threat_intel and threat_intel.get('is_malicious', False):
                    border_color = "#dc3545"
                    bg_color = "#f8d7da"
                    icon = "🚨"
                    category_color = "#dc3545"

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

                                        # Determine notification type
                                        notification_type = category
                                        if threat_intel and threat_intel.get('is_malicious', False):
                                            notification_type = 'malicious'

                                        success = run_async_function(
                                            agent.notifier.send_notification(mock_email, notification_type)
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

                                # Show threat intelligence if available
                                if threat_intel:
                                    st.write("**Threat Intelligence:**")
                                    st.write(
                                        f"• **Malicious:** {'Yes' if threat_intel.get('is_malicious', False) else 'No'}")
                                    st.write(f"• **Risk Score:** {threat_intel.get('risk_score', 0.0):.2f}")
                                    if threat_intel.get('threat_indicators'):
                                        st.write(f"• **Indicators:** {', '.join(threat_intel['threat_indicators'])}")

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

                # Important, Suspicious, and Malicious emails sections
                if (summary['details']['important_emails'] or
                        summary['details']['suspicious_emails'] or
                        summary['details'].get('malicious_emails')):
                    st.markdown("---")
                    st.subheader("🔍 Attention Required")

                    alert_col1, alert_col2, alert_col3 = st.columns(3)

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

                    with alert_col3:
                        if summary['details'].get('malicious_emails'):
                            st.write(f"**🚨 Malicious Emails ({len(summary['details']['malicious_emails'])})**")
                            with st.expander("View Malicious Emails", expanded=False):
                                for email in summary['details']['malicious_emails'][:5]:  # Show first 5
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

                stat_col1, stat_col2, stat_col3, stat_col4, stat_col5 = st.columns(5)

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

                with stat_col5:
                    malicious_count = len(summary['details'].get('malicious_emails', []))
                    st.metric(
                        "Malicious",
                        malicious_count,
                        delta="🚨" if malicious_count > 0 else "✅"
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
                new_emails = run_async_function(process_emails_for_streamlit())
                if new_emails:
                    st.toast(f"📧 {len(new_emails)} new emails detected!")
            except Exception as e:
                add_log(f"Auto-check error: {str(e)}")

            # Rerun to update the display
            time.sleep(5)  # Brief pause before rerun
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
