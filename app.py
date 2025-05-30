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
import html
from collections import Counter, defaultdict

# Import the refactored modules
try:
    from core.email_agent import EmailMonitoringAgent
    from utils.helpers import setup_logging
except ImportError as e:
    st.error(f"Import error: {e}")
    st.stop()


def run_async_function(func):
    """Helper to run async functions in Streamlit"""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(asyncio.run, func)
                return future.result(timeout=30)
        else:
            return loop.run_until_complete(func)
    except RuntimeError:
        return asyncio.run(func)


def initialize_session_state():
    """Initialize all session state variables"""
    defaults = {
        'monitoring_active': False,
        'emails_processed': [],
        'last_check_time': None,
        'total_emails': 0,
        'important_count': 0,
        'suspicious_count': 0,
        'log_messages': [],
        'agent': None,
        'feedback_messages': []
    }

    for key, default_value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = default_value

    # Initialize agent if not already done
    if st.session_state.agent is None:
        with st.spinner("Initializing Email Agent..."):
            st.session_state.agent = EmailMonitoringAgent()


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


def add_feedback_message(message, type="info"):
    """Add a feedback message to session state"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    st.session_state.feedback_messages.append({
        'message': message,
        'timestamp': timestamp,
        'type': type
    })
    # Keep only last 10 feedback messages
    if len(st.session_state.feedback_messages) > 10:
        st.session_state.feedback_messages = st.session_state.feedback_messages[-10:]


async def process_emails_for_streamlit():
    """Wrapper function to process emails and update Streamlit session state"""
    agent = st.session_state.agent

    try:
        add_log("Checking for new emails...")
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
                'details': classification.get('details', {}),
                'email_id': email.get('id', ''),
                'raw_email': email,
                'raw_classification': classification
            }
            processed_emails.append(email_data)
            add_log(f"Processed: {email_data['subject']} - {email_data['category']}")

            # Update counters in session state
            st.session_state.total_emails += 1
            category = classification.get('category', '').lower()
            if category == 'important':
                st.session_state.important_count += 1
            elif category == 'suspicious':
                st.session_state.suspicious_count += 1

        # Add to session state
        st.session_state.emails_processed.extend(processed_emails)
        st.session_state.last_check_time = datetime.now()

        add_log(f"Added {len(processed_emails)} emails to UI")
        return processed_emails

    except Exception as e:
        add_log(f"Error in email processing: {str(e)}")
        st.error(f"Error processing emails: {str(e)}")
        return []


def handle_feedback(email_data, is_correct, correct_category=None):
    """Handle user feedback on email classification"""
    agent = st.session_state.agent

    try:
        # Get raw email and classification data
        raw_email = email_data.get('raw_email', {})
        raw_classification = email_data.get('raw_classification', {})

        if not raw_email or not raw_classification:
            st.error("Missing email data for feedback")
            return False

        # If correct, use the original category
        if is_correct:
            correct_category = raw_classification.get('category', 'normal')

        # Save feedback
        success = agent.classifier.collect_user_feedback(
            raw_email, raw_classification, correct_category, is_correct
        )

        if success:
            if is_correct:
                add_feedback_message(f"✅ Classification '{email_data['category']}' marked as correct", "success")
            else:
                add_feedback_message(f"✅ Classification corrected to '{correct_category}'", "success")
            return True
        else:
            add_feedback_message("❌ Failed to save feedback", "error")
            return False

    except Exception as e:
        add_feedback_message(f"❌ Error saving feedback: {str(e)}", "error")
        return False


def render_email_card(email, index):
    """Render a single email card with improved styling and feedback options"""
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
    else:  # normal
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

        # Action buttons
        col1, col2, col3 = st.columns([1, 1, 1])

        with col1:
            if st.button("📖 Preview", key=f"preview_{index}", help="View email preview"):
                st.session_state[f"show_preview_{index}"] = not st.session_state.get(f"show_preview_{index}", False)

        with col2:
            if st.button("📊 Details", key=f"details_{index}", help="View detailed information"):
                st.session_state[f"show_details_{index}"] = not st.session_state.get(f"show_details_{index}", False)

        with col3:
            if category in ['important', 'suspicious'] and st.session_state.agent.notifier:
                if st.button("📱 Send SMS", key=f"sms_{index}", help="Send SMS notification"):
                    with st.spinner("Sending SMS..."):
                        try:
                            mock_email = {
                                'from': email['from'],
                                'subject': email['subject'],
                                'body': email['body_preview']
                            }

                            success = run_async_function(
                                st.session_state.agent.notifier.send_notification(mock_email, category)
                            )
                            if success:
                                st.success("SMS sent!")
                            else:
                                st.error("SMS failed")
                        except Exception as e:
                            st.error(f"SMS error: {e}")

        # Show preview if toggled
        if st.session_state.get(f"show_preview_{index}", False) and email['body_preview']:
            with st.expander("📖 Email Preview", expanded=True):
                st.text_area(
                    "Email Content Preview",
                    value=email['body_preview'],
                    height=200,
                    key=f"preview_text_{index}",
                    disabled=True
                )

        # Show details if toggled
        if st.session_state.get(f"show_details_{index}", False):
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

                    # Show all classification scores if available
                    details = email.get('details', {})
                    if details.get('all_scores'):
                        st.write("**All Scores:**")
                        for cat, score in details.get('all_scores', {}).items():
                            st.write(f"• {cat}: {score:.2%}")

        # Feedback section
        with st.expander("🧠 Provide Feedback", expanded=False):
            st.write("**Is this classification correct?**")

            feedback_col1, feedback_col2 = st.columns(2)

            with feedback_col1:
                if st.button("✅ Correct", key=f"correct_{index}"):
                    if handle_feedback(email, True):
                        st.success(f"Feedback saved: '{email['category']}' is correct")

            with feedback_col2:
                if st.button("❌ Incorrect", key=f"incorrect_{index}"):
                    st.session_state[f"show_correction_{index}"] = True

            # Show correction options if marked as incorrect
            if st.session_state.get(f"show_correction_{index}", False):
                st.write("**What should be the correct category?**")

                correction_col1, correction_col2, correction_col3 = st.columns(3)

                with correction_col1:
                    if st.button("Normal", key=f"normal_{index}"):
                        if handle_feedback(email, False, "normal"):
                            st.success("Feedback saved: Corrected to 'normal'")
                            st.session_state[f"show_correction_{index}"] = False

                with correction_col2:
                    if st.button("Important", key=f"important_{index}"):
                        if handle_feedback(email, False, "important"):
                            st.success("Feedback saved: Corrected to 'important'")
                            st.session_state[f"show_correction_{index}"] = False

                with correction_col3:
                    if st.button("Suspicious", key=f"suspicious_{index}"):
                        if handle_feedback(email, False, "suspicious"):
                            st.success("Feedback saved: Corrected to 'suspicious'")
                            st.session_state[f"show_correction_{index}"] = False


def check_for_new_emails():
    """Check if we should fetch new emails based on monitoring status and timing"""
    agent = st.session_state.agent

    # Only check if monitoring is active and fetcher is available
    if not st.session_state.monitoring_active:
        return False

    if not agent.fetcher or not agent.fetcher.gmail_service:
        return False

    # Check if it's time for a new check
    if st.session_state.last_check_time is None:
        return True

    time_since_last = (datetime.now() - st.session_state.last_check_time).total_seconds()
    return time_since_last >= agent.polling_interval


def display_status_bar():
    """Display status bar with time until next check"""
    agent = st.session_state.agent

    if not st.session_state.last_check_time:
        return

    time_since_last = (datetime.now() - st.session_state.last_check_time).total_seconds()
    time_remaining = max(0, agent.polling_interval - time_since_last)

    with st.container():
        st.write(f"⏰ Next check in {int(time_remaining)} seconds...")
        progress = min(1.0, time_since_last / agent.polling_interval)
        st.progress(progress)


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
    st.markdown("*Powered by Zero-Shot Classification with Active Learning*")
    st.markdown("---")

    # Check component status
    components_status = []
    if agent.fetcher and agent.fetcher.gmail_service:
        components_status.append("✅ Gmail Fetcher")
    else:
        components_status.append("❌ Gmail Fetcher")

    if agent.classifier and agent.classifier.classifier:
        components_status.append("✅ Zero-Shot Classifier")
    else:
        components_status.append("❌ Zero-Shot Classifier")

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

        st.markdown("---")

        # Control buttons
        col1, col2 = st.columns(2)
        with col1:
            if st.button("▶️ Start"):
                if not agent.fetcher or not agent.fetcher.gmail_service:
                    st.error("Gmail fetcher not available!")
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
            if not agent.fetcher or not agent.fetcher.gmail_service:
                st.error("Gmail fetcher not available!")
            else:
                with st.spinner("Checking for new emails..."):
                    try:
                        new_emails = run_async_function(process_emails_for_streamlit())
                        if new_emails:
                            st.success(f"Found {len(new_emails)} new emails!")
                            # Force rerun to update UI immediately
                            st.rerun()
                        else:
                            st.info("No new emails found")
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

        st.markdown("---")
        st.subheader("🧠 Learning System")

        # Display learning stats
        learning_stats = agent.classifier.get_learning_stats()

        st.write(f"**Model Version:** v{learning_stats['model_version']}")
        st.write(f"**Model Trained:** {'Yes ✅' if learning_stats['is_trained'] else 'No ❌'}")

        feedback_stats = learning_stats.get('feedback_stats', {})
        if feedback_stats:
            st.write(f"**Total Feedback:** {feedback_stats.get('total_feedback', 0)}")
            st.write(f"**Training Examples:** {feedback_stats.get('training_examples', 0)}")
            st.write(f"**Overall Accuracy:** {feedback_stats.get('overall_accuracy', 0):.1f}%")

        # Retrain button
        if st.button("🔄 Retrain Model"):
            with st.spinner("Retraining model..."):
                try:
                    success = agent.classifier.active_learner.retrain_model()
                    if success:
                        st.success("Model retrained successfully!")
                    else:
                        st.warning("Not enough training data for retraining")
                except Exception as e:
                    st.error(f"Error retraining model: {e}")

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
            agent.clear_data()
            st.success("Data cleared!")
            st.rerun()

    # Main content area with tabs
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Dashboard", "📧 Email List", "🧠 Learning", "📝 Logs"])

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
            categories = ['All'] + list(set([email['category'] for email in st.session_state.emails_processed]))
            selected_category = st.selectbox("Filter by Category", categories, key="category_filter")
        with col3:
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

            # Display emails
            for i, email in enumerate(filtered_emails):
                render_email_card(email, i)
        else:
            # Empty state
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
        st.subheader("🧠 Learning System")

        # Learning stats
        learning_stats = agent.classifier.get_learning_stats()
        feedback_stats = learning_stats.get('feedback_stats', {})

        col1, col2 = st.columns(2)

        with col1:
            st.write("### Model Information")
            st.write(f"**Model Version:** v{learning_stats['model_version']}")
            st.write(f"**Model Trained:** {'Yes ✅' if learning_stats['is_trained'] else 'No ❌'}")
            st.write(f"**Available Training Data:** {learning_stats.get('available_training_data', 0)}")

            if feedback_stats:
                st.write(f"**Total Feedback:** {feedback_stats.get('total_feedback', 0)}")
                st.write(f"**Training Examples:** {feedback_stats.get('training_examples', 0)}")

        with col2:
            st.write("### Accuracy Metrics")

            if feedback_stats and feedback_stats.get('total_feedback', 0) > 0:
                st.write(f"**Overall Accuracy:** {feedback_stats.get('overall_accuracy', 0):.1f}%")

                # Category accuracy
                st.write("**Category Accuracy:**")
                for category, cat_stats in feedback_stats.get('category_stats', {}).items():
                    accuracy = cat_stats.get('accuracy', 0)
                    correct = cat_stats.get('correct', 0)
                    total = cat_stats.get('total', 0)

                    # Color based on accuracy
                    if accuracy >= 80:
                        color = "green"
                    elif accuracy >= 60:
                        color = "orange"
                    else:
                        color = "red"

                    st.markdown(
                        f"- **{category}**: <span style='color:{color}'>{accuracy:.1f}%</span> ({correct}/{total})",
                        unsafe_allow_html=True)
            else:
                st.info(
                    "No feedback data available yet. Provide feedback on email classifications to improve the model.")

        # Recent feedback
        st.write("### Recent Feedback")

        if st.session_state.feedback_messages:
            for msg in reversed(st.session_state.feedback_messages):
                if msg['type'] == "success":
                    st.success(f"[{msg['timestamp']}] {msg['message']}")
                elif msg['type'] == "error":
                    st.error(f"[{msg['timestamp']}] {msg['message']}")
                else:
                    st.info(f"[{msg['timestamp']}] {msg['message']}")
        else:
            st.info("No feedback provided yet.")

    with tab4:
        st.subheader("📝 Activity Logs")

        if st.session_state.log_messages:
            log_container = st.container()
            with log_container:
                for log_msg in reversed(st.session_state.log_messages[-20:]):
                    st.text(log_msg)
        else:
            st.info("No log messages yet.")

    # Auto-refresh functionality - completely restructured
    # Check if we should fetch new emails
    should_check_emails = check_for_new_emails()

    if should_check_emails:
        try:
            with st.spinner("Checking for new emails..."):
                new_emails = run_async_function(process_emails_for_streamlit())
                if new_emails:
                    st.toast(f"📧 {len(new_emails)} new emails detected!")
                    # Force rerun to update UI
                    st.rerun()
        except Exception as e:
            add_log(f"Auto-check error: {str(e)}")
            st.error(f"Auto-check error: {str(e)}")

        # Shorter sleep before rerun
        time.sleep(2)
        st.rerun()
    else:
        # Display status bar with time until next check
        display_status_bar()

        # Auto-refresh every 5 seconds to update countdown
        time.sleep(5)
        st.rerun()


if __name__ == "__main__":
    main()
