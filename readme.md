# 🌐 Email Monitoring Agent Web Interface Guide

This guide explains how to use the Streamlit web interface for the Email Monitoring Agent.

## 🚀 Getting Started

### Starting the Web Interface

\`\`\`bash
# Start the Streamlit web interface
streamlit run app.py
\`\`\`

The web interface will be available at `http://localhost:8501` in your browser.

## 📋 Interface Overview

The web interface is organized into several tabs:

1. **📊 Dashboard** - Overview and statistics
2. **📧 Email List** - List of processed emails
3. **🧠 Learning** - Learning system statistics and controls
4. **📝 Logs** - Activity logs

## 🎛️ Controls

The sidebar contains controls for the email monitoring system:

### Status Indicators

- **✅ ACTIVE** / **⏸️ PAUSED** - Current monitoring status
- **📱 SMS ON** / **📱 SMS OFF** - SMS notification status

### Control Buttons

- **▶️ Start** - Start email monitoring
- **⏸️ Pause** - Pause email monitoring
- **🔍 Check Now** - Manually check for new emails
- **📱 Test SMS** - Send a test SMS notification

### Settings

- **Polling Interval** - Adjust how often emails are checked (in seconds)
- **🗑️ Clear Data** - Clear all stored email data

## 📊 Dashboard

The Dashboard tab provides an overview of your email monitoring:

### Statistics

- **Total Emails** - Total number of processed emails
- **Important** - Number of important emails
- **Suspicious** - Number of suspicious emails
- **Last Check** - Time since last email check

### Charts

- **Categories Distribution** - Bar chart showing email categories
- **Emails Over Time** - Line chart showing email volume over time

## 📧 Email List

The Email List tab shows all processed emails:

### Filtering and Sorting

- **Filter by Category** - Show only emails of a specific category
- **Sort by** - Sort emails by newest, oldest, category, or sender

### Email Cards

Each email is displayed as a card with:

- **Subject** - Email subject
- **Sender** - Email sender
- **Category** - Classification category with color coding
- **Time** - When the email was received

### Email Actions

Each email card has action buttons:

- **📖 Preview** - View email content preview
- **📊 Details** - View detailed classification information
- **📱 Send SMS** - Send SMS notification for this email (for important/suspicious)

### Feedback System

Each email card has a feedback section:

1. Click **🧠 Provide Feedback**
2. Choose **✅ Correct** or **❌ Incorrect**
3. If incorrect, select the correct category

## 🧠 Learning

The Learning tab provides information about the AI learning system:

### Model Information

- **Model Version** - Current version of the learned model
- **Model Trained** - Whether the model has been trained
- **Available Training Data** - Amount of data available for training

### Training Requirements

- Shows requirements for automatic training
- Displays current class distribution
- Indicates if the system is ready for training

### Accuracy Metrics

- **Overall Accuracy** - Overall classification accuracy
- **Category Accuracy** - Accuracy broken down by category

### Recent Feedback

- Shows recent feedback submissions
- Displays success/error messages

## 📝 Logs

The Logs tab shows recent activity in the system:

- Email processing events
- Classification results
- System status changes
- Errors and warnings

## 🔄 Auto-Refresh

The web interface automatically refreshes to:

- Check for new emails based on the polling interval
- Update the countdown timer
- Show real-time status

## 📱 Mobile View

The interface is responsive and works on mobile devices:

- Sidebar collapses to a hamburger menu
- Cards stack vertically
- Controls remain accessible

## 🛠️ Troubleshooting

### Common Issues

1. **Interface Not Loading**
   - Check that Streamlit is installed: `pip install streamlit`
   - Ensure you're running the command from the project directory

2. **No Emails Showing**
   - Click "Check Now" to manually fetch emails
   - Verify Gmail API credentials are set up correctly
   - Check logs for any connection errors

3. **Charts Not Updating**
   - Refresh the page
   - Ensure there's enough data to display charts

4. **SMS Testing Fails**
   - Verify Twilio credentials in `config/credentials.env`
   - Check logs for specific Twilio errors

### Browser Compatibility

The web interface works best with:
- Chrome
- Firefox
- Edge
- Safari

## 🔒 Security Notes

- The web interface runs locally by default
- To expose it to the network, use: `streamlit run app.py --server.address 0.0.0.0`
- Consider adding authentication for network access
