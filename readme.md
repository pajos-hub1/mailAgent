# AI Email Monitoring Agent (Gmail Edition)

## Overview

An intelligent email monitoring tool that uses AI to classify and prioritize new emails from Gmail, providing real-time insights into your inbox.

## Key Features

- Real-time new email detection
- AI-powered email classification
- Zero-shot classification model
- Terminal-based notifications
- Gmail API integration

## Classification Categories

- Important
- Suspicious
- Newsletter
- Personal
- Low-priority

## Prerequisites

- Python 3.8+
- Google Cloud Console account
- Gmail account

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ai-email-agent.git
cd ai-email-agent
```

2. Create virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Gmail API Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project
3. Enable Gmail API
4. Create OAuth 2.0 credentials
5. Download credentials
6. Save as `gmail_credentials.json`

## Configuration

No additional configuration required. The first run will guide you through OAuth authentication.

## Running the Application

```bash
python main.py
```

On first run:
- A browser window will open for Google account authorization
- Select your Gmail account
- Grant necessary permissions
- Token will be saved for future use

## Example Output

```
10 new email(s) found.

==================================================
New Email Received
==================================================
Subject: Team Meeting Invitation
From: colleague@company.com
Category: important
Confidence: 87.5%
Preview: Join us for our weekly team sync-up...
==================================================
```

## How It Works

1. Fetch new emails using Gmail API
2. Preprocess email content
3. Use Facebook's BART-MNLI model for zero-shot classification
4. Apply custom classification rules
5. Display results in terminal

## Customization

Modify `analysis/classifier.py` to:
- Add custom classification rules
- Adjust confidence thresholds
- Extend classification categories

## Troubleshooting

- Delete `cgmail_token.json` to re-authenticate
- Check internet connection
- Verify Gmail API permissions

## Technologies

- Python
- Gmail API
- Transformers (Hugging Face)
- Zero-shot Classification

## Security

- OAuth 2.0 authentication
- No storage of email credentials
- Minimal data retention

## Roadmap

- [ ] Add more email providers
- [ ] Create persistent storage for classifications
- [ ] Develop web dashboard
- [ ] Implement machine learning model training

## Limitations

- Requires initial manual authentication
- Relies on pre-trained zero-shot model
- Limited to Gmail

## Contributing

1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create pull request

## License

MIT License

## Support

Open an issue in the GitHub repository