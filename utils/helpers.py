import os
import logging
from logging.handlers import RotatingFileHandler


def setup_logging(log_level=logging.INFO, log_file='./data/logs/email_agent.log'):
    """Configure logging for the application"""
    # Ensure log directory exists
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    # Configure basic logging
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            RotatingFileHandler(
                log_file,
                maxBytes=10 * 1024 * 1024,  # 10 MB
                backupCount=5
            )
        ]
    )


def display_welcome_message():
    print("""
    **************************************
    *      AI Email Monitoring Agent      *
    *         Chatbot Interface          *
    **************************************
    Type 'help' for available commands
    """)


def display_help():
    print("""
    📋 Available Commands:

    Monitoring Control:
    • help - Show this help
    • status - Show current status
    • pause - Pause monitoring
    • resume - Resume monitoring
    • exit - Quit
    """)
