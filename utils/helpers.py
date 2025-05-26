import os
import logging
import structlog
from logging.handlers import RotatingFileHandler


def setup_logging(log_level=logging.INFO, log_file='./data/logs/email_agent.log'):
    """
    Configure logging for the application

    :param log_level: Logging level (default: INFO)
    :param log_file: Path to log file
    """
    # Ensure log directory exists
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    # Configure basic logging
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            # Console handler
            logging.StreamHandler(),
            # File handler with rotation
            RotatingFileHandler(
                log_file,
                maxBytes=10 * 1024 * 1024,  # 10 MB
                backupCount=5
            )
        ]
    )

    # Configure structlog for structured logging
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    def encrypt_sensitive_data(data, key=None):
        """
        Encrypt sensitive data

        :param data: Data to encrypt
        :param key: Encryption key
        :return: Encrypted data
        """
        import base64
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        # If no key provided, generate a default key
        if not key:
            key = os.getenv('ENCRYPTION_KEY')

        if not key:
            # Generate a random key if not provided
            key = Fernet.generate_key()

        # Derive key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'email_agent_salt',
            iterations=100000,
        )
        derived_key = base64.urlsafe_b64encode(kdf.derive(key.encode()))

        # Create Fernet instance
        f = Fernet(derived_key)

        # Encrypt data
        return f.encrypt(data.encode()).decode()

    def decrypt_sensitive_data(encrypted_data, key=None):
        """
        Decrypt sensitive data

        :param encrypted_data: Data to decrypt
        :param key: Decryption key
        :return: Decrypted data
        """
        import base64
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        # If no key provided, use environment key
        if not key:
            key = os.getenv('ENCRYPTION_KEY')

        if not key:
            raise ValueError("No decryption key provided")

        # Derive key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'email_agent_salt',
            iterations=100000,
        )
        derived_key = base64.urlsafe_b64encode(kdf.derive(key.encode()))

        # Create Fernet instance
        f = Fernet(derived_key)

        # Decrypt data
        return f.decrypt(encrypted_data.encode()).decode()

    def validate_email(email):
        """
        Validate email address format

        :param email: Email address to validate
        :return: Boolean indicating email validity
        """
        import re

        # Regular expression for email validation
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

        return re.match(email_regex, email) is not None

    def generate_unique_id():
        """
        Generate a unique identifier for emails or logs

        :return: Unique identifier string
        """
        import uuid

        return str(uuid.uuid4())

    def sanitize_filename(filename):
        """
        Sanitize filename to remove potentially dangerous characters

        :param filename: Original filename
        :return: Sanitized filename
        """
        import re

        # Remove or replace potentially dangerous characters
        sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)

        # Limit filename length
        return sanitized[:255]


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