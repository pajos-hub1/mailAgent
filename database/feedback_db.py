import logging
import mysql.connector
from mysql.connector import Error
import os
from datetime import datetime
from typing import List, Dict, Optional
import json


class FeedbackDatabase:
    def __init__(self):
        """Initialize MySQL database connection for user feedback"""
        self.logger = logging.getLogger(__name__)
        self.connection = None
        self.connect()
        self.create_tables()

    def connect(self):
        """Connect to MySQL database"""
        try:
            self.connection = mysql.connector.connect(
                host=os.getenv('MYSQL_HOST', 'localhost'),
                port=os.getenv('MYSQL_PORT', 3306),
                database=os.getenv('MYSQL_DATABASE', 'email_agent'),
                user=os.getenv('MYSQL_USER', 'root'),
                password=os.getenv('MYSQL_PASSWORD', ''),
                autocommit=True
            )

            if self.connection.is_connected():
                self.logger.info("Successfully connected to MySQL database")

        except Error as e:
            self.logger.error(f"Error connecting to MySQL: {e}")
            self.connection = None

    def create_tables(self):
        """Create necessary tables for feedback storage"""
        if not self.connection:
            return

        try:
            cursor = self.connection.cursor()

            # Create email_feedback table with proper text field sizes
            create_feedback_table = """
            CREATE TABLE IF NOT EXISTS email_feedback (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email_id VARCHAR(255) NOT NULL,
                email_subject TEXT,
                email_sender VARCHAR(500),
                email_body LONGTEXT,
                predicted_category VARCHAR(50),
                predicted_confidence FLOAT,
                user_category VARCHAR(50),
                is_correct BOOLEAN,
                feedback_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                model_scores JSON,
                email_metadata JSON,
                INDEX idx_email_id (email_id),
                INDEX idx_predicted_category (predicted_category),
                INDEX idx_user_category (user_category),
                INDEX idx_feedback_timestamp (feedback_timestamp)
            )
            """

            cursor.execute(create_feedback_table)

            # Create training_data table for processed training examples
            create_training_table = """
            CREATE TABLE IF NOT EXISTS training_data (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email_text LONGTEXT NOT NULL,
                true_category VARCHAR(50) NOT NULL,
                confidence_score FLOAT,
                feedback_type VARCHAR(20) DEFAULT 'correction',
                created_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                used_for_training BOOLEAN DEFAULT FALSE,
                training_timestamp TIMESTAMP NULL,
                INDEX idx_true_category (true_category),
                INDEX idx_used_for_training (used_for_training),
                INDEX idx_feedback_type (feedback_type)
            )
            """

            cursor.execute(create_training_table)

            # Check if we need to alter existing tables
            self._upgrade_tables(cursor)

            self.logger.info("Database tables created successfully")
            cursor.close()

        except Error as e:
            self.logger.error(f"Error creating tables: {e}")

    def _upgrade_tables(self, cursor):
        """Upgrade existing tables if needed"""
        try:
            # Check if email_body column needs to be upgraded
            cursor.execute("""
                SELECT COLUMN_TYPE 
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME = 'email_feedback' 
                AND COLUMN_NAME = 'email_body'
            """)

            result = cursor.fetchone()
            if result and 'text' in result[0].lower() and 'longtext' not in result[0].lower():
                self.logger.info("Upgrading email_body column to LONGTEXT")
                cursor.execute("ALTER TABLE email_feedback MODIFY COLUMN email_body LONGTEXT")

            # Check if email_text column needs to be upgraded
            cursor.execute("""
                SELECT COLUMN_TYPE 
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME = 'training_data' 
                AND COLUMN_NAME = 'email_text'
            """)

            result = cursor.fetchone()
            if result and 'text' in result[0].lower() and 'longtext' not in result[0].lower():
                self.logger.info("Upgrading email_text column to LONGTEXT")
                cursor.execute("ALTER TABLE training_data MODIFY COLUMN email_text LONGTEXT")

            # Check if feedback_type column exists, if not add it
            cursor.execute("""
                SELECT COLUMN_NAME 
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME = 'training_data' 
                AND COLUMN_NAME = 'feedback_type'
            """)

            result = cursor.fetchone()
            if not result:
                self.logger.info("Adding feedback_type column to training_data table")
                cursor.execute("ALTER TABLE training_data ADD COLUMN feedback_type VARCHAR(20) DEFAULT 'correction'")

        except Error as e:
            self.logger.warning(f"Could not upgrade tables: {e}")

    def _truncate_text(self, text, max_length=65535):
        """Safely truncate text to fit in database column"""
        if not text:
            return ""

        if len(text) <= max_length:
            return text

        # Truncate and add indicator
        truncated = text[:max_length - 50] + "\n\n[... TEXT TRUNCATED ...]"
        return truncated

    def save_feedback(self, email_data: Dict, prediction: Dict, user_feedback: Dict) -> bool:
        """Save user feedback to database"""
        if not self.connection:
            self.logger.error("No database connection available")
            return False

        try:
            cursor = self.connection.cursor()

            # Safely truncate email body and subject
            email_body = self._truncate_text(email_data.get('body', ''), 65535)
            email_subject = self._truncate_text(email_data.get('subject', ''), 65535)
            email_sender = email_data.get('from', '')[:500]  # Limit sender to 500 chars

            insert_query = """
            INSERT INTO email_feedback (
                email_id, email_subject, email_sender, email_body,
                predicted_category, predicted_confidence, user_category,
                is_correct, model_scores, email_metadata
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """

            values = (
                email_data.get('id', '')[:255],  # Limit email_id to 255 chars
                email_subject,
                email_sender,
                email_body,
                prediction.get('category', '')[:50],  # Limit category to 50 chars
                prediction.get('confidence', 0.0),
                user_feedback.get('correct_category', '')[:50],  # Limit category to 50 chars
                user_feedback.get('is_correct', False),
                json.dumps(prediction.get('details', {}).get('all_scores', {})),
                json.dumps({
                    'date': email_data.get('date', ''),
                    'labels': email_data.get('labels', []),
                    'thread_id': email_data.get('thread_id', '')
                })
            )

            cursor.execute(insert_query, values)

            # Add to training data - BOTH correct and incorrect feedback
            self.add_training_example(email_data, user_feedback)

            cursor.close()
            self.logger.info(f"Feedback saved for email: {email_data.get('subject', 'Unknown')[:50]}...")
            return True

        except Error as e:
            self.logger.error(f"Error saving feedback: {e}")
            return False

    def add_training_example(self, email_data: Dict, user_feedback: Dict) -> bool:
        """Add ALL feedback (correct and incorrect) to training data"""
        if not self.connection:
            return False

        try:
            cursor = self.connection.cursor()

            # Create training text from email with proper truncation
            subject = self._truncate_text(email_data.get('subject', ''), 500)
            sender = email_data.get('from', '')[:200]
            body = self._truncate_text(email_data.get('body', ''), 64000)  # Leave room for subject and sender

            email_text = f"Subject: {subject}\nFrom: {sender}\nContent: {body}"

            # Final safety check - truncate to fit LONGTEXT if needed
            email_text = self._truncate_text(email_text, 65535)

            # Use the user's category (which is the correct one for both correct and incorrect feedback)
            correct_category = user_feedback.get('correct_category', '')
            is_correct = user_feedback.get('is_correct', False)

            # Determine feedback type and confidence
            if is_correct:
                feedback_type = 'confirmation'
                confidence_score = 1.0  # High confidence for confirmed correct classifications
            else:
                feedback_type = 'correction'
                confidence_score = 1.0  # High confidence for human corrections

            insert_query = """
            INSERT INTO training_data (email_text, true_category, confidence_score, feedback_type)
            VALUES (%s, %s, %s, %s)
            """

            values = (email_text, correct_category[:50], confidence_score, feedback_type)
            cursor.execute(insert_query, values)
            cursor.close()

            self.logger.info(f"Training example added: {correct_category} ({feedback_type})")
            return True

        except Error as e:
            self.logger.error(f"Error adding training example: {e}")
            return False

    def get_feedback_stats(self) -> Dict:
        """Get statistics about user feedback"""
        if not self.connection:
            return {}

        try:
            cursor = self.connection.cursor()

            # Get overall accuracy
            cursor.execute("SELECT COUNT(*) as total, SUM(is_correct) as correct FROM email_feedback")
            result = cursor.fetchone()
            total_feedback = result[0] if result[0] else 0
            correct_feedback = result[1] if result[1] else 0
            accuracy = (correct_feedback / total_feedback * 100) if total_feedback > 0 else 0

            # Get category-wise accuracy
            cursor.execute("""
                SELECT predicted_category, COUNT(*) as total, SUM(is_correct) as correct
                FROM email_feedback 
                GROUP BY predicted_category
            """)
            category_stats = {}
            for row in cursor.fetchall():
                category = row[0]
                total = row[1]
                correct = row[2] if row[2] else 0
                category_accuracy = (correct / total * 100) if total > 0 else 0
                category_stats[category] = {
                    'total': total,
                    'correct': correct,
                    'accuracy': category_accuracy
                }

            # Get training data count by type
            cursor.execute("""
                SELECT feedback_type, COUNT(*) 
                FROM training_data 
                GROUP BY feedback_type
            """)
            training_breakdown = {}
            total_training = 0
            for row in cursor.fetchall():
                feedback_type = row[0]
                count = row[1]
                training_breakdown[feedback_type] = count
                total_training += count

            cursor.close()

            return {
                'total_feedback': total_feedback,
                'overall_accuracy': accuracy,
                'category_stats': category_stats,
                'training_examples': total_training,
                'training_breakdown': training_breakdown
            }

        except Error as e:
            self.logger.error(f"Error getting feedback stats: {e}")
            return {}

    def get_training_data(self, limit: int = 1000) -> List[Dict]:
        """Get training data for model improvement"""
        if not self.connection:
            return []

        try:
            cursor = self.connection.cursor()

            query = """
            SELECT email_text, true_category, confidence_score, feedback_type
            FROM training_data
            WHERE used_for_training = FALSE
            ORDER BY created_timestamp DESC
            LIMIT %s
            """

            cursor.execute(query, (limit,))
            training_data = []

            for row in cursor.fetchall():
                training_data.append({
                    'text': row[0],
                    'category': row[1],
                    'confidence': row[2],
                    'feedback_type': row[3]
                })

            cursor.close()
            return training_data

        except Exception as e:
            self.logger.error(f"Error getting training data: {e}")
            return []

    def mark_training_data_used(self, count: int) -> bool:
        """Mark training data as used"""
        if not self.connection:
            return False

        try:
            cursor = self.connection.cursor()

            query = """
            UPDATE training_data 
            SET used_for_training = TRUE, training_timestamp = CURRENT_TIMESTAMP
            WHERE used_for_training = FALSE
            ORDER BY created_timestamp DESC
            LIMIT %s
            """

            cursor.execute(query, (count,))
            cursor.close()
            return True

        except Error as e:
            self.logger.error(f"Error marking training data as used: {e}")
            return False

    def close(self):
        """Close database connection"""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            self.logger.info("MySQL connection closed")
