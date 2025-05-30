import logging
from typing import Dict, List, Tuple
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
import pickle
import os
from datetime import datetime
from collections import Counter

from database.feedback_db import FeedbackDatabase


class ActiveLearner:
    def __init__(self):
        """Initialize active learning system"""
        self.logger = logging.getLogger(__name__)
        self.db = FeedbackDatabase()

        # Initialize models
        self.vectorizer = TfidfVectorizer(max_features=5000, stop_words='english')
        self.classifier = LogisticRegression(random_state=42)

        # Model state
        self.is_trained = False
        self.model_version = 0

        # Minimum requirements for training (lowered since we now use ALL feedback)
        self.min_examples_per_class = 1  # Lowered since we get more data
        self.min_total_examples = 3  # Lowered since we get more data
        self.min_classes = 2

        # Load existing model if available
        self.load_model()

    def _truncate_text_for_training(self, text, max_length=10000):
        """Truncate text for training purposes"""
        if not text:
            return ""

        if len(text) <= max_length:
            return text

        # For training, we want to keep the most relevant parts
        # Keep beginning and end, skip middle if too long
        if max_length > 1000:
            keep_start = max_length // 2
            keep_end = max_length - keep_start - 50
            return text[:keep_start] + "\n[...TRUNCATED...]\n" + text[-keep_end:]
        else:
            return text[:max_length - 20] + "\n[...TRUNCATED...]"

    def collect_feedback(self, email_data: Dict, prediction: Dict, user_category: str, is_correct: bool) -> bool:
        """Collect user feedback and store in database"""
        user_feedback = {
            'correct_category': user_category,
            'is_correct': is_correct
        }

        # Truncate email data before saving to prevent database errors
        truncated_email_data = {
            'id': email_data.get('id', '')[:255],
            'subject': email_data.get('subject', '')[:1000],
            'from': email_data.get('from', '')[:500],
            'body': self._truncate_text_for_training(email_data.get('body', ''), 50000),
            'date': email_data.get('date', ''),
            'labels': email_data.get('labels', []),
            'thread_id': email_data.get('thread_id', '')
        }

        success = self.db.save_feedback(truncated_email_data, prediction, user_feedback)

        if success:
            feedback_type = "confirmation" if is_correct else "correction"
            self.logger.info(
                f"Feedback collected ({feedback_type}): {prediction['category']} -> {user_category} (correct: {is_correct})")

            # Trigger retraining if we have enough new examples
            self.check_retrain_trigger()

        return success

    def check_retrain_trigger(self):
        """Check if we should retrain the model"""
        training_data = self.db.get_training_data(limit=100)  # Get more examples to check diversity

        if len(training_data) >= self.min_total_examples:
            # Check class distribution
            class_counts = Counter(item['category'] for item in training_data)

            # Check if we have enough classes and examples per class
            if len(class_counts) >= self.min_classes:
                min_examples = min(class_counts.values())
                if min_examples >= self.min_examples_per_class:
                    # Count feedback types
                    feedback_types = Counter(item['feedback_type'] for item in training_data)
                    self.logger.info(
                        f"Triggering retraining with {len(training_data)} examples across {len(class_counts)} classes")
                    self.logger.info(f"Feedback breakdown: {dict(feedback_types)}")
                    self.retrain_model()
                else:
                    self.logger.info(
                        f"Not enough examples per class for retraining. Min examples per class: {min_examples}, required: {self.min_examples_per_class}")
            else:
                self.logger.info(
                    f"Not enough class diversity for retraining. Classes: {len(class_counts)}, required: {self.min_classes}")
                self.logger.info(f"Current classes: {list(class_counts.keys())}")
        else:
            self.logger.info(
                f"Not enough total examples for retraining. Current: {len(training_data)}, required: {self.min_total_examples}")

    def retrain_model(self) -> bool:
        """Retrain the model with new feedback data"""
        try:
            # Get training data from database
            training_data = self.db.get_training_data(limit=1000)

            if len(training_data) < self.min_total_examples:
                self.logger.warning(
                    f"Not enough training data for retraining. Have {len(training_data)}, need {self.min_total_examples}")
                return False

            # Prepare training data with text truncation
            texts = []
            labels = []
            feedback_types = []

            for item in training_data:
                # Truncate text for training
                text = self._truncate_text_for_training(item['text'], 5000)
                texts.append(text)
                labels.append(item['category'])
                feedback_types.append(item.get('feedback_type', 'unknown'))

            # Check class distribution
            class_counts = Counter(labels)
            feedback_type_counts = Counter(feedback_types)

            self.logger.info(f"Training data class distribution: {dict(class_counts)}")
            self.logger.info(f"Training data feedback types: {dict(feedback_type_counts)}")

            # Validate we have enough classes and examples per class
            if len(class_counts) < self.min_classes:
                self.logger.warning(
                    f"Not enough classes for training. Have {len(class_counts)}, need {self.min_classes}")
                self.logger.warning(f"Available classes: {list(class_counts.keys())}")
                return False

            min_examples = min(class_counts.values())
            if min_examples < self.min_examples_per_class:
                self.logger.warning(
                    f"Not enough examples per class. Min: {min_examples}, need: {self.min_examples_per_class}")
                return False

            self.logger.info(f"Retraining with {len(texts)} examples across {len(class_counts)} classes")
            self.logger.info(
                f"Using {feedback_type_counts.get('confirmation', 0)} confirmations and {feedback_type_counts.get('correction', 0)} corrections")

            # Vectorize texts
            X = self.vectorizer.fit_transform(texts)

            # Train classifier
            self.classifier.fit(X, labels)

            # Calculate accuracy on training data
            y_pred = self.classifier.predict(X)
            accuracy = accuracy_score(labels, y_pred)

            self.logger.info(f"Model retrained with accuracy: {accuracy:.2%}")

            # Log detailed classification report
            try:
                report = classification_report(labels, y_pred, output_dict=True)
                self.logger.info("Classification report:")
                for class_name, metrics in report.items():
                    if isinstance(metrics, dict) and 'precision' in metrics:
                        self.logger.info(
                            f"  {class_name}: precision={metrics['precision']:.2f}, recall={metrics['recall']:.2f}, f1={metrics['f1-score']:.2f}")
            except Exception as e:
                self.logger.warning(f"Could not generate classification report: {e}")

            # Update model state
            self.is_trained = True
            self.model_version += 1

            # Save model
            self.save_model()

            # Mark training data as used
            self.db.mark_training_data_used(len(training_data))

            return True

        except Exception as e:
            self.logger.error(f"Error retraining model: {e}")
            return False

    def predict_with_learned_model(self, email_text: str) -> Dict:
        """Make prediction using the learned model"""
        if not self.is_trained:
            return None

        try:
            # Truncate input text for prediction
            truncated_text = self._truncate_text_for_training(email_text, 5000)

            # Vectorize input text
            X = self.vectorizer.transform([truncated_text])

            # Get prediction and probabilities
            prediction = self.classifier.predict(X)[0]
            probabilities = self.classifier.predict_proba(X)[0]

            # Get class labels
            classes = self.classifier.classes_

            # Create scores dictionary
            scores = {classes[i]: prob for i, prob in enumerate(probabilities)}

            # Get confidence (max probability)
            confidence = max(probabilities)

            return {
                'category': prediction,
                'confidence': confidence,
                'all_scores': scores,
                'model_version': self.model_version,
                'source': 'learned_model'
            }

        except Exception as e:
            self.logger.error(f"Error making learned prediction: {e}")
            return None

    def save_model(self):
        """Save the trained model to disk"""
        try:
            model_dir = 'models'
            os.makedirs(model_dir, exist_ok=True)

            # Save vectorizer
            with open(f'{model_dir}/vectorizer_v{self.model_version}.pkl', 'wb') as f:
                pickle.dump(self.vectorizer, f)

            # Save classifier
            with open(f'{model_dir}/classifier_v{self.model_version}.pkl', 'wb') as f:
                pickle.dump(self.classifier, f)

            # Save metadata
            metadata = {
                'version': self.model_version,
                'trained_at': datetime.now().isoformat(),
                'is_trained': self.is_trained
            }

            with open(f'{model_dir}/metadata.pkl', 'wb') as f:
                pickle.dump(metadata, f)

            self.logger.info(f"Model v{self.model_version} saved successfully")

        except Exception as e:
            self.logger.error(f"Error saving model: {e}")

    def load_model(self):
        """Load existing model from disk"""
        try:
            model_dir = 'models'
            metadata_path = f'{model_dir}/metadata.pkl'

            if not os.path.exists(metadata_path):
                self.logger.info("No existing model found")
                return

            # Load metadata
            with open(metadata_path, 'rb') as f:
                metadata = pickle.load(f)

            version = metadata['version']

            # Load vectorizer
            with open(f'{model_dir}/vectorizer_v{version}.pkl', 'rb') as f:
                self.vectorizer = pickle.load(f)

            # Load classifier
            with open(f'{model_dir}/classifier_v{version}.pkl', 'rb') as f:
                self.classifier = pickle.load(f)

            self.model_version = version
            self.is_trained = metadata['is_trained']

            self.logger.info(f"Loaded model v{version} (trained: {self.is_trained})")

        except Exception as e:
            self.logger.error(f"Error loading model: {e}")

    def get_learning_stats(self) -> Dict:
        """Get statistics about the learning system"""
        db_stats = self.db.get_feedback_stats()

        # Get training data to analyze class distribution
        training_data = self.db.get_training_data(limit=100)
        class_distribution = Counter(item['category'] for item in training_data)
        feedback_type_distribution = Counter(item.get('feedback_type', 'unknown') for item in training_data)

        # Check if ready for training
        ready_for_training = (
            len(training_data) >= self.min_total_examples and
            len(class_distribution) >= self.min_classes and
            min(class_distribution.values()) >= self.min_examples_per_class if class_distribution else False
        )

        return {
            'model_version': self.model_version,
            'is_trained': self.is_trained,
            'feedback_stats': db_stats,
            'available_training_data': len(training_data),
            'class_distribution': dict(class_distribution),
            'feedback_type_distribution': dict(feedback_type_distribution),
            'ready_for_training': ready_for_training,
            'training_requirements': {
                'min_total_examples': self.min_total_examples,
                'min_classes': self.min_classes,
                'min_examples_per_class': self.min_examples_per_class
            }
        }

    def force_retrain(self) -> bool:
        """Force retraining even with limited data (for testing purposes)"""
        self.logger.info("Force retraining requested")

        training_data = self.db.get_training_data(limit=1000)

        if len(training_data) < 2:
            self.logger.error("Cannot train with less than 2 examples")
            return False

        # Check if we have at least 2 classes
        class_counts = Counter(item['category'] for item in training_data)

        if len(class_counts) < 2:
            self.logger.error(f"Cannot train with only one class: {list(class_counts.keys())}")
            self.logger.info(
                "Need feedback examples from at least 2 different categories (normal, important, suspicious)")
            return False

        # Temporarily lower requirements
        original_min_examples = self.min_examples_per_class
        original_min_total = self.min_total_examples

        self.min_examples_per_class = 1
        self.min_total_examples = 2

        try:
            result = self.retrain_model()
            return result
        finally:
            # Restore original requirements
            self.min_examples_per_class = original_min_examples
            self.min_total_examples = original_min_total
