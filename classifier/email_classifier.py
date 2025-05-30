import logging
import re
import json
import os
from transformers import pipeline
from collections import defaultdict
import torch

from learning.active_learner import ActiveLearner


class EmailClassifier:
    def __init__(self, rules_file="classification_rules.json"):
        """
        Initialize Email Classifier with learning capabilities
        """
        self.logger = logging.getLogger(__name__)

        # Use the single best model for email classification
        self.model_name = "microsoft/deberta-v2-xlarge-mnli"

        # Initialize zero-shot classification pipeline
        self.classifier = self._load_model()

        # Initialize active learner
        self.active_learner = ActiveLearner()

        # Email classification categories
        self.categories = [
            'normal',
            'important',
            'suspicious'
        ]

        # Email-specific classification hypotheses for better accuracy
        self.category_hypotheses = {
            'important': "This email requires immediate attention or action",
            'suspicious': "This email is spam or a phishing attempt",
            'normal': "This email is routine correspondence"
        }

        # Load classification rules (now only used for pattern analysis)
        self.rules = self._load_classification_rules(rules_file)

    def _load_model(self):
        """Load the best email classification model"""
        try:
            self.logger.info(f"Loading best email classification model: {self.model_name}")

            classifier = pipeline(
                "zero-shot-classification",
                model=self.model_name,
                device=0 if self._has_gpu() else -1,
                torch_dtype=torch.float16 if self._has_gpu() else torch.float32
            )

            self.logger.info(f"Successfully loaded {self.model_name}")
            return classifier

        except Exception as e:
            self.logger.error(f"Failed to load {self.model_name}: {e}")

            # Single fallback to a reliable model
            fallback_model = "roberta-large-mnli"
            try:
                self.logger.info(f"Trying fallback model: {fallback_model}")
                classifier = pipeline(
                    "zero-shot-classification",
                    model=fallback_model,
                    device=-1  # Use CPU for fallback
                )
                self.logger.info(f"Successfully loaded fallback model: {fallback_model}")
                self.model_name = fallback_model
                return classifier
            except Exception as fallback_error:
                self.logger.error(f"Fallback model also failed: {fallback_error}")
                return None

    def _has_gpu(self):
        """Check if GPU is available"""
        try:
            import torch
            return torch.cuda.is_available()
        except ImportError:
            return False

    def get_model_info(self):
        """Get information about the current model"""
        learning_stats = self.active_learner.get_learning_stats()

        return {
            'current_model': self.model_name,
            'name': 'DeBERTa-v2 XLarge MNLI (Best for Email)',
            'specialty': 'Natural Language Inference - Optimized for email classification',
            'gpu_available': self._has_gpu(),
            'using_gpu': self._has_gpu() and self.classifier is not None,
            'learning_enabled': True,
            'learned_model_version': learning_stats['model_version'],
            'learned_model_trained': learning_stats['is_trained']
        }

    def _load_classification_rules(self, rules_file):
        """Load classification rules from JSON file or use defaults"""
        default_rules = {
            "email_patterns": {
                "important_keywords": [
                    "urgent", "asap", "deadline", "meeting", "call", "response required",
                    "action needed", "please review", "approval", "decision", "budget",
                    "contract", "proposal", "client", "customer", "boss", "manager",
                    "cohort", "start", "when", "schedule", "registration", "enrollment"
                ],
                "suspicious_keywords": [
                    "click here", "verify account", "suspended", "expired", "winner",
                    "congratulations", "free", "limited time", "act now", "bitcoin",
                    "cryptocurrency", "investment", "loan", "credit", "inheritance"
                ]
            }
        }

        try:
            if os.path.exists(rules_file):
                with open(rules_file, 'r') as f:
                    loaded_rules = json.load(f)
                    # Merge with defaults
                    for key in default_rules:
                        if key not in loaded_rules:
                            loaded_rules[key] = default_rules[key]
                    self.logger.info(f"Classification rules loaded from {rules_file}")
                    return loaded_rules
            else:
                self.logger.warning(f"Rules file not found: {rules_file}. Using default rules.")
                return default_rules
        except Exception as e:
            self.logger.error(f"Error loading rules file: {e}. Using default rules.")
            return default_rules

    def _preprocess_email_text(self, email):
        """Enhanced preprocessing for email content"""
        subject = email.get('subject', '')
        body = email.get('body', '')
        sender = email.get('from', '')

        # Create comprehensive text representation
        email_text = f"Subject: {subject}\nFrom: {sender}\nContent: {body}"

        if not email_text.strip():
            return ""

        # Remove email signatures and excessive whitespace
        email_text = re.sub(r'\n--\s*\n.*$', '', email_text, flags=re.DOTALL)
        email_text = re.sub(r'\nBest regards.*$', '', email_text, flags=re.DOTALL | re.IGNORECASE)
        email_text = re.sub(r'\n\s*\n', '\n\n', email_text)
        email_text = re.sub(r' +', ' ', email_text)

        return email_text.strip()[:2000]

    def classify(self, email):
        """Classify an email using both base model and learned model"""
        if not self.classifier:
            return {
                'category': 'unknown',
                'confidence': 0.0,
                'details': {'error': 'Classifier not available'}
            }

        try:
            # Preprocess email text
            processed_text = self._preprocess_email_text(email)

            if not processed_text:
                return {
                    'category': 'normal',
                    'confidence': 0.5,
                    'details': {
                        'subject': email.get('subject', 'No Subject'),
                        'sender': email.get('from', 'Unknown Sender'),
                        'note': 'No content to classify'
                    }
                }

            # Get prediction from base model
            base_prediction = self._classify_with_base_model(processed_text, email)

            # Get prediction from learned model if available
            learned_prediction = self.active_learner.predict_with_learned_model(processed_text)

            # Combine predictions (prioritize learned model if confident)
            final_prediction = self._combine_predictions(base_prediction, learned_prediction)

            return final_prediction

        except Exception as e:
            self.logger.error(f"Classification error: {e}")
            return {
                'category': 'unknown',
                'confidence': 0.0,
                'details': {
                    'error': str(e),
                    'subject': email.get('subject', 'No Subject'),
                    'sender': email.get('from', 'Unknown Sender')
                }
            }

    def _classify_with_base_model(self, processed_text, email):
        """Classify using the base transformer model"""
        # Use enhanced hypotheses for classification
        hypotheses = [self.category_hypotheses[cat] for cat in self.categories]

        # Perform zero-shot classification
        result = self.classifier(processed_text, hypotheses, multi_label=False)

        # Map back to categories and get all scores
        hypothesis_to_category = {v: k for k, v in self.category_hypotheses.items()}
        all_scores = {}

        for i, hypothesis in enumerate(result['labels']):
            category = hypothesis_to_category.get(hypothesis, 'normal')
            confidence = result['scores'][i]
            all_scores[category] = confidence

        # Pick the category with the highest confidence score
        top_category = max(all_scores, key=all_scores.get)
        top_confidence = all_scores[top_category]

        return {
            'category': top_category,
            'confidence': top_confidence,
            'all_scores': all_scores,
            'source': 'base_model',
            'model_used': self.model_name
        }

    def _combine_predictions(self, base_prediction, learned_prediction):
        """Combine base model and learned model predictions"""
        if not learned_prediction:
            # No learned model available, use base model
            return {
                'category': base_prediction['category'],
                'confidence': base_prediction['confidence'],
                'details': {
                    'all_scores': base_prediction['all_scores'],
                    'model_used': base_prediction['model_used'],
                    'source': 'base_model_only',
                    'classification_method': 'pure_highest_confidence'
                }
            }

        # Both models available - use learned model if confident enough
        if learned_prediction['confidence'] > 0.7:
            return {
                'category': learned_prediction['category'],
                'confidence': learned_prediction['confidence'],
                'details': {
                    'all_scores': learned_prediction['all_scores'],
                    'base_prediction': base_prediction['category'],
                    'base_confidence': base_prediction['confidence'],
                    'model_used': f"learned_v{learned_prediction['model_version']}",
                    'source': 'learned_model_primary',
                    'classification_method': 'learned_model_confident'
                }
            }
        else:
            # Use base model but include learned model info
            return {
                'category': base_prediction['category'],
                'confidence': base_prediction['confidence'],
                'details': {
                    'all_scores': base_prediction['all_scores'],
                    'learned_prediction': learned_prediction['category'],
                    'learned_confidence': learned_prediction['confidence'],
                    'model_used': base_prediction['model_used'],
                    'source': 'base_model_fallback',
                    'classification_method': 'base_model_with_learned_context'
                }
            }

    def collect_user_feedback(self, email_data, prediction, user_category, is_correct):
        """Collect user feedback for learning"""
        return self.active_learner.collect_feedback(email_data, prediction, user_category, is_correct)

    def get_learning_stats(self):
        """Get learning system statistics"""
        return self.active_learner.get_learning_stats()

    def classify_batch(self, emails):
        """Classify multiple emails"""
        return [self.classify(email) for email in emails]

    def get_category_stats(self, classifications):
        """Get statistics about classification results"""
        if not classifications:
            return {}

        categories = [c['category'] for c in classifications]
        confidences = [c['confidence'] for c in classifications]

        category_counts = defaultdict(int)
        category_confidences = defaultdict(list)

        for category, confidence in zip(categories, confidences):
            category_counts[category] += 1
            category_confidences[category].append(confidence)

        return {
            'total_emails': len(classifications),
            'category_counts': dict(category_counts),
            'category_percentages': {
                cat: (count / len(classifications)) * 100
                for cat, count in category_counts.items()
            },
            'average_confidence': sum(confidences) / len(confidences),
            'category_avg_confidence': {
                cat: sum(confs) / len(confs)
                for cat, confs in category_confidences.items()
            },
            'model_used': self.model_name
        }
