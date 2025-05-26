import logging
import re
import json
import os
from collections import defaultdict
from transformers import pipeline


class EmailClassifier:
    def __init__(self, rules_file="classification_rules.json"):
        """
        Initialize Email Classifier with pre-trained model and custom rules

        :param rules_file: Path to JSON file containing classification rules
        """
        self.logger = logging.getLogger(__name__)

        # Initialize zero-shot classification pipeline
        try:
            self.classifier = pipeline(
                "zero-shot-classification",
                model="facebook/bart-large-mnli"
            )
        except Exception as e:
            self.logger.error(f"Error loading classification model: {e}")
            self.classifier = None

        # Predefined classification categories
        self.categories = [
            'important',
            'suspicious',
            'newsletter',
            'personal',
            'low-priority'
        ]

        # Load classification rules
        self.rules = self._load_classification_rules(rules_file)

    def _load_classification_rules(self, rules_file):
        """
        Load classification rules from JSON file or use defaults

        :param rules_file: Path to JSON file containing rules
        :return: Dictionary of classification rules
        """
        default_rules = {
            "keyword_rules": {
                "suspicious": {
                    "subject": ["urgent", "verify", "account", "security", "bank", "password"],
                    "body": ["click here", "limited time", "act now", "your account has been", "verify your"]
                },
                "newsletter": {
                    "subject": ["newsletter", "weekly update", "digest", "monthly report"],
                    "body": ["unsubscribe", "subscription", "newsletter"]
                },
                "important": {
                    "subject": ["urgent", "important", "deadline", "meeting", "attention required"],
                    "from": ["boss@company.com", "hr@company.com", "ceo@"]
                },
                "personal": {
                    "from_domains": ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]
                },
                "low-priority": {
                    "subject": ["sale", "discount", "offer", "promotion"],
                    "from": ["marketing@", "noreply@", "donotreply@"]
                }
            },
            "confidence_thresholds": {
                "suspicious": 0.7,
                "newsletter": 0.8,
                "important": 0.75,
                "personal": 0.6,
                "low-priority": 0.65
            },
            "priority_order": [
                "suspicious",  # Highest priority rule
                "important",
                "personal",
                "newsletter",
                "low-priority"  # Lowest priority rule
            ]
        }

        try:
            if os.path.exists(rules_file):
                with open(rules_file, 'r') as f:
                    loaded_rules = json.load(f)
                    self.logger.info(f"Classification rules loaded from {rules_file}")
                    return loaded_rules
            else:
                self.logger.warning(f"Rules file not found: {rules_file}. Using default rules.")
                return default_rules
        except Exception as e:
            self.logger.error(f"Error loading rules file: {e}. Using default rules.")
            return default_rules

    def _preprocess_text(self, text):
        """
        Preprocess email text for classification

        :param text: Raw email text
        :return: Cleaned and processed text
        """
        if not text:
            return ""

        # Convert to lowercase
        text = text.lower()

        # Remove special characters and extra whitespace
        text = re.sub(r'[^a-z0-9\s]', '', text)
        text = re.sub(r'\s+', ' ', text).strip()

        # Truncate to first 1000 characters to avoid model input limitations
        return text[:1000]

    def classify(self, email):
        """
        Classify an individual email

        :param email: Email dictionary
        :return: Classification results
        """
        if not self.classifier:
            return {
                'category': 'unknown',
                'confidence': 0.0,
                'details': {}
            }

        try:
            # Combine relevant email fields for classification
            text_to_classify = f"{email.get('subject', '')} {email.get('body', '')}"

            # Preprocess text
            processed_text = self._preprocess_text(text_to_classify)

            # Perform zero-shot classification
            result = self.classifier(
                processed_text,
                self.categories,
                multi_label=False
            )

            # Get the top category and its confidence
            top_category = result['labels'][0]
            top_confidence = result['scores'][0]

            # Initial classification
            classification = {
                'category': top_category,
                'confidence': top_confidence,
                'details': {
                    'subject': email.get('subject', 'No Subject'),
                    'sender': email.get('from', 'Unknown Sender'),
                    'rule_matches': []
                }
            }

            # Apply advanced classification rules
            classification = self._apply_classification_rules(email, classification)

            return classification

        except Exception as e:
            self.logger.error(f"Classification error: {e}")
            return {
                'category': 'unknown',
                'confidence': 0.0,
                'details': {}
            }

    def _apply_classification_rules(self, email, classification):
        """
        Apply advanced classification rules based on email content

        :param email: Email dictionary
        :param classification: Initial classification result
        :return: Potentially modified classification
        """
        # Extract email components for rule matching
        subject = email.get('subject', '').lower()
        body = email.get('body', '').lower()
        sender = email.get('from', '').lower()

        # Track rule matches for each category
        rule_matches = defaultdict(list)
        match_strengths = defaultdict(float)

        # Process keyword rules
        keyword_rules = self.rules.get("keyword_rules", {})
        for category, category_rules in keyword_rules.items():
            # Check subject keywords
            if "subject" in category_rules:
                for keyword in category_rules["subject"]:
                    if keyword.lower() in subject:
                        rule_matches[category].append(f"Subject contains '{keyword}'")
                        match_strengths[category] += 0.2  # Subject matches have higher weight

            # Check body keywords
            if "body" in category_rules:
                for keyword in category_rules["body"]:
                    if keyword.lower() in body:
                        rule_matches[category].append(f"Body contains '{keyword}'")
                        match_strengths[category] += 0.1

            # Check sender keywords
            if "from" in category_rules:
                for keyword in category_rules["from"]:
                    if keyword.lower() in sender:
                        rule_matches[category].append(f"Sender contains '{keyword}'")
                        match_strengths[category] += 0.3  # Sender matches have highest weight

            # Check sender domains for personal emails
            if "from_domains" in category_rules:
                for domain in category_rules["from_domains"]:
                    if domain.lower() in sender:
                        rule_matches[category].append(f"Sender domain is '{domain}'")
                        match_strengths[category] += 0.3

        # If we have rule matches, determine the strongest match
        if rule_matches:
            # Get confidence thresholds from config
            confidence_thresholds = self.rules.get("confidence_thresholds", {})
            priority_order = self.rules.get("priority_order", self.categories)

            # First, find categories that matched rules
            matched_categories = [cat for cat in priority_order if cat in rule_matches]

            if matched_categories:
                # Select highest priority category from matched categories
                selected_category = matched_categories[0]

                # Only override if match strength or confidence threshold is high enough
                if (match_strengths[selected_category] > 0.3 or
                        classification['confidence'] < confidence_thresholds.get(selected_category, 0.7)):
                    classification['category'] = selected_category
                    classification['confidence'] = max(
                        classification['confidence'],
                        confidence_thresholds.get(selected_category, 0.7),
                        match_strengths[selected_category]
                    )
                    classification['details']['rule_matches'] = rule_matches[selected_category]
                    classification['details']['rule_based'] = True

        return classification