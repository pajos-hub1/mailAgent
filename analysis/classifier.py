import logging
import re
import json
import os
import requests
import time
import socket
import ipaddress
from collections import defaultdict
from transformers import pipeline
from urllib.parse import urlparse
from email.utils import parseaddr
import dns.resolver
import dns.exception


class EmailClassifier:
    def __init__(self, rules_file="classification_rules.json", api_key=None):
        """
        Initialize Email Classifier with pre-trained model, custom rules, and threat intelligence

        :param rules_file: Path to JSON file containing classification rules
        :param api_key: EmailRep.io API key (optional, but recommended for higher rate limits)
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

        # EmailRep.io configuration
        self.emailrep_api_key = api_key
        self.emailrep_base_url = "https://emailrep.io"
        self.emailrep_cache = {}  # Simple cache to avoid duplicate API calls
        self.emailrep_rate_limit = 1.0  # Seconds between API calls for free tier
        self.last_api_call = 0

        # DNSBL configuration
        self.dnsbl_cache = {}  # Cache for DNSBL lookups
        self.dnsbl_timeout = 5  # Timeout for DNS queries in seconds

        # Initialize DNS resolver with custom settings
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = self.dnsbl_timeout
        self.dns_resolver.lifetime = self.dnsbl_timeout

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
            ],
            "threat_intelligence": {
                "enabled": True,
                "suspicious_reputation_threshold": 0.7,  # EmailRep reputation threshold
                "malicious_reputation_threshold": 0.5,  # Lower threshold for definitely malicious
                "check_domains": True,
                "check_ips": True,  # Enable IP checking
                "override_confidence": 0.9,  # High confidence when threat intel confirms suspicion
                "dnsbl": {
                    "enabled": True,
                    "providers": [
                        "zen.spamhaus.org",
                        "bl.spamcop.net",
                        "blacklist.woody.ch",
                        "combined.abuse.ch",
                        "cbl.abuseat.org",
                        "psbl.surriel.com",
                        "dnsbl.sorbs.net",
                        "ubl.unsubscore.com",
                        "dnsbl-1.uceprotect.net",
                        "dnsbl-2.uceprotect.net",
                        "truncate.gbudb.net",
                        "query.senderbase.org",
                        "opm.tornevall.org",
                        "netblock.pedantic.org",
                        "access.redhawk.org",
                        "cdl.anti-spam.org.cn",
                        "multi.surbl.org",
                        "dsn.rfc-ignorant.org",
                        "spam.abuse.ch",
                        "multi.uribl.com"
                    ],
                    "timeout": 5,  # DNS query timeout
                    "max_concurrent": 5,  # Maximum concurrent DNSBL checks
                    "cache_ttl": 3600,  # Cache results for 1 hour
                    "suspicious_threshold": 2,  # Number of blacklists to consider suspicious
                    "malicious_threshold": 4  # Number of blacklists to consider malicious
                }
            }
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

    def _extract_email_address(self, email_string):
        """
        Extract clean email address from email string (handles display names)

        :param email_string: Raw email string (e.g., "John Doe <john@example.com>")
        :return: Clean email address
        """
        if not email_string:
            return None

        # Use email.utils.parseaddr to handle display names
        name, email = parseaddr(email_string)
        return email.lower().strip() if email else None

    def _extract_domain_from_email(self, email):
        """
        Extract domain from email address

        :param email: Email address
        :return: Domain name
        """
        if not email or '@' not in email:
            return None
        return email.split('@')[1].lower()

    def _extract_ip_from_headers(self, email):
        """
        Extract IP addresses from email headers (Received headers)

        :param email: Email dictionary
        :return: List of IP addresses found in headers
        """
        ips = []
        headers = email.get('headers', {})

        # Check common header fields that might contain IP addresses
        received_headers = []
        if isinstance(headers, dict):
            # Handle single Received header or list of Received headers
            received = headers.get('Received', [])
            if isinstance(received, str):
                received_headers = [received]
            elif isinstance(received, list):
                received_headers = received
        elif isinstance(headers, str):
            # Parse headers string if needed
            for line in headers.split('\n'):
                if line.lower().startswith('received:'):
                    received_headers.append(line)

        # Extract IPs from Received headers using regex
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        for header in received_headers:
            found_ips = re.findall(ip_pattern, header)
            for ip in found_ips:
                try:
                    # Validate IP address
                    ipaddress.ip_address(ip)
                    # Skip private IP ranges
                    if not ipaddress.ip_address(ip).is_private:
                        ips.append(ip)
                except ValueError:
                    continue

        return list(set(ips))  # Remove duplicates

    def _reverse_ip_for_dnsbl(self, ip):
        """
        Reverse IP address for DNSBL lookup (e.g., 1.2.3.4 -> 4.3.2.1)

        :param ip: IP address string
        :return: Reversed IP string
        """
        try:
            parts = ip.split('.')
            return '.'.join(reversed(parts))
        except Exception:
            return None

    def _check_single_dnsbl(self, ip, dnsbl_provider):
        """
        Check a single IP against a single DNSBL provider

        :param ip: IP address to check
        :param dnsbl_provider: DNSBL provider hostname
        :return: Dictionary with check results
        """
        reversed_ip = self._reverse_ip_for_dnsbl(ip)
        if not reversed_ip:
            return None

        query_host = f"{reversed_ip}.{dnsbl_provider}"
        cache_key = f"{ip}:{dnsbl_provider}"

        # Check cache first
        if cache_key in self.dnsbl_cache:
            cache_time, result = self.dnsbl_cache[cache_key]
            cache_ttl = self.rules.get("threat_intelligence", {}).get("dnsbl", {}).get("cache_ttl", 3600)
            if time.time() - cache_time < cache_ttl:
                return result

        try:
            # Perform DNS A record lookup
            answers = self.dns_resolver.resolve(query_host, 'A', raise_on_no_answer=False)

            result = {
                'provider': dnsbl_provider,
                'listed': True,
                'response_codes': [str(answer) for answer in answers],
                'query_host': query_host
            }

            # Try to get TXT record for additional information
            try:
                txt_answers = self.dns_resolver.resolve(query_host, 'TXT', raise_on_no_answer=False)
                result['txt_info'] = [str(txt) for txt in txt_answers]
            except:
                result['txt_info'] = []

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            # IP not listed in this DNSBL
            result = {
                'provider': dnsbl_provider,
                'listed': False,
                'response_codes': [],
                'query_host': query_host
            }
        except Exception as e:
            self.logger.debug(f"DNSBL query failed for {query_host}: {e}")
            result = {
                'provider': dnsbl_provider,
                'listed': None,  # Unknown due to error
                'error': str(e),
                'query_host': query_host
            }

        # Cache the result
        self.dnsbl_cache[cache_key] = (time.time(), result)
        return result

    def _check_ip_dnsbl(self, ip):
        """
        Check IP against multiple DNSBL providers

        :param ip: IP address to check
        :return: Dictionary with comprehensive DNSBL results
        """
        dnsbl_config = self.rules.get("threat_intelligence", {}).get("dnsbl", {})
        if not dnsbl_config.get("enabled", True):
            return None

        providers = dnsbl_config.get("providers", [])
        if not providers:
            return None

        results = {
            'ip': ip,
            'total_providers': len(providers),
            'providers_checked': 0,
            'listed_count': 0,
            'error_count': 0,
            'provider_results': [],
            'is_suspicious': False,
            'is_malicious': False,
            'threat_indicators': []
        }

        self.logger.debug(f"Checking IP {ip} against {len(providers)} DNSBL providers")

        for provider in providers:
            try:
                provider_result = self._check_single_dnsbl(ip, provider)
                if provider_result:
                    results['provider_results'].append(provider_result)
                    results['providers_checked'] += 1

                    if provider_result['listed'] is True:
                        results['listed_count'] += 1
                        results['threat_indicators'].append(f"Listed in {provider}")
                    elif provider_result['listed'] is None:
                        results['error_count'] += 1

            except Exception as e:
                self.logger.debug(f"Error checking {provider} for IP {ip}: {e}")
                results['error_count'] += 1

        # Determine threat level based on number of listings
        suspicious_threshold = dnsbl_config.get("suspicious_threshold", 2)
        malicious_threshold = dnsbl_config.get("malicious_threshold", 4)

        if results['listed_count'] >= malicious_threshold:
            results['is_malicious'] = True
            results['is_suspicious'] = True
        elif results['listed_count'] >= suspicious_threshold:
            results['is_suspicious'] = True

        self.logger.debug(f"DNSBL check for {ip}: {results['listed_count']}/{results['providers_checked']} listings")

        return results

    def _check_emailrep_reputation(self, email):
        """
        Check email reputation using EmailRep.io API

        :param email: Email address to check
        :return: Dictionary with reputation data or None if error
        """
        if not email or not self.rules.get("threat_intelligence", {}).get("enabled", True):
            return None

        # Check cache first
        if email in self.emailrep_cache:
            self.logger.debug(f"Using cached reputation data for {email}")
            return self.emailrep_cache[email]

        # Rate limiting for free tier
        current_time = time.time()
        if current_time - self.last_api_call < self.emailrep_rate_limit:
            time.sleep(self.emailrep_rate_limit - (current_time - self.last_api_call))

        try:
            # Prepare headers
            headers = {
                'User-Agent': 'EmailClassifier/1.0'
            }
            if self.emailrep_api_key:
                headers['Authorization'] = f'Bearer {self.emailrep_api_key}'

            # Make API request
            url = f"{self.emailrep_base_url}/{email}"
            response = requests.get(url, headers=headers, timeout=10)
            self.last_api_call = time.time()

            if response.status_code == 200:
                reputation_data = response.json()

                # Cache the result
                self.emailrep_cache[email] = reputation_data

                self.logger.debug(f"EmailRep data for {email}: {reputation_data}")
                return reputation_data

            elif response.status_code == 429:
                self.logger.warning("EmailRep.io rate limit exceeded")
                return None

            elif response.status_code == 404:
                # Email not found in database - not necessarily bad
                self.logger.debug(f"Email {email} not found in EmailRep database")
                return {"email": email, "reputation": "unknown", "suspicious": False}

            else:
                self.logger.error(f"EmailRep API error: {response.status_code}")
                return None

        except requests.exceptions.RequestException as e:
            self.logger.error(f"EmailRep API request failed: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error checking EmailRep: {e}")
            return None

    def _analyze_threat_intelligence(self, email):
        """
        Analyze threat intelligence data for email including DNSBL checks

        :param email: Email dictionary
        :return: Threat intelligence analysis results
        """
        threat_config = self.rules.get("threat_intelligence", {})
        if not threat_config.get("enabled", True):
            return None

        sender_email = self._extract_email_address(email.get('from', ''))
        if not sender_email:
            return None

        analysis = {
            'sender_email': sender_email,
            'reputation_data': None,
            'dnsbl_results': [],
            'threat_indicators': [],
            'risk_score': 0.0,
            'is_suspicious': False,
            'is_malicious': False
        }

        # Check sender email reputation
        reputation_data = self._check_emailrep_reputation(sender_email)
        if reputation_data:
            analysis['reputation_data'] = reputation_data

            # Analyze reputation data
            if reputation_data.get('suspicious', False):
                analysis['threat_indicators'].append("Email marked as suspicious in EmailRep database")
                analysis['risk_score'] += 0.4

            if reputation_data.get('malicious', False):
                analysis['threat_indicators'].append("Email marked as malicious in EmailRep database")
                analysis['risk_score'] += 0.6
                analysis['is_malicious'] = True

            # Check reputation score (if available)
            reputation_score = reputation_data.get('reputation', None)
            if reputation_score is not None:
                try:
                    rep_score = float(reputation_score)
                    if rep_score <= threat_config.get("malicious_reputation_threshold", 0.5):
                        analysis['threat_indicators'].append(f"Low reputation score: {rep_score}")
                        analysis['risk_score'] += 0.5
                        analysis['is_malicious'] = True
                    elif rep_score <= threat_config.get("suspicious_reputation_threshold", 0.7):
                        analysis['threat_indicators'].append(f"Suspicious reputation score: {rep_score}")
                        analysis['risk_score'] += 0.3
                        analysis['is_suspicious'] = True
                except (ValueError, TypeError):
                    pass

            # Check for known bad indicators
            details = reputation_data.get('details', {})
            if details:
                if details.get('blacklisted', False):
                    analysis['threat_indicators'].append("Sender is blacklisted")
                    analysis['risk_score'] += 0.7
                    analysis['is_malicious'] = True

                if details.get('spam', False):
                    analysis['threat_indicators'].append("Sender associated with spam")
                    analysis['risk_score'] += 0.4
                    analysis['is_suspicious'] = True

                if details.get('free_provider', False) and details.get('disposable', False):
                    analysis['threat_indicators'].append("Disposable email address")
                    analysis['risk_score'] += 0.3
                    analysis['is_suspicious'] = True

        # DNSBL checks for IP addresses
        if threat_config.get("check_ips", True):
            ip_addresses = self._extract_ip_from_headers(email)
            for ip in ip_addresses:
                dnsbl_result = self._check_ip_dnsbl(ip)
                if dnsbl_result:
                    analysis['dnsbl_results'].append(dnsbl_result)

                    if dnsbl_result['is_malicious']:
                        analysis['threat_indicators'].extend([
                            f"IP {ip}: {indicator}" for indicator in dnsbl_result['threat_indicators']
                        ])
                        analysis['risk_score'] += 0.8
                        analysis['is_malicious'] = True
                    elif dnsbl_result['is_suspicious']:
                        analysis['threat_indicators'].extend([
                            f"IP {ip}: {indicator}" for indicator in dnsbl_result['threat_indicators']
                        ])
                        analysis['risk_score'] += 0.5
                        analysis['is_suspicious'] = True

        # Set overall suspicion flags
        if analysis['risk_score'] >= 0.5:
            analysis['is_suspicious'] = True
        if analysis['risk_score'] >= 0.7:
            analysis['is_malicious'] = True

        return analysis

    def classify(self, email):
        """
        Classify an individual email with threat intelligence integration

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
                    'rule_matches': [],
                    'threat_intelligence': None
                }
            }

            # Apply threat intelligence analysis
            threat_analysis = self._analyze_threat_intelligence(email)
            if threat_analysis:
                classification['details']['threat_intelligence'] = threat_analysis

                # Override classification if threat intelligence indicates high risk
                threat_config = self.rules.get("threat_intelligence", {})
                if threat_analysis['is_malicious'] or threat_analysis['is_suspicious']:
                    classification['category'] = 'suspicious'
                    classification['confidence'] = threat_config.get("override_confidence", 0.9)
                    classification['details']['threat_override'] = True

                    # Add threat indicators to rule matches
                    classification['details']['rule_matches'].extend([
                        f"THREAT INTEL: {indicator}" for indicator in threat_analysis['threat_indicators']
                    ])

            # Apply other classification rules
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
                # But don't override if threat intelligence already set it to suspicious with high confidence
                if (not classification['details'].get('threat_override', False) and
                        (match_strengths[selected_category] > 0.3 or
                         classification['confidence'] < confidence_thresholds.get(selected_category, 0.7))):
                    classification['category'] = selected_category
                    classification['confidence'] = max(
                        classification['confidence'],
                        confidence_thresholds.get(selected_category, 0.7),
                        match_strengths[selected_category]
                    )
                    classification['details']['rule_matches'].extend(rule_matches[selected_category])
                    classification['details']['rule_based'] = True

        return classification

    def get_threat_intelligence_summary(self, emails):
        """
        Get a summary of threat intelligence findings across multiple emails

        :param emails: List of email dictionaries
        :return: Summary of threat intelligence findings
        """
        summary = {
            'total_emails': len(emails),
            'suspicious_emails': 0,
            'malicious_emails': 0,
            'threat_indicators': defaultdict(int),
            'suspicious_senders': set(),
            'malicious_senders': set(),
            'dnsbl_stats': {
                'total_ips_checked': 0,
                'ips_listed': 0,
                'provider_stats': defaultdict(int)
            }
        }

        for email in emails:
            classification = self.classify(email)
            threat_intel = classification.get('details', {}).get('threat_intelligence')

            if threat_intel:
                if threat_intel['is_suspicious']:
                    summary['suspicious_emails'] += 1
                    summary['suspicious_senders'].add(threat_intel['sender_email'])

                if threat_intel['is_malicious']:
                    summary['malicious_emails'] += 1
                    summary['malicious_senders'].add(threat_intel['sender_email'])

                for indicator in threat_intel['threat_indicators']:
                    summary['threat_indicators'][indicator] += 1

                # Process DNSBL statistics
                for dnsbl_result in threat_intel.get('dnsbl_results', []):
                    summary['dnsbl_stats']['total_ips_checked'] += 1
                    if dnsbl_result['listed_count'] > 0:
                        summary['dnsbl_stats']['ips_listed'] += 1

                    for provider_result in dnsbl_result['provider_results']:
                        if provider_result['listed']:
                            summary['dnsbl_stats']['provider_stats'][provider_result['provider']] += 1

        # Convert sets to lists for JSON serialization
        summary['suspicious_senders'] = list(summary['suspicious_senders'])
        summary['malicious_senders'] = list(summary['malicious_senders'])
        summary['threat_indicators'] = dict(summary['threat_indicators'])
        summary['dnsbl_stats']['provider_stats'] = dict(summary['dnsbl_stats']['provider_stats'])

        return summary

    def get_dnsbl_provider_status(self):
        """
        Check the status of configured DNSBL providers

        :return: Dictionary with provider status information
        """
        dnsbl_config = self.rules.get("threat_intelligence", {}).get("dnsbl", {})
        providers = dnsbl_config.get("providers", [])

        status = {
            'total_providers': len(providers),
            'providers': []
        }

        # Test each provider with a known test IP (127.0.0.2 is commonly used for testing)
        test_ip = "127.0.0.2"

        for provider in providers:
            provider_status = {
                'name': provider,
                'status': 'unknown',
                'response_time': None,
                'error': None
            }

            try:
                start_time = time.time()
                result = self._check_single_dnsbl(test_ip, provider)
                end_time = time.time()

                provider_status['response_time'] = round((end_time - start_time) * 1000, 2)  # ms

                if result and result.get('listed') is not None:
                    provider_status['status'] = 'active'
                else:
                    provider_status['status'] = 'inactive'

            except Exception as e:
                provider_status['status'] = 'error'
                provider_status['error'] = str(e)

            status['providers'].append(provider_status)

        return status