import torch
import torch.nn as nn
from transformers import AutoTokenizer, AutoModel
import numpy as np
import hashlib
import re
import ssl
import socket
import whois
from datetime import datetime
import requests
from typing import Dict, List, Tuple
import asyncio
import aiohttp

class BankingPhishingDetector:
    """
    Specialized phishing detection for banking systems
    Key Requirements: <0.1% false positive rate, 99.9% accuracy
    """
    
    def __init__(self, bank_name: str, strict_mode: bool = True):
        self.bank_name = bank_name
        self.strict_mode = strict_mode
        self.banking_keywords = self._load_banking_keywords()
        
        # Multi-model ensemble
        self.models = self._initialize_models()
        
        # Threat intelligence for financial sector
        self.threat_intel = FinancialThreatIntelligence()
        
        # Real-time blacklists
        self.blacklist_cache = {}
        self.whitelist_cache = set()
        
        # SSL/TLS certificate validation
        self.cert_validator = SSLCertificateValidator()
        
    def _initialize_models(self):
        """Initialize specialized banking models"""
        return {
            'bert_financial': self._load_bert_financial_model(),
            'cnn_url': self._load_cnn_url_model(),
            'xgboost_ensemble': self._load_xgboost_model(),
            'anomaly_detector': self._load_anomaly_model(),
            'brand_protection': BrandProtectionModel(self.bank_name)
        }
    
    def detect_banking_phishing(self, url: str, email_content: str = None, 
                               sms_content: str = None, metadata: Dict = None) -> Dict:
        """
        Comprehensive phishing detection for banking context
        """
        results = {
            'url': url,
            'bank': self.bank_name,
            'timestamp': datetime.utcnow().isoformat(),
            'risk_level': 'UNKNOWN',
            'confidence': 0.0,
            'reasons': [],
            'recommended_action': 'ALLOW',
            'audit_trail': []
        }
        
        # Stage 1: Ultra-fast whitelist/blacklist check (1ms)
        if self._check_whitelist(url):
            results.update({
                'risk_level': 'SAFE',
                'confidence': 1.0,
                'reasons': ['URL in bank whitelist'],
                'recommended_action': 'ALLOW'
            })
            return results
        
        if self._check_blacklist(url):
            results.update({
                'risk_level': 'CRITICAL',
                'confidence': 1.0,
                'reasons': ['URL in financial blacklist'],
                'recommended_action': 'BLOCK_IMMEDIATELY'
            })
            return results
        
        # Stage 2: Banking-specific heuristics (5ms)
        banking_heuristics = self._analyze_banking_heuristics(url, email_content, sms_content)
        results['heuristics'] = banking_heuristics
        
        if banking_heuristics['suspicion_score'] > 0.9:
            results.update({
                'risk_level': 'HIGH',
                'confidence': banking_heuristics['suspicion_score'],
                'reasons': banking_heuristics['red_flags'],
                'recommended_action': 'BLOCK'
            })
            return results
        
        # Stage 3: SSL/TLS certificate validation (10-50ms)
        cert_analysis = self.cert_validator.analyze_certificate(url)
        results['certificate_analysis'] = cert_analysis
        
        if not cert_analysis['is_valid']:
            results.update({
                'risk_level': 'HIGH',
                'confidence': 0.95,
                'reasons': ['Invalid or suspicious SSL certificate'],
                'recommended_action': 'BLOCK'
            })
            return results
        
        # Stage 4: Brand impersonation detection (10ms)
        brand_check = self.models['brand_protection'].check_impersonation(
            url, email_content, sms_content
        )
        results['brand_protection'] = brand_check
        
        if brand_check['is_impersonation']:
            results.update({
                'risk_level': 'CRITICAL',
                'confidence': brand_check['confidence'],
                'reasons': [f'Brand impersonation detected: {brand_check["matched_patterns"]}'],
                'recommended_action': 'BLOCK_AND_ALERT'
            })
            return results
        
        # Stage 5: ML ensemble prediction (20-100ms)
        ml_features = self._extract_banking_features(url, email_content, sms_content, metadata)
        ml_results = self._run_ml_ensemble(ml_features)
        results['ml_predictions'] = ml_results
        
        # Stage 6: Real-time threat intelligence (50-200ms)
        threat_data = asyncio.run(self._check_threat_intelligence(url))
        results['threat_intelligence'] = threat_data
        
        # Stage 7: Calculate final risk score
        final_risk = self._calculate_final_risk(
            banking_heuristics,
            cert_analysis,
            brand_check,
            ml_results,
            threat_data
        )
        
        # Update results with final decision
        results.update(final_risk)
        
        # Stage 8: If suspicious but not definite, trigger 2FA or warning
        if final_risk['risk_level'] == 'MEDIUM':
            results['recommended_action'] = 'WARN_WITH_2FA'
        
        # Audit logging
        self._log_detection_audit(results)
        
        return results
    
    def _analyze_banking_heuristics(self, url: str, email_content: str = None, 
                                   sms_content: str = None) -> Dict:
        """
        Banking-specific heuristic analysis
        """
        heuristics = {
            'suspicion_score': 0.0,
            'red_flags': [],
            'banking_indicators': [],
            'urgency_indicators': 0
        }
        
        # Check for banking-related keywords in URL
        url_lower = url.lower()
        banking_terms = ['bank', 'login', 'secure', 'account', 'verify', 
                        'update', 'authorize', 'signin', 'onlinebanking']
        
        matched_terms = [term for term in banking_terms if term in url_lower]
        if matched_terms:
            heuristics['banking_indicators'] = matched_terms
            heuristics['suspicion_score'] += 0.1 * len(matched_terms)
        
        # Check for urgency indicators
        urgency_patterns = [
            r'urgent', r'immediate', r'action required', r'suspended',
            r'locked', r'verify now', r'within 24 hours'
        ]
        
        content = (email_content or '') + ' ' + (sms_content or '')
        content_lower = content.lower()
        
        for pattern in urgency_patterns:
            if re.search(pattern, content_lower):
                heuristics['urgency_indicators'] += 1
                heuristics['red_flags'].append(f'Urgency indicator: {pattern}')
        
        # Check for fake login forms
        if re.search(r'login|signin|authenticate', url_lower) and \
           not re.search(r'secure\.|https://.*bank\.', url_lower):
            heuristics['red_flags'].append('Login form on non-secure banking domain')
            heuristics['suspicion_score'] += 0.3
        
        # Check for IP addresses in URL (common in phishing)
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            heuristics['red_flags'].append('IP address in URL')
            heuristics['suspicion_score'] += 0.4
        
        # Check URL length and complexity
        if len(url) > 100:
            heuristics['red_flags'].append('Unusually long URL')
            heuristics['suspicion_score'] += 0.2
        
        # Check for @ symbol in URL (credentials in URL)
        if '@' in url:
            heuristics['red_flags'].append('Credentials in URL (@ symbol)')
            heuristics['suspicion_score'] += 0.5
        
        # Check for hex encoding
        if re.search(r'%[0-9a-fA-F]{2}', url):
            heuristics['red_flags'].append('Hex encoding in URL')
            heuristics['suspicion_score'] += 0.3
        
        # Ensure suspicion score is between 0 and 1
        heuristics['suspicion_score'] = min(heuristics['suspicion_score'], 1.0)
        
        return heuristics
    
    def _extract_banking_features(self, url: str, email_content: str = None,
                                 sms_content: str = None, metadata: Dict = None) -> Dict:
        """
        Extract comprehensive features for banking context
        """
        features = {}
        
        # URL-based features
        features.update(self._extract_url_features(url))
        
        # Content-based features
        if email_content:
            features.update(self._extract_email_features(email_content))
        
        if sms_content:
            features.update(self._extract_sms_features(sms_content))
        
        # Metadata features
        if metadata:
            features.update(self._extract_metadata_features(metadata))
        
        # Banking-specific features
        features.update(self._extract_banking_context_features(url, email_content))
        
        return features
    
    def _extract_url_features(self, url: str) -> Dict:
        """Extract URL features with banking context"""
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        
        features = {
            'url_length': len(url),
            'domain_length': len(domain),
            'num_subdomains': domain.count('.') - 1,
            'has_https': 1 if parsed_url.scheme == 'https' else 0,
            'has_port': 1 if ':' in domain else 0,
            'num_digits': sum(c.isdigit() for c in url),
            'num_special_chars': sum(not c.isalnum() for c in url),
            'entropy': self._calculate_entropy(url),
            'is_ip_address': 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain) else 0,
            'suspicious_tld': 1 if domain.split('.')[-1] in ['xyz', 'top', 'club', 'online'] else 0,
            'contains_bank_keywords': 1 if any(kw in url.lower() for kw in self.banking_keywords) else 0,
            'similarity_to_legitimate': self._calculate_domain_similarity(domain, self.bank_name)
        }
        
        # WHOIS features
        try:
            whois_info = whois.whois(domain)
            features.update({
                'domain_age_days': self._calculate_domain_age(whois_info),
                'registrar_reputation': self._check_registrar_reputation(whois_info.registrar),
                'has_privacy_protection': 1 if 'redacted' in str(whois_info).lower() else 0
            })
        except:
            features.update({
                'domain_age_days': -1,
                'registrar_reputation': 0,
                'has_privacy_protection': 0
            })
        
        return features
    
    def _extract_banking_context_features(self, url: str, email_content: str = None) -> Dict:
        """Extract features specific to banking context"""
        features = {}
        
        # Check for typical banking phrases
        banking_phrases = [
            'your account has been', 'suspicious activity', 'verify your identity',
            'update your information', 'password reset', 'security alert',
            'unusual login attempt', 'confirm your details'
        ]
        
        content = (email_content or '').lower()
        matched_phrases = sum(1 for phrase in banking_phrases if phrase in content)
        features['banking_phrases_count'] = matched_phrases
        
        # Check for fake bank names
        fake_bank_patterns = [
            rf'{self.bank_name.lower()}[^\w]secure',
            rf'secure[^\w]{self.bank_name.lower()}',
            rf'{self.bank_name.lower()}[^\w]online',
            rf'online[^\w]{self.bank_name.lower()}'
        ]
        
        fake_bank_matches = sum(1 for pattern in fake_bank_patterns 
                               if re.search(pattern, url.lower()))
        features['fake_bank_patterns'] = fake_bank_matches
        
        # Check for login form indicators
        form_keywords = ['login', 'username', 'password', 'pin', 'security code']
        features['login_form_indicators'] = sum(1 for kw in form_keywords 
                                               if kw in content)
        
        return features