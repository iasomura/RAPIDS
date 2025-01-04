#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Security Scorer Module
Handles security score calculations for certificates.
"""

import numpy as np
import pandas as pd
from typing import Dict

class SecurityScorer:
    """Handles security score calculations"""
    
    def __init__(self):
        """Initialize security scorer with configuration"""
        self.security_config = {
            'min_key_size': 2048,
            'preferred_protocols': ['TLSv1.3'],
            'acceptable_protocols': ['TLSv1.2'],
            'high_risk_issuers': ['R10', 'R11'],
            'suspicious_domain_length': 50
        }

    def calculate_security_score(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Calculate comprehensive security score based on multiple factors
        
        Args:
            df: DataFrame containing certificate data
            
        Returns:
            DataFrame with added security scores
        """
        # Component weights
        weights = {
            'tls_version': 0.25,
            'key_size': 0.25,
            'cert_issuer': 0.20,
            'domain_features': 0.15,
            'cipher_strength': 0.15
        }
        
        # TLS version score
        df['tls_score'] = df['protocol_version'].map({
            'TLSv1.3': 1.0,
            'TLSv1.2': 0.7,
            'TLSv1.1': 0.3,
            'TLSv1.0': 0.1,
            None: 0.0
        }).fillna(0.0)
        
        # Key size score
        df['key_score'] = df['public_key_bits'].apply(
            lambda x: min(1.0, (x or 0) / self.security_config['min_key_size'])
        )
        
        # Certificate issuer score with extended validation
        df['issuer_score'] = df.apply(self._calculate_issuer_score, axis=1)
        
        # Domain features score with enhanced analysis
        df['domain_score'] = df.apply(self._calculate_domain_score, axis=1)
        
        # Cipher strength score with detailed analysis
        df['cipher_score'] = df['cipher_suite'].apply(self._calculate_cipher_score)
        
        # Additional security features score
        df['additional_security_score'] = df.apply(self._calculate_additional_security_score, axis=1)
        
        # Calculate final security score with weighted components
        df['security_score'] = (
            weights['tls_version'] * df['tls_score'] +
            weights['key_size'] * df['key_score'] +
            weights['cert_issuer'] * df['issuer_score'] +
            weights['domain_features'] * df['domain_score'] +
            weights['cipher_strength'] * df['cipher_score']
        ) * df['additional_security_score']  # Apply additional security modifier
        
        return df

    def _calculate_issuer_score(self, row: pd.Series) -> float:
        """Calculate detailed certificate issuer security score"""
        issuer = row['https_certificate_issuer']
        if issuer in self.security_config['high_risk_issuers']:
            return 0.2
            
        score = 1.0
        
        # Check for well-known trusted CAs
        trusted_cas = ['DigiCert', 'Let\'s Encrypt', 'Sectigo', 'GlobalSign']
        if any(ca in str(issuer) for ca in trusted_cas):
            score *= 1.2
        
        # Check for EV certificate indicators
        if 'Extended Validation' in str(row.get('cert_details', {})):
            score *= 1.3
            
        return min(1.0, score)  # Cap at 1.0

    def _calculate_domain_score(self, row: pd.Series) -> float:
        """Calculate comprehensive domain security score"""
        domain_features = row.get('domain_features', {})
        if not domain_features:
            return 0.0
            
        scores = []
        
        # Length score with nuanced evaluation
        length = domain_features.get('length', 0)
        length_score = 1.0 if length < 30 else (0.7 if length < 40 else (0.4 if length < 50 else 0.0))
        scores.append(length_score)
        
        # Entropy score with refined thresholds
        entropy = domain_features.get('entropy', 0)
        entropy_score = 1.0 if entropy < 3.5 else (0.7 if entropy < 4.0 else (0.4 if entropy < 4.5 else 0.0))
        scores.append(entropy_score)
        
        # Special character analysis
        special_chars = domain_features.get('special_char_count', 0)
        special_score = 1.0 if special_chars == 0 else (0.7 if special_chars < 2 else (0.3 if special_chars < 4 else 0.0))
        scores.append(special_score)
        
        # Subdomain depth analysis
        subdomain_count = domain_features.get('subdomain_count', 0)
        subdomain_score = 1.0 if subdomain_count < 2 else (0.7 if subdomain_count < 3 else 0.3)
        scores.append(subdomain_score)
        
        # IP address presence check
        if domain_features.get('is_ip_address', False):
            scores.append(0.3)
            
        return np.mean(scores)

    def _calculate_cipher_score(self, cipher: str) -> float:
        """Calculate detailed cipher strength score"""
        if not cipher:
            return 0.0
            
        score = 0.0
        cipher = str(cipher).upper()
        
        # Evaluate encryption algorithm
        if 'CHACHA20' in cipher:
            score += 0.4  # Modern, highly secure
        elif 'GCM' in cipher:
            score += 0.35  # Very good
        elif 'CBC' in cipher:
            score += 0.25  # Acceptable
            
        # Evaluate hash function
        if 'SHA384' in cipher:
            score += 0.3
        elif 'SHA256' in cipher:
            score += 0.25
        elif 'SHA1' in cipher:
            score += 0.1
            
        # Evaluate key exchange
        if 'ECDHE' in cipher:
            score += 0.3  # Perfect forward secrecy with elliptic curves
        elif 'DHE' in cipher:
            score += 0.25  # Perfect forward secrecy
            
        return min(1.0, score)  # Cap at 1.0

    def _calculate_additional_security_score(self, row: pd.Series) -> float:
        """Calculate score for additional security features"""
        score = 1.0
        cert_details = row.get('cert_details', {})
        
        # Check for HSTS
        if 'hsts' in str(cert_details.get('security_headers', '')).lower():
            score *= 1.1
            
        # Check for CAA records
        if cert_details.get('has_caa_records', False):
            score *= 1.1
            
        # Check certificate transparency
        if cert_details.get('certificate_transparency', False):
            score *= 1.1
            
        return min(1.2, score)  # Cap bonus at 20%