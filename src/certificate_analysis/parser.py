#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Enhanced Certificate Parser Module
Handles the parsing of SSL certificate data for the RAPIDS project.

Author: RAPIDS Project Team
Date: 2024-12-14
"""

import re
from typing import Dict, Optional
from datetime import datetime

class CertificateParser:
    """Enhanced parser for SSL certificate data"""
    
    @staticmethod
    def parse_certificate_all(cert_text: str) -> Dict:
        """
        Parse https_certificate_all content with enhanced cleaning and feature extraction
        
        Args:
            cert_text: Raw certificate text from https_certificate_all
            
        Returns:
            Dictionary containing parsed certificate information
        """
        info = {
            'protocol_version': None,
            'cipher_suite': None,
            'subject': {},
            'issuer': {},
            'public_key_bits': None,
            'security_features': [],
            'validation_result': None,
            'cert_chain_length': 0,
            'cert_dates': {
                'not_before': None,
                'not_after': None
            },
            'key_algorithm': None,
            'signature_algorithm': None
        }
        
        if not cert_text or not isinstance(cert_text, str):
            return info

        # Clean the certificate text
        cert_text = re.sub(r'<[^>]+>', '', cert_text)
        lines = [line.strip() for line in cert_text.split('\n') if line.strip()]
        
        in_cert_chain = False
        in_server_cert = False
        current_section = None
        
        for line in lines:
            # Track sections
            if 'Certificate chain:' in line:
                in_cert_chain = True
                current_section = 'chain'
                continue
            elif 'Server certificate:' in line:
                in_server_cert = True
                in_cert_chain = False
                current_section = 'server_cert'
                continue
            elif not line:
                current_section = None
                continue
            
            # Parse certificate chain
            if in_cert_chain and line.startswith(('s:', 'i:')):
                info['cert_chain_length'] += 1
            
            # Parse protocol and cipher information
            if 'Protocol:' in line:
                info['protocol_version'] = line.split(':')[1].strip()
            elif 'Cipher:' in line:
                info['cipher_suite'] = line.split(':')[1].strip()
            
            # Parse subject and issuer information
            elif 'subject=' in line:
                info['subject'].update(CertificateParser._parse_name_field(line.split('subject=')[1]))
            elif 'issuer=' in line:
                info['issuer'].update(CertificateParser._parse_name_field(line.split('issuer=')[1]))
            
            # Parse key information
            elif 'Public Key Algorithm:' in line:
                info['key_algorithm'] = line.split(':')[1].strip()
            elif 'Server public key is' in line:
                try:
                    info['public_key_bits'] = int(re.findall(r'\d+', line)[0])
                except (IndexError, ValueError):
                    pass
            
            # Parse dates
            elif 'Not Before:' in line:
                info['cert_dates']['not_before'] = CertificateParser._parse_date(line.split(':', 1)[1])
            elif 'Not After:' in line:
                info['cert_dates']['not_after'] = CertificateParser._parse_date(line.split(':', 1)[1])
            
            # Parse signature algorithm
            elif 'Signature Algorithm:' in line:
                info['signature_algorithm'] = line.split(':')[1].strip()

        return info

    @staticmethod
    def _parse_name_field(name_str: str) -> Dict:
        """
        Parse certificate name fields (subject or issuer)
        
        Args:
            name_str: String containing name field information
            
        Returns:
            Dictionary of parsed name fields
        """
        result = {}
        parts = name_str.split(',')
        for part in parts:
            if '=' in part:
                key, value = part.strip().split('=', 1)
                result[key.strip()] = value.strip()
        return result

    @staticmethod
    def _parse_date(date_str: str) -> Optional[datetime]:
        """
        Parse certificate date strings
        
        Args:
            date_str: Date string from certificate
            
        Returns:
            Datetime object or None if parsing fails
        """
        try:
            return datetime.strptime(date_str.strip(), '%b %d %H:%M:%S %Y GMT')
        except ValueError:
            try:
                return datetime.strptime(date_str.strip(), '%Y%m%d%H%M%SZ')
            except ValueError:
                return None

    @staticmethod
    def extract_domain_features(domain: str) -> Dict:
        """
        Extract comprehensive features from domain name
        
        Args:
            domain: Domain name string
            
        Returns:
            Dictionary containing domain features
        """
        if not domain:
            return {
                'length': 0,
                'word_count': 0,
                'has_hyphen': False,
                'has_digits': False,
                'special_char_count': 0,
                'digit_count': 0,
                'subdomain_count': 0,
                'is_ip_address': False
            }
        
        features = {
            'length': len(domain),
            'word_count': domain.count('.') + 1,
            'has_hyphen': '-' in domain,
            'has_digits': bool(re.search(r'\d', domain)),
            'special_char_count': len(re.findall(r'[^a-zA-Z0-9.-]', domain)),
            'digit_count': sum(c.isdigit() for c in domain),
            'subdomain_count': domain.count('.'),
            'is_ip_address': bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain))
        }
        
        # Additional complexity metrics
        features['entropy'] = CertificateParser._calculate_entropy(domain)
        features['consonant_ratio'] = CertificateParser._calculate_consonant_ratio(domain)
        
        return features

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """
        Calculate Shannon entropy of text
        
        Args:
            text: Input text string
            
        Returns:
            Entropy value
        """
        from math import log2
        
        if not text:
            return 0.0
            
        # Calculate frequency of each character
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
            
        # Calculate entropy
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            probability = count / length
            entropy -= probability * log2(probability)
            
        return entropy

    @staticmethod
    def _calculate_consonant_ratio(text: str) -> float:
        """
        Calculate ratio of consonants in text
        
        Args:
            text: Input text string
            
        Returns:
            Consonant ratio
        """
        if not text:
            return 0.0
            
        consonants = set('bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ')
        text_length = len(text)
        consonant_count = sum(1 for c in text if c in consonants)
        
        return consonant_count / text_length if text_length > 0 else 0.0
