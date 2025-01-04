#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Cipher Analyzer Module
Handles cipher suite analysis for certificates.
"""

from typing import Dict
import pandas as pd

class CipherAnalyzer:
    """Handles cipher suite analysis"""
    
    def analyze_cipher_suites(self, df: pd.DataFrame) -> Dict:
        """
        Analyze cipher suite distributions and security patterns
        
        Args:
            df: DataFrame containing certificate data
            
        Returns:
            Dictionary containing comprehensive cipher suite analysis
        """
        # Basic distribution analysis
        cipher_distribution = df.groupby(['site_type', 'cipher_suite']).size()
        cipher_dist_dict = {f"{site_type}_{cipher}": count 
                          for (site_type, cipher), count in cipher_distribution.items()}

        # Enhanced cipher categorization
        df['cipher_category'] = df['cipher_suite'].apply(self._categorize_cipher)
        category_dist = df.groupby(['site_type', 'cipher_category']).size().to_dict()

        # Forward secrecy analysis
        has_pfs = df['cipher_suite'].apply(self._has_perfect_forward_secrecy)
        pfs_stats = {
            'total_with_pfs': int(has_pfs.sum()),
            'percentage_with_pfs': float(has_pfs.mean() * 100)
        }

        # Key exchange algorithm analysis
        key_exchange_types = df['cipher_suite'].apply(self._extract_key_exchange).value_counts().to_dict()

        # Prepare comprehensive analysis results
        return {
            'total_unique_ciphers': df['cipher_suite'].nunique(),
            'cipher_distribution': cipher_dist_dict,
            'category_distribution': category_dist,
            'forward_secrecy_stats': pfs_stats,
            'key_exchange_distribution': key_exchange_types,
            'security_stats': self._calculate_security_stats(df)
        }

    def _categorize_cipher(self, cipher: str) -> str:
        """
        Categorize cipher suite based on security level
        
        Args:
            cipher: Cipher suite string
            
        Returns:
            Category string ('excellent', 'strong', 'acceptable', 'legacy', or 'weak')
        """
        if not cipher:
            return 'unknown'
        cipher = str(cipher).upper()
        
        # Modern, highly secure configurations
        if 'CHACHA20' in cipher:
            return 'excellent'
        # Strong configurations
        elif 'GCM' in cipher and ('ECDHE' in cipher or 'DHE' in cipher):
            return 'strong'
        # Acceptable configurations
        elif 'CBC' in cipher and 'SHA256' in cipher:
            return 'acceptable'
        # Legacy configurations
        elif 'CBC' in cipher or 'SHA1' in cipher:
            return 'legacy'
        else:
            return 'weak'

    def _has_perfect_forward_secrecy(self, cipher: str) -> bool:
        """
        Check if cipher suite supports Perfect Forward Secrecy
        
        Args:
            cipher: Cipher suite string
            
        Returns:
            Boolean indicating PFS support
        """
        if not cipher:
            return False
        cipher = str(cipher).upper()
        return 'ECDHE' in cipher or 'DHE' in cipher

    def _extract_key_exchange(self, cipher: str) -> str:
        """
        Extract key exchange algorithm from cipher suite
        
        Args:
            cipher: Cipher suite string
            
        Returns:
            Key exchange algorithm name
        """
        if not cipher:
            return 'unknown'
        cipher = str(cipher).upper()
        
        if 'ECDHE' in cipher:
            return 'ECDHE'
        elif 'DHE' in cipher or 'EDH' in cipher:
            return 'DHE'
        elif 'ECDH' in cipher:
            return 'ECDH'
        elif 'DH' in cipher:
            return 'DH'
        elif 'RSA' in cipher:
            return 'RSA'
        else:
            return 'other'

    def _calculate_security_stats(self, df: pd.DataFrame) -> Dict:
        """
        Calculate security statistics for cipher suites
        
        Args:
            df: DataFrame with cipher categories
            
        Returns:
            Dictionary containing security statistics
        """
        return {
            'excellent_count': int(df[df['cipher_category'] == 'excellent'].shape[0]),
            'strong_count': int(df[df['cipher_category'] == 'strong'].shape[0]),
            'acceptable_count': int(df[df['cipher_category'] == 'acceptable'].shape[0]),
            'legacy_count': int(df[df['cipher_category'] == 'legacy'].shape[0]),
            'weak_count': int(df[df['cipher_category'] == 'weak'].shape[0]),
            'unknown_count': int(df[df['cipher_category'] == 'unknown'].shape[0])
        }
