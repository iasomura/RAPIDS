#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Certificate Parser for RAPIDS Project

This module provides functionality for parsing and analyzing SSL certificate data.
Place this file at: RAPIDS/src/certificate_analysis/certificate_parser.py

Features:
- SSL certificate parsing and analysis
- Certificate feature extraction
- Common CA detection
- Certificate validity checks
- Security score calculation
"""

from pathlib import Path
import json
import logging
from datetime import datetime
from typing import Optional, Dict, List, Any, Union
import re
from dataclasses import dataclass
import pandas as pd
import numpy as np
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from base64 import b64decode

@dataclass
class CertificateFeatures:
    """Data class to store extracted certificate features."""
    domain: str
    issuer: str
    subject: str
    validity_days: int
    signature_algorithm: str
    key_size: int
    is_wildcard: bool
    san_count: int
    is_ev: bool
    is_free_ca: bool

class CertificateParser:
    """Handles SSL certificate parsing and analysis."""

    def __init__(self, config_path: Path):
        """
        Initialize CertificateParser.

        Args:
            config_path: Path to configuration file
        """
        self.config_path = config_path
        self.setup_paths()
        self.setup_logging()
        self.load_config()
        self.initialize_ca_lists()

    def setup_paths(self) -> None:
        """Set up necessary directory paths."""
        self.project_root = Path('/home/asomura/waseda/nextstep/RAPIDS')
        self.log_dir = self.project_root / 'data' / 'logs'
        self.output_dir = self.project_root / 'data' / 'processed' / 'certificates'

        # Create directories if they don't exist
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def setup_logging(self) -> None:
        """Configure logging settings."""
        log_file = self.log_dir / f'certificate_parser_{datetime.now():%Y%m%d}.log'
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def load_config(self) -> None:
        """Load configuration from JSON file."""
        try:
            with open(self.config_path) as f:
                self.config = json.load(f)
            self.logger.info("Configuration loaded successfully")
        except Exception as e:
            self.logger.error(f"Error loading config: {str(e)}")
            raise

    def initialize_ca_lists(self) -> None:
        """Initialize lists of known CAs and their characteristics."""
        self.free_cas = {
            "Let's Encrypt",
            "ZeroSSL",
            "Cloudflare Inc ECC CA",
            "Amazon",
            "Google Trust Services"
        }
        
        self.ev_cas = {
            "DigiCert EV",
            "Sectigo EV",
            "GlobalSign EV",
            "GeoTrust EV"
        }

    def parse_certificate_text(self, cert_text: Optional[str]) -> Dict[str, Any]:
        """
        Parse certificate text into structured data.

        Args:
            cert_text: Raw certificate text, can be None

        Returns:
            Dictionary containing parsed certificate data
        """
        if cert_text is None:
            return {}

        try:
            parsed_data = {}
            
            # Extract issuer
            issuer_match = re.search(r"Issuer:\s*(.*)", cert_text)
            if issuer_match:
                parsed_data['issuer'] = issuer_match.group(1)

            # Extract validity period
            validity_match = re.search(r"Not Before:\s*(.*)\s*Not After\s*:\s*(.*)", cert_text)
            if validity_match:
                parsed_data['not_before'] = validity_match.group(1)
                parsed_data['not_after'] = validity_match.group(2)

            # Extract subject
            subject_match = re.search(r"Subject:\s*(.*)", cert_text)
            if subject_match:
                parsed_data['subject'] = subject_match.group(1)

            # Extract signature algorithm
            sig_match = re.search(r"Signature Algorithm:\s*(.*)", cert_text)
            if sig_match:
                parsed_data['signature_algorithm'] = sig_match.group(1)

            # Extract public key info
            pubkey_match = re.search(r"Public Key Algorithm:\s*(.*)", cert_text)
            if pubkey_match:
                parsed_data['public_key_algorithm'] = pubkey_match.group(1)

            return parsed_data

        except Exception as e:
            self.logger.error(f"Error parsing certificate text: {str(e)}")
            return {}

    def extract_features(self, cert_data: Dict[str, Any]) -> Optional[CertificateFeatures]:
        """
        Extract relevant features from certificate data.

        Args:
            cert_data: Dictionary containing certificate data

        Returns:
            CertificateFeatures object containing extracted features, or None if data is invalid
        """
        if not cert_data:
            return None

        try:
            # Extract basic information
            domain = cert_data.get('domain', '')
            issuer = cert_data.get('https_certificate_issuer', '')
            subject = cert_data.get('subject', '')
            
            # Calculate validity period
            validity_days = 0  # Default value
            if 'not_before' in cert_data and 'not_after' in cert_data:
                try:
                    not_before = datetime.strptime(cert_data['not_before'], '%Y-%m-%d %H:%M:%S')
                    not_after = datetime.strptime(cert_data['not_after'], '%Y-%m-%d %H:%M:%S')
                    validity_days = (not_after - not_before).days
                except ValueError:
                    self.logger.warning(f"Could not parse dates for domain {domain}")

            # Get signature algorithm
            signature_algorithm = cert_data.get('https_certificate_signature_algorithm', '')

            # Determine key size (if available)
            key_size = 0
            if 'https_certificate_public_key' in cert_data:
                key_match = re.search(r'(\d+)\s*bit', cert_data['https_certificate_public_key'])
                if key_match:
                    key_size = int(key_match.group(1))

            # Check if wildcard certificate
            is_wildcard = '*.' in domain

            # Count Subject Alternative Names (if available)
            san_count = 0
            if 'https_certificate_extensions' in cert_data:
                sans = re.findall(r'DNS:', cert_data['https_certificate_extensions'])
                san_count = len(sans)

            # Check if EV certificate
            is_ev = any(ev_ca in issuer for ev_ca in self.ev_cas)

            # Check if free CA
            is_free_ca = any(free_ca in issuer for free_ca in self.free_cas)

            return CertificateFeatures(
                domain=domain,
                issuer=issuer,
                subject=subject,
                validity_days=validity_days,
                signature_algorithm=signature_algorithm,
                key_size=key_size,
                is_wildcard=is_wildcard,
                san_count=san_count,
                is_ev=is_ev,
                is_free_ca=is_free_ca
            )

        except Exception as e:
            self.logger.error(f"Error extracting features for {cert_data.get('domain', 'unknown')}: {str(e)}")
            return None

    def calculate_security_score(self, features: CertificateFeatures) -> float:
        """
        Calculate a security score based on certificate features.

        Args:
            features: CertificateFeatures object

        Returns:
            Security score between 0 and 1
        """
        score = 0.0
        max_score = 0.0

        # Key size scoring
        if features.key_size >= 4096:
            score += 1.0
        elif features.key_size >= 2048:
            score += 0.8
        max_score += 1.0

        # Validity period scoring (prefer shorter periods)
        if 0 < features.validity_days <= 90:
            score += 1.0
        elif features.validity_days <= 365:
            score += 0.8
        elif features.validity_days <= 730:
            score += 0.6
        max_score += 1.0

        # Signature algorithm scoring
        if 'sha256' in features.signature_algorithm.lower():
            score += 1.0
        elif 'sha1' in features.signature_algorithm.lower():
            score += 0.4
        max_score += 1.0

        # CA reputation scoring
        if features.is_ev:
            score += 1.0
        elif not features.is_free_ca:
            score += 0.8
        max_score += 1.0

        # Normalize score
        return score / max_score if max_score > 0 else 0.0

    def analyze_certificates(self, cert_df: pd.DataFrame) -> pd.DataFrame:
        """
        Analyze a batch of certificates and extract features.

        Args:
            cert_df: DataFrame containing certificate data

        Returns:
            DataFrame with extracted features and analysis results
        """
        try:
            results = []
            total_certs = len(cert_df)
            processed_certs = 0
            
            for _, row in cert_df.iterrows():
                try:
                    # Parse certificate data
                    cert_data = self.parse_certificate_text(row.get('https_certificate_body', ''))
                    cert_data.update({
                        'domain': row.get('domain'),
                        'https_certificate_issuer': row.get('https_certificate_issuer'),
                        'https_certificate_signature_algorithm': row.get('https_certificate_signature_algorithm'),
                        'https_certificate_public_key': row.get('https_certificate_public_key'),
                        'https_certificate_extensions': row.get('https_certificate_extensions')
                    })

                    # Extract features
                    features = self.extract_features(cert_data)
                    if features is None:
                        self.logger.warning(f"Could not extract features for domain {row.get('domain', 'unknown')}")
                        continue

                    # Calculate security score
                    security_score = self.calculate_security_score(features)

                    # Append results
                    results.append({
                        'id': row.get('id'),
                        'domain': features.domain,
                        'issuer': features.issuer,
                        'validity_days': features.validity_days,
                        'signature_algorithm': features.signature_algorithm,
                        'key_size': features.key_size,
                        'is_wildcard': features.is_wildcard,
                        'san_count': features.san_count,
                        'is_ev': features.is_ev,
                        'is_free_ca': features.is_free_ca,
                        'security_score': security_score
                    })

                    processed_certs += 1
                    if processed_certs % 100 == 0:
                        self.logger.info(f"Processed {processed_certs}/{total_certs} certificates")

                except Exception as e:
                    self.logger.error(f"Error processing certificate for {row.get('domain', 'unknown')}: {str(e)}")
                    continue

            # Create DataFrame from results
            results_df = pd.DataFrame(results)
            
            # Save results
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = self.output_dir / f'certificate_analysis_{timestamp}.csv'
            results_df.to_csv(output_file, index=False)
            self.logger.info(f"Analysis results saved to {output_file}")
            self.logger.info(f"Successfully processed {processed_certs} out of {total_certs} certificates")

            return results_df

        except Exception as e:
            self.logger.error(f"Error in certificate analysis: {str(e)}")
            raise

if __name__ == "__main__":
    try:
        from database_handler import DatabaseHandler
        
        config_path = Path('/home/asomura/waseda/nextstep/RAPIDS/config/database.json')
        
        # Initialize handlers
        db_handler = DatabaseHandler(config_path)
        cert_parser = CertificateParser(config_path)

        # Get certificate data
        cert_data = db_handler.get_certificate_data('website_data')
        
        # Analyze certificates
        if not cert_data.empty:
            results = cert_parser.analyze_certificates(cert_data)
            print(f"\nAnalyzed {len(results)} certificates")
            print("\nSample analysis results:")
            print(results.head())
            
            # Print summary statistics
            print("\nSummary Statistics:")
            print(f"Average security score: {results['security_score'].mean():.2f}")
            print(f"EV certificates: {results['is_ev'].sum()}")
            print(f"Free CA certificates: {results['is_free_ca'].sum()}")

        db_handler.close_connections()

    except Exception as e:
        logging.error(f"Error in main process: {str(e)}")
        raise
