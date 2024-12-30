#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Enhanced Certificate Analyzer Module
Handles the main analysis of SSL certificates for the RAPIDS project.

Author: RAPIDS Project Team
Date: 2024-12-14
"""

import os
import pandas as pd
import numpy as np
import json
import logging
from datetime import datetime
from sqlalchemy import create_engine
from typing import Dict, Tuple, List
import warnings

from parser import CertificateParser
from visualizer import CertificateVisualizer

class CertificateAnalyzer:
    """Enhanced analyzer class for certificate analysis"""
    
    def __init__(self, project_root: str):
        """
        Initialize the analyzer
        
        Args:
            project_root: Root directory path of the project
        """
        self.project_root = project_root
        self.setup_logging()
        self.setup_output_dirs()
        self.connect_databases()
        self.parser = CertificateParser()
        self.visualizer = CertificateVisualizer(self.output_dirs['plots'])
        
        # Security configuration
        self.security_config = {
            'min_key_size': 2048,
            'preferred_protocols': ['TLSv1.3'],
            'acceptable_protocols': ['TLSv1.2'],
            'high_risk_issuers': ['R10', 'R11'],
            'suspicious_domain_length': 50
        }

    def setup_logging(self):
        """Configure logging settings"""
        log_dir = os.path.join(self.project_root, 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        logging.basicConfig(
            filename=os.path.join(log_dir, f'cert_analysis_{datetime.now():%Y%m%d}.log'),
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def setup_output_dirs(self):
        """Create output directories for results"""
        self.output_dirs = {
            'data': os.path.join(self.project_root, 'results', 'cross_analysis', 'cert_registrar', 'data'),
            'plots': os.path.join(self.project_root, 'results', 'cross_analysis', 'cert_registrar', 'plots'),
            'models': os.path.join(self.project_root, 'models', 'cert_analysis')
        }
        for dir_path in self.output_dirs.values():
            os.makedirs(dir_path, exist_ok=True)

    def connect_databases(self):
        """Establish database connections using SQLAlchemy"""
        try:
            # Load database configuration
            config_path = os.path.join(self.project_root, 'config', 'database.json')
            with open(config_path, 'r') as f:
                db_config = json.load(f)

            # Create connection strings
            phish_conn_str = f"postgresql://{db_config['database']['user']}:{db_config['database']['password']}@{db_config['database']['host']}/website_data"
            normal_conn_str = "postgresql://postgres:asomura@192.168.1.92/normal_sites"

            # Create engines with error handling
            self.phish_engine = create_engine(phish_conn_str)
            self.normal_engine = create_engine(normal_conn_str)
            
            # Test connections
            with self.phish_engine.connect() as conn:
                conn.execute("SELECT 1")
            with self.normal_engine.connect() as conn:
                conn.execute("SELECT 1")
                
            self.logger.info("Database connections established successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to connect to databases: {str(e)}")
            raise

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
        
        # Certificate issuer score
        df['issuer_score'] = df['https_certificate_issuer'].apply(
            lambda x: 0.2 if x in self.security_config['high_risk_issuers'] else 1.0
        )
        
        # Domain features score
        df['domain_score'] = df.apply(self._calculate_domain_score, axis=1)
        
        # Cipher strength score
        df['cipher_score'] = df['cipher_suite'].apply(self._calculate_cipher_score)
        
        # Calculate final security score
        df['security_score'] = (
            weights['tls_version'] * df['tls_score'] +
            weights['key_size'] * df['key_score'] +
            weights['cert_issuer'] * df['issuer_score'] +
            weights['domain_features'] * df['domain_score'] +
            weights['cipher_strength'] * df['cipher_score']
        )
        
        return df

    def _calculate_domain_score(self, row: pd.Series) -> float:
        """Calculate domain security score"""
        domain_features = row.get('domain_features', {})
        if not domain_features:
            return 0.0
            
        scores = []
        
        # Length score
        length = domain_features.get('length', 0)
        length_score = 1.0 if length < 30 else (0.5 if length < 50 else 0.0)
        scores.append(length_score)
        
        # Entropy score
        entropy = domain_features.get('entropy', 0)
        entropy_score = 1.0 if entropy < 4.0 else (0.5 if entropy < 5.0 else 0.0)
        scores.append(entropy_score)
        
        # Special character score
        special_chars = domain_features.get('special_char_count', 0)
        special_score = 1.0 if special_chars == 0 else (0.5 if special_chars < 3 else 0.0)
        scores.append(special_score)
        
        return np.mean(scores)

    def _calculate_cipher_score(self, cipher: str) -> float:
        """Calculate cipher strength score"""
        if not cipher:
            return 0.0
            
        score = 0.0
        cipher = cipher.upper()
        
        # Check for strong encryption
        if any(x in cipher for x in ['GCM', 'CHACHA20', 'POLY1305']):
            score += 0.5
        
        # Check for strong hash
        if any(x in cipher for x in ['SHA384', 'SHA256']):
            score += 0.3
        
        # Check for perfect forward secrecy
        if any(x in cipher for x in ['ECDHE', 'DHE']):
            score += 0.2
            
        return score

    def analyze_cipher_suites(self, df: pd.DataFrame) -> Dict:
        """
        Analyze cipher suite distributions and security
        
        Args:
            df: DataFrame containing certificate data
            
        Returns:
            Dictionary containing cipher suite analysis
        """
        cipher_distribution = df.groupby(['site_type', 'cipher_suite']).size()
        cipher_dist_dict = {f"{site_type}_{cipher}": count 
                          for (site_type, cipher), count in cipher_distribution.items()}

        # Categorize ciphers
        def categorize_cipher(cipher):
            if not cipher:
                return 'unknown'
            cipher = cipher.upper()
            if any(x in cipher for x in ['GCM', 'CHACHA20', 'POLY1305']):
                return 'strong'
            elif 'SHA384' in cipher:
                return 'medium'
            else:
                return 'weak'

        df['cipher_category'] = df['cipher_suite'].apply(categorize_cipher)
        category_dist = df.groupby(['site_type', 'cipher_category']).size().to_dict()

        return {
            'total_unique_ciphers': df['cipher_suite'].nunique(),
            'cipher_distribution': cipher_dist_dict,
            'category_distribution': category_dist,
            'strong_cipher_count': len(df[df['cipher_category'] == 'strong']),
            'weak_cipher_count': len(df[df['cipher_category'].isin(['weak', 'unknown'])])
        }


def get_data_from_db(self, engine, site_type: str) -> pd.DataFrame:
        """
        Retrieve and process data from database with enhanced error handling
        
        Args:
            engine: SQLAlchemy engine
            site_type: Type of sites ('phishing' or 'normal')
            
        Returns:
            Processed DataFrame
        """
        query = """
        SELECT 
            domain_registrar,
            https_certificate_issuer,
            https_certificate_all,
            https_certificate_expiry,
            domain,
            whois_domain,
            https_certificate_domain,
            domain_status,
            whois_date,
            https_certificate_date
        FROM 
            website_data
        WHERE 
            status = 7
        """
        
        try:
            df = pd.read_sql(query, engine)
            df['site_type'] = site_type
            
            # Process certificates
            cert_details = []
            domain_features = []
            
            for _, row in df.iterrows():
                # Parse certificate
                cert_info = self.parser.parse_certificate_all(row['https_certificate_all'])
                cert_details.append(cert_info)
                
                # Extract domain features
                domain_feat = self.parser.extract_domain_features(row['domain'])
                domain_features.append(domain_feat)
            
            # Add parsed information to DataFrame
            df['cert_details'] = cert_details
            df['domain_features'] = domain_features
            
            # Extract common fields
            df['protocol_version'] = df['cert_details'].apply(lambda x: x.get('protocol_version'))
            df['cipher_suite'] = df['cert_details'].apply(lambda x: x.get('cipher_suite'))
            df['public_key_bits'] = df['cert_details'].apply(lambda x: x.get('public_key_bits'))
            df['cert_chain_length'] = df['cert_details'].apply(lambda x: x.get('cert_chain_length'))
            df['key_algorithm'] = df['cert_details'].apply(lambda x: x.get('key_algorithm'))
            df['signature_algorithm'] = df['cert_details'].apply(lambda x: x.get('signature_algorithm'))
            
            # Add validity period
            df['cert_valid_from'] = df['cert_details'].apply(lambda x: x.get('cert_dates', {}).get('not_before'))
            df['cert_valid_to'] = df['cert_details'].apply(lambda x: x.get('cert_dates', {}).get('not_after'))
            
            return df
            
        except Exception as e:
            self.logger.error(f"Error retrieving data for {site_type} sites: {str(e)}")
            raise

    def analyze_certificates(self) -> Tuple[pd.DataFrame, Dict]:
        """
        Perform comprehensive certificate analysis with enhanced features
        
        Returns:
            Tuple of (DataFrame containing analyzed data, Dictionary of statistics)
        """
        try:
            # Get and process data
            self.logger.info("Retrieving phishing site data...")
            phish_df = self.get_data_from_db(self.phish_engine, 'phishing')
            
            self.logger.info("Retrieving normal site data...")
            normal_df = self.get_data_from_db(self.normal_engine, 'normal')
            
            # Combine datasets
            combined_df = pd.concat([phish_df, normal_df], ignore_index=True)
            
            # Calculate security scores
            self.logger.info("Calculating security scores...")
            combined_df = self.calculate_security_score(combined_df)
            
            # Perform analyses
            cipher_analysis = self.analyze_cipher_suites(combined_df)
            
            # Calculate protocol distribution
            protocol_distribution = combined_df.groupby(['site_type', 'protocol_version']).size()
            protocol_dist_dict = {f"{site_type}_{protocol}": count 
                                for (site_type, protocol), count in protocol_distribution.items()}
            
            # Calculate validity periods
            validity_periods = self._analyze_validity_periods(combined_df)
            
            # Prepare comprehensive statistics
            stats = {
                'total_sites': len(combined_df),
                'phishing_sites': len(combined_df[combined_df['site_type'] == 'phishing']),
                'normal_sites': len(combined_df[combined_df['site_type'] == 'normal']),
                'unique_issuers': combined_df['https_certificate_issuer'].nunique(),
                'avg_chain_length': float(combined_df['cert_chain_length'].mean()),
                'avg_key_size': float(combined_df['public_key_bits'].mean()),
                'cipher_analysis': cipher_analysis,
                'protocol_distribution': protocol_dist_dict,
                'validity_periods': validity_periods,
                'security_scores': {
                    'mean': float(combined_df['security_score'].mean()),
                    'median': float(combined_df['security_score'].median()),
                    'std': float(combined_df['security_score'].std()),
                    'by_site_type': combined_df.groupby('site_type')['security_score'].describe().to_dict()
                }
            }
            
            return combined_df, stats
            
        except Exception as e:
            self.logger.error(f"Error in certificate analysis: {str(e)}")
            raise

    def _analyze_validity_periods(self, df: pd.DataFrame) -> Dict:
        """Analyze certificate validity periods"""
        validity_analysis = {
            'mean_valid_days': 0,
            'expired_certs': 0,
            'not_yet_valid': 0,
            'distribution': {}
        }
        
        now = datetime.now()
        
        # Calculate validity periods
        df['valid_days'] = (pd.to_datetime(df['cert_valid_to']) - 
                          pd.to_datetime(df['cert_valid_from'])).dt.total_seconds() / (24*3600)
        
        validity_analysis['mean_valid_days'] = float(df['valid_days'].mean())
        validity_analysis['expired_certs'] = int(df[pd.to_datetime(df['cert_valid_to']) < now].shape[0])
        validity_analysis['not_yet_valid'] = int(df[pd.to_datetime(df['cert_valid_from']) > now].shape[0])
        
        # Create distribution buckets
        validity_analysis['distribution'] = (
            df['valid_days']
            .map(lambda x: f"{int(x//30)} months")
            .value_counts()
            .to_dict()
        )
        
        return validity_analysis

    def save_results(self, df: pd.DataFrame, stats: Dict):
        """
        Save analysis results with compression and versioning
        
        Args:
            df: DataFrame containing analyzed data
            stats: Dictionary containing statistics
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Save main data with compression
        output_path = os.path.join(self.output_dirs['data'], f'cert_analysis_{timestamp}.csv.gz')
        df.to_csv(output_path, index=False, compression='gzip')
        
        # Save statistics
        stats_path = os.path.join(self.output_dirs['data'], f'detailed_stats_{timestamp}.json')
        with open(stats_path, 'w') as f:
            json.dump(stats, f, indent=4)
        
        # Create visualizations
        self.visualizer.create_all_visualizations(df, timestamp)
        
        self.logger.info(f"Results saved: {output_path}")
        self.logger.info(f"Statistics saved: {stats_path}")
