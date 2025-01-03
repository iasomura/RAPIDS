#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Base Certificate Analyzer Module
Contains the main CertificateAnalyzer class and initialization logic.
"""

import os
import logging
from datetime import datetime
from typing import Dict, Tuple
import pandas as pd

from parser import CertificateParser
from visualizer import CertificateVisualizer
from .database import DatabaseHandler
from .security import SecurityScorer
from .cipher import CipherAnalyzer

class CertificateAnalyzer:
    """Main analyzer class for certificate analysis"""
    
    def __init__(self, project_root: str):
        """
        Initialize the analyzer
        
        Args:
            project_root: Root directory path of the project
        """
        self.project_root = project_root
        self.setup_logging()
        self.setup_output_dirs()
        
        # Initialize components
        self.db_handler = DatabaseHandler(project_root)
        self.parser = CertificateParser()
        self.visualizer = CertificateVisualizer(self.output_dirs['plots'])
        self.security_scorer = SecurityScorer()
        self.cipher_analyzer = CipherAnalyzer()

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

    def analyze_certificates(self) -> Tuple[pd.DataFrame, Dict]:
        """
        Perform comprehensive certificate analysis
        
        Returns:
            Tuple of (DataFrame containing analyzed data, Dictionary of statistics)
        """
        try:
            # Get and process data
            self.logger.info("Retrieving phishing site data...")
            phish_df = self.db_handler.get_data('phishing')
            
            self.logger.info("Retrieving normal site data...")
            normal_df = self.db_handler.get_data('normal')
            
            # Combine datasets
            combined_df = pd.concat([phish_df, normal_df], ignore_index=True)
            
            # Calculate security scores
            self.logger.info("Calculating security scores...")
            combined_df = self.security_scorer.calculate_security_score(combined_df)
            
            # Perform cipher analysis
            cipher_analysis = self.cipher_analyzer.analyze_cipher_suites(combined_df)
            
            # Calculate protocol distribution
            protocol_distribution = combined_df.groupby(['site_type', 'protocol_version']).size()
            protocol_dist_dict = {f"{site_type}_{protocol}": count 
                                for (site_type, protocol), count in protocol_distribution.items()}
            
            # Calculate validity periods
            validity_periods = self._analyze_validity_periods(combined_df)
            
            # Prepare comprehensive statistics
            stats = self._prepare_statistics(combined_df, cipher_analysis, protocol_dist_dict, validity_periods)
            
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

    def _prepare_statistics(self, df: pd.DataFrame, cipher_analysis: Dict, 
                          protocol_dist: Dict, validity_periods: Dict) -> Dict:
        """Prepare comprehensive statistics"""
        return {
            'total_sites': len(df),
            'phishing_sites': len(df[df['site_type'] == 'phishing']),
            'normal_sites': len(df[df['site_type'] == 'normal']),
            'unique_issuers': df['https_certificate_issuer'].nunique(),
            'avg_chain_length': float(df['cert_chain_length'].mean()),
            'avg_key_size': float(df['public_key_bits'].mean()),
            'cipher_analysis': cipher_analysis,
            'protocol_distribution': protocol_dist,
            'validity_periods': validity_periods,
            'security_scores': {
                'mean': float(df['security_score'].mean()),
                'median': float(df['security_score'].median()),
                'std': float(df['security_score'].std()),
                'by_site_type': df.groupby('site_type')['security_score'].describe().to_dict()
            }
        }

    def save_results(self, df: pd.DataFrame, stats: Dict):
        """Save analysis results with compression and versioning"""
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