# 03_certificate_renewal_analyzer.py
# Location: RAPIDS/src/certificate_analysis/03_certificate_renewal_analyzer.py

"""
Certificate renewal pattern analysis class.
This module handles:
- Certificate renewal interval detection
- Renewal pattern analysis
- Irregular renewal identification
"""
from certificate_base_analyzer import CertificateBaseAnalyzer
from typing import Dict, List, Set, Optional
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from .certificate_base_analyzer import CertificateBaseAnalyzer

class CertificateRenewalAnalyzer(CertificateBaseAnalyzer):
    """Analyzer for certificate renewal patterns"""
    
    def __init__(self, config_path: str = '/home/asomura/waseda/nextstep/RAPIDS/config/database.json'):
        """Initialize the renewal analyzer"""
        super().__init__(config_path)
        self.irregular_threshold = 0.5  # 50% deviation from mean interval

    def analyze_renewal_patterns(self, df: pd.DataFrame) -> Dict:
        """
        Analyze certificate renewal patterns
        
        Args:
            df: DataFrame containing certificate data
            
        Returns:
            Dictionary containing renewal analysis results
        """
        self.logger.info("Starting renewal pattern analysis")
        
        # Extract renewal information
        renewal_info = self._extract_renewal_info(df)
        
        # Calculate renewal statistics
        stats = self._calculate_renewal_statistics(renewal_info)
        
        # Analyze renewal patterns
        patterns = self._analyze_renewal_patterns(renewal_info)
        
        results = {
            'statistics': stats,
            'patterns': patterns,
            'irregular_renewals': self._get_irregular_renewals(renewal_info)
        }
        
        self.logger.info("Completed renewal pattern analysis")
        return results

    def _extract_renewal_info(self, df: pd.DataFrame) -> Dict:
        """
        Extract renewal information for all domains
        
        Args:
            df: DataFrame containing certificate data
            
        Returns:
            Dictionary containing renewal information
        """
        df = df.sort_values(['domain', 'last_update'])
        domains = df['domain'].unique()
        
        renewal_info = {
            'intervals': [],
            'irregular_domains': set(),
            'renewal_counts': {},
            'first_seen': {},
            'last_seen': {},
            'total_duration': {}
        }
        
        for domain in domains:
            domain_certs = df[df['domain'] == domain]
            if len(domain_certs) > 1:
                # Calculate intervals
                intervals = domain_certs['last_update'].diff().dt.total_seconds() / 86400  # Convert to days
                valid_intervals = intervals.dropna()
                
                if len(valid_intervals) > 0:
                    renewal_info['intervals'].extend(valid_intervals.tolist())
                    renewal_info['renewal_counts'][domain] = len(domain_certs)
                    renewal_info['first_seen'][domain] = domain_certs['last_update'].min()
                    renewal_info['last_seen'][domain] = domain_certs['last_update'].max()
                    renewal_info['total_duration'][domain] = (
                        renewal_info['last_seen'][domain] - renewal_info['first_seen'][domain]
                    ).total_seconds() / 86400
                    
                    # Check for irregular renewals
                    mean_interval = valid_intervals.mean()
                    if any(abs(interval - mean_interval) > mean_interval * self.irregular_threshold 
                          for interval in valid_intervals):
                        renewal_info['irregular_domains'].add(domain)
        
        return renewal_info

    def _calculate_renewal_statistics(self, renewal_info: Dict) -> Dict:
        """
        Calculate statistical measures for renewal intervals
        
        Args:
            renewal_info: Dictionary containing renewal information
            
        Returns:
            Dictionary containing statistical measures
        """
        if not renewal_info['intervals']:
            return {
                'mean_interval': None,
                'median_interval': None,
                'std_interval': None,
                'min_interval': None,
                'max_interval': None,
                'total_renewals': 0,
                'domains_with_renewals': 0
            }
        
        intervals = pd.Series(renewal_info['intervals'])
        
        return {
            'mean_interval': intervals.mean(),
            'median_interval': intervals.median(),
            'std_interval': intervals.std(),
            'min_interval': intervals.min(),
            'max_interval': intervals.max(),
            'total_renewals': sum(renewal_info['renewal_counts'].values()),
            'domains_with_renewals': len(renewal_info['renewal_counts'])
        }

    def _analyze_renewal_patterns(self, renewal_info: Dict) -> Dict:
        """
        Analyze patterns in renewal intervals
        
        Args:
            renewal_info: Dictionary containing renewal information
            
        Returns:
            Dictionary containing pattern analysis
        """
        if not renewal_info['intervals']:
            return {
                'interval_distribution': {},
                'renewal_frequency': {},
                'duration_distribution': {}
            }
        
        intervals = pd.Series(renewal_info['intervals'])
        renewal_counts = pd.Series(renewal_info['renewal_counts'])
        durations = pd.Series(renewal_info['total_duration'])
        
        # Analyze interval distribution
        interval_bins = [0, 30, 60, 90, 180, 365, float('inf')]
        interval_labels = [
            '0-30 days', '31-60 days', '61-90 days',
            '91-180 days', '181-365 days', '365+ days'
        ]
        interval_dist = pd.cut(intervals, bins=interval_bins, labels=interval_labels)
        
        # Analyze renewal frequency
        renewal_freq = renewal_counts.value_counts().sort_index()
        
        # Analyze duration distribution
        duration_bins = [0, 90, 180, 365, float('inf')]
        duration_labels = ['0-90 days', '91-180 days', '181-365 days', '365+ days']
        duration_dist = pd.cut(durations, bins=duration_bins, labels=duration_labels)
        
        return {
            'interval_distribution': interval_dist.value_counts().to_dict(),
            'renewal_frequency': renewal_freq.to_dict(),
            'duration_distribution': duration_dist.value_counts().to_dict()
        }

    def _get_irregular_renewals(self, renewal_info: Dict) -> Dict:
        """
        Get detailed information about irregular renewals
        
        Args:
            renewal_info: Dictionary containing renewal information
            
        Returns:
            Dictionary containing irregular renewal information
        """
        return {
            'count': len(renewal_info['irregular_domains']),
            'domains': list(renewal_info['irregular_domains']),
            'ratio': len(renewal_info['irregular_domains']) / len(renewal_info['renewal_counts'])
                     if renewal_info['renewal_counts'] else 0
        }

# Example usage in Jupyter notebook:
if __name__ == "__main__":
    # Create analyzer instance
    analyzer = CertificateRenewalAnalyzer()
    
    # Analyze both databases
    for db_name in ['website_data', 'normal_sites']:
        try:
            print(f"\nAnalyzing {db_name}...")
            
            # Extract data
            df = analyzer.extract_certificate_data(db_name)
            
            # Analyze renewal patterns
            results = analyzer.analyze_renewal_patterns(df)
            
            # Print summary
            print("\nRenewal Statistics:")
            if results['statistics']['mean_interval'] is not None:
                print(f"Mean interval: {results['statistics']['mean_interval']:.2f} days")
                print(f"Median interval: {results['statistics']['median_interval']:.2f} days")
                print(f"Total renewals: {results['statistics']['total_renewals']}")
                print(f"Domains with renewals: {results['statistics']['domains_with_renewals']}")
            
            print("\nIrregular Renewals:")
            print(f"Count: {results['irregular_renewals']['count']}")
            print(f"Ratio: {results['irregular_renewals']['ratio']:.2%}")
            
            # Save results
            analyzer.save_results(results, db_name, 'renewal_analysis')
            
        except Exception as e:
            print(f"Error processing {db_name}: {str(e)}")
