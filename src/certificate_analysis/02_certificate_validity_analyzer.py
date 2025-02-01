# 02_certificate_validity_analyzer.py
# Location: RAPIDS/src/certificate_analysis/02_certificate_validity_analyzer.py

"""
Certificate validity period analysis class.
This module handles:
- Certificate expiry period extraction
- Validity period statistics calculation
- Validity pattern analysis
"""

from certificate_base_analyzer import CertificateBaseAnalyzer
from typing import Dict, List, Optional
import pandas as pd
import numpy as np
from datetime import datetime
import re
from .certificate_base_analyzer import CertificateBaseAnalyzer

class CertificateValidityAnalyzer(CertificateBaseAnalyzer):
    """Analyzer for certificate validity periods and patterns"""
    
    def __init__(self, config_path: str = '/home/asomura/waseda/nextstep/RAPIDS/config/database.json'):
        """Initialize the validity analyzer"""
        super().__init__(config_path)
        self.validity_patterns = {
            'days': r'(\d+)\s*(?:days?|d)',
            'validity': r'validity[^:]*?:\s*(\d+)',
            'valid_for': r'valid for\s*(\d+)',
            'expires_in': r'expires? in\s*(\d+)',
            'date_range': r'(\d{4}-\d{2}-\d{2})'
        }

    def analyze_validity_periods(self, df: pd.DataFrame) -> Dict:
        """
        Analyze certificate validity periods and patterns
        
        Args:
            df: DataFrame containing certificate data
            
        Returns:
            Dictionary containing validity analysis results
        """
        self.logger.info("Starting validity period analysis")
        
        # Extract validity periods
        validity_periods = self._extract_all_validity_periods(df)
        
        # Calculate basic statistics
        stats = self._calculate_validity_statistics(validity_periods)
        
        # Analyze validity patterns
        patterns = self._analyze_validity_patterns(validity_periods)
        
        results = {
            'statistics': stats,
            'patterns': patterns
        }
        
        self.logger.info("Completed validity period analysis")
        return results

    def _extract_all_validity_periods(self, df: pd.DataFrame) -> pd.Series:
        """
        Extract validity periods for all certificates
        
        Args:
            df: DataFrame containing certificate data
            
        Returns:
            Series containing validity periods in days
        """
        return df['https_certificate_expiry'].apply(self._extract_validity_period)

    def _extract_validity_period(self, expiry_text: str) -> int:
        """
        Extract validity period from certificate expiry text
        
        Args:
            expiry_text: Text containing expiry information
            
        Returns:
            Number of days until expiry
        """
        if pd.isna(expiry_text):
            return 0
            
        expiry_text = str(expiry_text)
        
        # Try direct day patterns
        for pattern in [self.validity_patterns['days'], 
                       self.validity_patterns['validity'],
                       self.validity_patterns['valid_for'],
                       self.validity_patterns['expires_in']]:
            match = re.search(pattern, expiry_text, re.IGNORECASE)
            if match:
                return int(match.group(1))
        
        # Try date range pattern
        try:
            dates = re.findall(self.validity_patterns['date_range'], expiry_text)
            if len(dates) >= 2:
                start_date = datetime.strptime(dates[0], '%Y-%m-%d')
                end_date = datetime.strptime(dates[1], '%Y-%m-%d')
                return (end_date - start_date).days
        except Exception as e:
            self.logger.warning(f"Error extracting dates: {str(e)}")
            
        return 0

    def _calculate_validity_statistics(self, validity_periods: pd.Series) -> Dict:
        """
        Calculate statistical measures for validity periods
        
        Args:
            validity_periods: Series containing validity periods
            
        Returns:
            Dictionary containing statistical measures
        """
        return {
            'mean_validity': validity_periods.mean(),
            'median_validity': validity_periods.median(),
            'std_validity': validity_periods.std(),
            'min_validity': validity_periods.min(),
            'max_validity': validity_periods.max(),
            'quartiles': {
                'q1': validity_periods.quantile(0.25),
                'q2': validity_periods.quantile(0.50),
                'q3': validity_periods.quantile(0.75)
            }
        }

    def _analyze_validity_patterns(self, validity_periods: pd.Series) -> Dict:
        """
        Analyze patterns in validity periods
        
        Args:
            validity_periods: Series containing validity periods
            
        Returns:
            Dictionary containing pattern analysis
        """
        # Calculate period distributions
        total_certs = len(validity_periods)
        patterns = {
            'short_term': {  # Less than 90 days
                'count': len(validity_periods[validity_periods < 90]),
                'ratio': (validity_periods < 90).mean()
            },
            'medium_term': {  # 90-365 days
                'count': len(validity_periods[(validity_periods >= 90) & (validity_periods < 365)]),
                'ratio': ((validity_periods >= 90) & (validity_periods < 365)).mean()
            },
            'long_term': {  # 365 days or more
                'count': len(validity_periods[validity_periods >= 365]),
                'ratio': (validity_periods >= 365).mean()
            }
        }
        
        # Add common validity periods
        common_periods = validity_periods.value_counts().head(5).to_dict()
        patterns['common_periods'] = {
            str(period): {
                'count': count,
                'ratio': count / total_certs
            } for period, count in common_periods.items()
        }
        
        return patterns

# Example usage in Jupyter notebook:
if __name__ == "__main__":
    # Create analyzer instance
    analyzer = CertificateValidityAnalyzer()
    
    # Analyze both databases
    for db_name in ['website_data', 'normal_sites']:
        try:
            print(f"\nAnalyzing {db_name}...")
            
            # Extract data
            df = analyzer.extract_certificate_data(db_name)
            
            # Analyze validity periods
            results = analyzer.analyze_validity_periods(df)
            
            # Print summary
            print("\nValidity Period Statistics:")
            print(f"Mean validity: {results['statistics']['mean_validity']:.2f} days")
            print(f"Median validity: {results['statistics']['median_validity']:.2f} days")
            print(f"Standard deviation: {results['statistics']['std_validity']:.2f} days")
            
            print("\nValidity Period Patterns:")
            print(f"Short-term certificates (<90 days): {results['patterns']['short_term']['ratio']:.2%}")
            print(f"Medium-term certificates (90-365 days): {results['patterns']['medium_term']['ratio']:.2%}")
            print(f"Long-term certificates (>365 days): {results['patterns']['long_term']['ratio']:.2%}")
            
            # Save results
            analyzer.save_results(results, db_name, 'validity_analysis')
            
        except Exception as e:
            print(f"Error processing {db_name}: {str(e)}")
