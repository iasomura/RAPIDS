# 04_certificate_temporal_analyzer.py
# Location: RAPIDS/src/certificate_analysis/04_certificate_temporal_analyzer.py

"""
Certificate temporal pattern analysis class.
This module handles:
- Weekday vs Weekend pattern analysis
- Business hours pattern analysis
- Monthly and seasonal pattern analysis
"""

from certificate_base_analyzer import CertificateBaseAnalyzer
from typing import Dict, List, Tuple
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import calendar
from .certificate_base_analyzer import CertificateBaseAnalyzer

class CertificateTemporalAnalyzer(CertificateBaseAnalyzer):
    """Analyzer for certificate temporal patterns"""
    
    def __init__(self, config_path: str = '/home/asomura/waseda/nextstep/RAPIDS/config/database.json'):
        """Initialize the temporal analyzer"""
        super().__init__(config_path)
        self.business_hours = range(9, 18)  # 9 AM to 5 PM

    def analyze_temporal_patterns(self, df: pd.DataFrame) -> Dict:
        """
        Analyze temporal patterns in certificate issuance
        
        Args:
            df: DataFrame containing certificate data
            
        Returns:
            Dictionary containing temporal analysis results
        """
        self.logger.info("Starting temporal pattern analysis")
        
        # Add temporal features
        df_temporal = self._add_temporal_features(df)
        
        # Analyze different temporal aspects
        results = {
            'weekday_patterns': self._analyze_weekday_patterns(df_temporal),
            'hour_patterns': self._analyze_hour_patterns(df_temporal),
            'monthly_patterns': self._analyze_monthly_patterns(df_temporal),
            'business_hours_analysis': self._analyze_business_hours(df_temporal)
        }
        
        self.logger.info("Completed temporal pattern analysis")
        return results

    def _add_temporal_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Add temporal features to DataFrame
        
        Args:
            df: Original DataFrame
            
        Returns:
            DataFrame with additional temporal features
        """
        df = df.copy()
        df['weekday'] = df['last_update'].dt.dayofweek
        df['hour'] = df['last_update'].dt.hour
        df['month'] = df['last_update'].dt.month
        df['year'] = df['last_update'].dt.year
        df['is_weekend'] = df['weekday'].isin([5, 6])
        df['is_business_hours'] = df['hour'].isin(self.business_hours)
        
        return df

    def _analyze_weekday_patterns(self, df: pd.DataFrame) -> Dict:
        """
        Analyze weekday vs weekend patterns
        
        Args:
            df: DataFrame with temporal features
            
        Returns:
            Dictionary containing weekday pattern analysis
        """
        weekday_stats = {
            'weekday_distribution': df['weekday'].map(lambda x: calendar.day_name[x]).value_counts().to_dict(),
            'weekend_ratio': df['is_weekend'].mean(),
            'daily_averages': df.groupby('weekday').size().to_dict()
        }
        
        # Add detailed weekend vs weekday stats
        weekend_df = df[df['is_weekend']]
        weekday_df = df[~df['is_weekend']]
        
        weekday_stats.update({
            'weekend_stats': {
                'total_count': len(weekend_df),
                'hourly_distribution': weekend_df['hour'].value_counts().to_dict()
            },
            'weekday_stats': {
                'total_count': len(weekday_df),
                'hourly_distribution': weekday_df['hour'].value_counts().to_dict()
            }
        })
        
        return weekday_stats

    def _analyze_hour_patterns(self, df: pd.DataFrame) -> Dict:
        """
        Analyze hourly patterns
        
        Args:
            df: DataFrame with temporal features
            
        Returns:
            Dictionary containing hourly pattern analysis
        """
        hour_stats = {
            'hourly_distribution': df['hour'].value_counts().to_dict(),
            'business_hours_ratio': df['is_business_hours'].mean(),
            'peak_hours': self._find_peak_hours(df)
        }
        
        # Add hour patterns by weekday
        for day in range(7):
            day_name = calendar.day_name[day]
            day_data = df[df['weekday'] == day]
            hour_stats[f'{day_name.lower()}_hours'] = day_data['hour'].value_counts().to_dict()
        
        return hour_stats

    def _analyze_monthly_patterns(self, df: pd.DataFrame) -> Dict:
        """
        Analyze monthly and seasonal patterns
        
        Args:
            df: DataFrame with temporal features
            
        Returns:
            Dictionary containing monthly pattern analysis
        """
        monthly_stats = {
            'monthly_distribution': df['month'].map(lambda x: calendar.month_name[x]).value_counts().to_dict(),
            'yearly_monthly_counts': df.groupby(['year', 'month']).size().to_dict()
        }
        
        # Add seasonal analysis
        seasons = {
            'Winter': [12, 1, 2],
            'Spring': [3, 4, 5],
            'Summer': [6, 7, 8],
            'Fall': [9, 10, 11]
        }
        
        df['season'] = df['month'].map(lambda x: next(season for season, months in seasons.items() if x in months))
        monthly_stats['seasonal_distribution'] = df['season'].value_counts().to_dict()
        
        return monthly_stats

    def _analyze_business_hours(self, df: pd.DataFrame) -> Dict:
        """
        Analyze business hours patterns
        
        Args:
            df: DataFrame with temporal features
            
        Returns:
            Dictionary containing business hours analysis
        """
        business_hours_df = df[df['is_business_hours']]
        non_business_hours_df = df[~df['is_business_hours']]
        
        business_stats = {
            'business_hours_count': len(business_hours_df),
            'non_business_hours_count': len(non_business_hours_df),
            'business_hours_ratio': len(business_hours_df) / len(df),
            'business_hours_weekday_ratio': 
                len(business_hours_df[~business_hours_df['is_weekend']]) / 
                len(df[~df['is_weekend']]) if len(df[~df['is_weekend']]) > 0 else 0,
            'business_hours_weekend_ratio':
                len(business_hours_df[business_hours_df['is_weekend']]) /
                len(df[df['is_weekend']]) if len(df[df['is_weekend']]) > 0 else 0
        }
        
        return business_stats

    def _find_peak_hours(self, df: pd.DataFrame) -> Dict:
        """
        Find peak hours for certificate issuance
        
        Args:
            df: DataFrame with temporal features
            
        Returns:
            Dictionary containing peak hour analysis
        """
        hourly_counts = df['hour'].value_counts()
        mean_count = hourly_counts.mean()
        std_count = hourly_counts.std()
        
        peak_hours = hourly_counts[hourly_counts > (mean_count + std_count)]
        
        return {
            'peak_hours': peak_hours.index.tolist(),
            'peak_hour_counts': peak_hours.to_dict(),
            'threshold': mean_count + std_count,
            'mean_count': mean_count,
            'std_count': std_count
        }

# Example usage in Jupyter notebook:
if __name__ == "__main__":
    # Create analyzer instance
    analyzer = CertificateTemporalAnalyzer()
    
    # Analyze both databases
    for db_name in ['website_data', 'normal_sites']:
        try:
            print(f"\nAnalyzing {db_name}...")
            
            # Extract data
            df = analyzer.extract_certificate_data(db_name)
            
            # Analyze temporal patterns
            results = analyzer.analyze_temporal_patterns(df)
            
            # Print summary
            print("\nTemporal Pattern Summary:")
            print(f"Weekend Ratio: {results['weekday_patterns']['weekend_ratio']:.2%}")
            print(f"Business Hours Ratio: {results['hour_patterns']['business_hours_ratio']:.2%}")
            
            print("\nPeak Hours:")
            for hour in results['hour_patterns']['peak_hours']['peak_hours']:
                print(f"Hour {hour:02d}:00")
            
            # Save results
            analyzer.save_results(results, db_name, 'temporal_analysis')
            
        except Exception as e:
            print(f"Error processing {db_name}: {str(e)}")
