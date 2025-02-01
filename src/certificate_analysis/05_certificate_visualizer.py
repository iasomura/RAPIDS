# 05_certificate_visualizer.py
# Location: RAPIDS/src/certificate_analysis/05_certificate_visualizer.py

"""
Certificate analysis visualization class.
This module handles:
- Visualization of validity periods
- Visualization of renewal patterns
- Visualization of temporal patterns
"""

from certificate_base_analyzer import CertificateBaseAnalyzer
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path
import calendar
from typing import Dict, List, Optional
from datetime import datetime
from .certificate_base_analyzer import CertificateBaseAnalyzer

class CertificateVisualizer(CertificateBaseAnalyzer):
    """Visualizer for certificate analysis results"""
    
    def __init__(self, config_path: str = '/home/asomura/waseda/nextstep/RAPIDS/config/database.json'):
        """Initialize the visualizer"""
        super().__init__(config_path)
        self._setup_plot_style()
        
    def _setup_plot_style(self) -> None:
        """Configure plot style settings"""
        plt.style.use('default')
        self.colors = {
            'primary': '#2196F3',
            'secondary': '#FF5722',
            'accent': '#4CAF50',
            'neutral': '#9E9E9E'
        }
        
    def create_visualizations(self, results: Dict, db_name: str) -> None:
        """
        Create all visualizations for analysis results
        
        Args:
            results: Dictionary containing analysis results
            db_name: Name of the database analyzed
        """
        self.logger.info(f"Creating visualizations for {db_name}")
        
        # Create individual visualizations
        self._plot_validity_distribution(results.get('validity_analysis', {}), db_name)
        self._plot_renewal_patterns(results.get('renewal_analysis', {}), db_name)
        self._plot_temporal_patterns(results.get('temporal_analysis', {}), db_name)
        
    def _plot_validity_distribution(self, validity_results: Dict, db_name: str) -> None:
        """
        Create validity period distribution plots
        
        Args:
            validity_results: Dictionary containing validity analysis results
            db_name: Name of the database analyzed
        """
        if not validity_results:
            return
            
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # Plot validity period distribution
        stats = validity_results.get('statistics', {})
        if stats.get('validity_distribution'):
            periods = list(stats['validity_distribution'].keys())
            counts = list(stats['validity_distribution'].values())
            
            ax1.bar(range(len(periods)), counts, color=self.colors['primary'])
            ax1.set_xticks(range(len(periods)))
            ax1.set_xticklabels(periods, rotation=45)
            ax1.set_title('Certificate Validity Period Distribution')
            ax1.set_xlabel('Validity Period (days)')
            ax1.set_ylabel('Number of Certificates')
            
        # Plot validity period categories
        patterns = validity_results.get('patterns', {})
        if patterns:
            categories = ['Short-term', 'Medium-term', 'Long-term']
            ratios = [
                patterns.get('short_term', {}).get('ratio', 0),
                patterns.get('medium_term', {}).get('ratio', 0),
                patterns.get('long_term', {}).get('ratio', 0)
            ]
            
            ax2.bar(categories, ratios, color=self.colors['secondary'])
            ax2.set_title('Certificate Validity Categories')
            ax2.set_ylabel('Ratio')
            ax2.set_ylim(0, 1)
            
        plt.tight_layout()
        plt.savefig(self.output_dir / f'validity_distribution_{db_name}_{self.timestamp}.png')
        plt.close()
        
    def _plot_renewal_patterns(self, renewal_results: Dict, db_name: str) -> None:
        """
        Create renewal pattern plots
        
        Args:
            renewal_results: Dictionary containing renewal analysis results
            db_name: Name of the database analyzed
        """
        if not renewal_results:
            return
            
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 12))
        
        # Plot renewal interval distribution
        patterns = renewal_results.get('patterns', {})
        if patterns.get('interval_distribution'):
            intervals = list(patterns['interval_distribution'].keys())
            counts = list(patterns['interval_distribution'].values())
            
            ax1.bar(range(len(intervals)), counts, color=self.colors['primary'])
            ax1.set_xticks(range(len(intervals)))
            ax1.set_xticklabels(intervals, rotation=45)
            ax1.set_title('Certificate Renewal Interval Distribution')
            ax1.set_xlabel('Interval')
            ax1.set_ylabel('Number of Renewals')
            
        # Plot renewal frequency
        if patterns.get('renewal_frequency'):
            frequencies = list(patterns['renewal_frequency'].keys())
            counts = list(patterns['renewal_frequency'].values())
            
            ax2.bar(frequencies, counts, color=self.colors['secondary'])
            ax2.set_title('Certificate Renewal Frequency')
            ax2.set_xlabel('Number of Renewals')
            ax2.set_ylabel('Number of Domains')
            
        plt.tight_layout()
        plt.savefig(self.output_dir / f'renewal_patterns_{db_name}_{self.timestamp}.png')
        plt.close()
        
    def _plot_temporal_patterns(self, temporal_results: Dict, db_name: str) -> None:
        """
        Create temporal pattern plots
        
        Args:
            temporal_results: Dictionary containing temporal analysis results
            db_name: Name of the database analyzed
        """
        if not temporal_results:
            return
            
        # Create daily pattern plot
        self._plot_daily_patterns(temporal_results, db_name)
        # Create hourly pattern plot
        self._plot_hourly_patterns(temporal_results, db_name)
        # Create monthly pattern plot
        self._plot_monthly_patterns(temporal_results, db_name)
        
    def _plot_daily_patterns(self, temporal_results: Dict, db_name: str) -> None:
        """Create daily pattern visualization"""
        weekday_patterns = temporal_results.get('weekday_patterns', {})
        if not weekday_patterns:
            return
            
        plt.figure(figsize=(12, 6))
        
        days = list(calendar.day_name)
        counts = [weekday_patterns.get('weekday_distribution', {}).get(day, 0) for day in days]
        
        plt.bar(days, counts, color=self.colors['primary'])
        plt.title('Certificate Issuance by Day of Week')
        plt.xlabel('Day of Week')
        plt.ylabel('Number of Certificates')
        plt.xticks(rotation=45)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / f'daily_patterns_{db_name}_{self.timestamp}.png')
        plt.close()
        
    def _plot_hourly_patterns(self, temporal_results: Dict, db_name: str) -> None:
        """Create hourly pattern visualization"""
        hour_patterns = temporal_results.get('hour_patterns', {})
        if not hour_patterns:
            return
            
        plt.figure(figsize=(12, 6))
        
        hours = range(24)
        counts = [hour_patterns.get('hourly_distribution', {}).get(hour, 0) for hour in hours]
        
        plt.plot(hours, counts, color=self.colors['secondary'], marker='o')
        plt.title('Certificate Issuance by Hour')
        plt.xlabel('Hour of Day')
        plt.ylabel('Number of Certificates')
        plt.grid(True, linestyle='--', alpha=0.7)
        
        # Highlight business hours
        plt.axvspan(9, 17, color=self.colors['accent'], alpha=0.1, label='Business Hours')
        plt.legend()
        
        plt.tight_layout()
        plt.savefig(self.output_dir / f'hourly_patterns_{db_name}_{self.timestamp}.png')
        plt.close()
        
    def _plot_monthly_patterns(self, temporal_results: Dict, db_name: str) -> None:
        """Create monthly pattern visualization"""
        monthly_patterns = temporal_results.get('monthly_patterns', {})
        if not monthly_patterns:
            return
            
        plt.figure(figsize=(12, 6))
        
        months = list(calendar.month_name)[1:]  # Skip empty first element
        counts = [monthly_patterns.get('monthly_distribution', {}).get(month, 0) for month in months]
        
        plt.bar(months, counts, color=self.colors['primary'])
        plt.title('Certificate Issuance by Month')
        plt.xlabel('Month')
        plt.ylabel('Number of Certificates')
        plt.xticks(rotation=45)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / f'monthly_patterns_{db_name}_{self.timestamp}.png')
        plt.close()

# Example usage in Jupyter notebook:
if __name__ == "__main__":
    # Create visualizer instance
    visualizer = CertificateVisualizer()
    
    # Example analysis results (you would typically load these from saved files)
    example_results = {
        'validity_analysis': {...},  # Your validity analysis results
        'renewal_analysis': {...},   # Your renewal analysis results
        'temporal_analysis': {...}   # Your temporal analysis results
    }
    
    # Create visualizations
    try:
        for db_name in ['website_data', 'normal_sites']:
            print(f"\nCreating visualizations for {db_name}...")
            visualizer.create_visualizations(example_results, db_name)
            print(f"Visualizations saved in {visualizer.output_dir}")
            
    except Exception as e:
        print(f"Error creating visualizations: {str(e)}")
