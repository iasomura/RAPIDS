# 06_main_certificate_analysis.py
# Location: RAPIDS/src/certificate_analysis/06_main_certificate_analysis.py

"""
Main certificate analysis script.
This script coordinates all certificate analyzers and visualizes the results.

Run this script to perform the complete certificate analysis pipeline:
1. Validity period analysis
2. Renewal pattern analysis
3. Temporal pattern analysis
4. Result visualization
"""

# メインスクリプトの先頭で
from certificate_validity_analyzer import CertificateValidityAnalyzer
from certificate_renewal_analyzer import CertificateRenewalAnalyzer
from certificate_temporal_analyzer import CertificateTemporalAnalyzer
from certificate_visualizer import CertificateVisualizer
import json
from pathlib import Path
from typing import Dict, Optional
from datetime import datetime
import logging

from certificate_validity_analyzer import CertificateValidityAnalyzer
from certificate_renewal_analyzer import CertificateRenewalAnalyzer
from certificate_temporal_analyzer import CertificateTemporalAnalyzer
from certificate_visualizer import CertificateVisualizer

class CertificateAnalysisPipeline:
    """Coordinator for the certificate analysis pipeline"""
    
    def __init__(self, config_path: str = '/home/asomura/waseda/nextstep/RAPIDS/config/database.json'):
        """
        Initialize the analysis pipeline
        
        Args:
            config_path: Path to database configuration file
        """
        self.config_path = config_path
        self.setup_environment()
        self.setup_logging()
        
        # Initialize analyzers
        self.validity_analyzer = CertificateValidityAnalyzer(config_path)
        self.renewal_analyzer = CertificateRenewalAnalyzer(config_path)
        self.temporal_analyzer = CertificateTemporalAnalyzer(config_path)
        self.visualizer = CertificateVisualizer(config_path)
        
    def setup_environment(self) -> None:
        """Setup analysis environment"""
        self.base_dir = Path('/home/asomura/waseda/nextstep/RAPIDS')
        self.output_dir = self.base_dir / 'reports' / 'analysis_results'
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def setup_logging(self) -> None:
        """Configure logging settings"""
        log_dir = self.base_dir / 'data' / 'logs'
        log_dir.mkdir(parents=True, exist_ok=True)
        
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        logging.basicConfig(
            filename=log_dir / f'analysis_pipeline_{self.timestamp}.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
    def run_analysis(self, db_name: str) -> Dict:
        """
        Run complete analysis for a database
        
        Args:
            db_name: Name of the database to analyze
            
        Returns:
            Dictionary containing all analysis results
        """
        self.logger.info(f"Starting analysis for {db_name}")
        
        try:
            # Extract data
            df = self.validity_analyzer.extract_certificate_data(db_name)
            
            # Run analyses
            validity_results = self.validity_analyzer.analyze_validity_periods(df)
            renewal_results = self.renewal_analyzer.analyze_renewal_patterns(df)
            temporal_results = self.temporal_analyzer.analyze_temporal_patterns(df)
            
            # Combine results
            results = {
                'validity_analysis': validity_results,
                'renewal_analysis': renewal_results,
                'temporal_analysis': temporal_results
            }
            
            # Create visualizations
            self.visualizer.create_visualizations(results, db_name)
            
            # Save combined results
            self._save_results(results, db_name)
            
            self.logger.info(f"Analysis completed for {db_name}")
            return results
            
        except Exception as e:
            self.logger.error(f"Error analyzing {db_name}: {str(e)}")
            raise
            
    def _save_results(self, results: Dict, db_name: str) -> None:
        """
        Save analysis results to file
        
        Args:
            results: Dictionary containing analysis results
            db_name: Name of the database analyzed
        """
        output_path = self.output_dir / f'analysis_results_{db_name}_{self.timestamp}.json'
        try:
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            self.logger.info(f"Results saved to {output_path}")
        except Exception as e:
            self.logger.error(f"Error saving results: {str(e)}")
            raise
            
    def print_summary(self, results: Dict, db_name: str) -> None:
        """
        Print summary of analysis results
        
        Args:
            results: Dictionary containing analysis results
            db_name: Name of the database analyzed
        """
        print(f"\nSummary for {db_name}:")
        print("=" * 50)
        
        # Validity summary
        validity = results.get('validity_analysis', {})
        if validity:
            stats = validity.get('statistics', {})
            print("\nValidity Period Analysis:")
            print(f"Mean validity period: {stats.get('mean_validity', 0):.2f} days")
            print(f"Median validity period: {stats.get('median_validity', 0):.2f} days")
            
            patterns = validity.get('patterns', {})
            print(f"\nShort-term certificates (<90 days): {patterns.get('short_term', {}).get('ratio', 0):.2%}")
            print(f"Medium-term certificates (90-365 days): {patterns.get('medium_term', {}).get('ratio', 0):.2%}")
            print(f"Long-term certificates (>365 days): {patterns.get('long_term', {}).get('ratio', 0):.2%}")
            
        # Renewal summary
        renewal = results.get('renewal_analysis', {})
        if renewal:
            stats = renewal.get('statistics', {})
            print("\nRenewal Pattern Analysis:")
            print(f"Domains with renewals: {stats.get('domains_with_renewals', 0)}")
            print(f"Total renewals: {stats.get('total_renewals', 0)}")
            print(f"Mean renewal interval: {stats.get('mean_interval', 0):.2f} days")
            
            irreg = renewal.get('irregular_renewals', {})
            print(f"Irregular renewals: {irreg.get('count', 0)} domains ({irreg.get('ratio', 0):.2%})")
            
        # Temporal summary
        temporal = results.get('temporal_analysis', {})
        if temporal:
            weekday = temporal.get('weekday_patterns', {})
            hours = temporal.get('hour_patterns', {})
            print("\nTemporal Pattern Analysis:")
            print(f"Weekend ratio: {weekday.get('weekend_ratio', 0):.2%}")
            print(f"Business hours ratio: {hours.get('business_hours_ratio', 0):.2%}")
            
            if hours.get('peak_hours', {}):
                peak_hours = hours['peak_hours'].get('peak_hours', [])
                print("Peak hours:", ', '.join(f"{hour:02d}:00" for hour in peak_hours))

def main():
    """Main execution function"""
    pipeline = CertificateAnalysisPipeline()
    
    databases = ['website_data', 'normal_sites']
    all_results = {}
    
    try:
        for db_name in databases:
            print(f"\nAnalyzing {db_name}...")
            results = pipeline.run_analysis(db_name)
            pipeline.print_summary(results, db_name)
            all_results[db_name] = results
            
        print(f"\nAnalysis completed. Results saved in {pipeline.output_dir}")
        
    except Exception as e:
        print(f"Error in analysis pipeline: {str(e)}")
        logging.error(f"Pipeline error: {str(e)}")

if __name__ == "__main__":
    main()
