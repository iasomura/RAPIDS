#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Main Script for Certificate Analysis
Executes the SSL certificate analysis for the RAPIDS project.

Author: RAPIDS Project Team
Date: 2024-12-14

Usage:
    python main.py

Required packages:
- pandas>=1.3.0
- numpy>=1.20.0
- matplotlib>=3.4.0
- seaborn>=0.11.0
- sqlalchemy>=1.4.0
- psycopg2-binary>=2.9.0
"""

import os
import sys
import logging
from analyzer import CertificateAnalyzer

def setup_environment():
    """
    Set up the project environment
    
    Returns:
        str: Project root directory path
    """
    # Get the current script directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Navigate up to the RAPIDS root directory
    # From /RAPIDS/src/certificate_analysis/main.py to /RAPIDS
    project_root = os.path.abspath(os.path.join(current_dir, '..', '..'))
    
    # Add project paths to Python path
    sys.path.append(os.path.dirname(current_dir))
    sys.path.append(current_dir)
    
    return project_root

def run_analysis(project_root: str):
    """
    Execute the certificate analysis
    
    Args:
        project_root: Project root directory path
    """
    try:
        # Initialize analyzer
        analyzer = CertificateAnalyzer(project_root)
        
        # Run analysis
        results_df, stats = analyzer.analyze_certificates()
        
        # Save results
        analyzer.save_results(results_df, stats)
        
        print("Analysis completed successfully!")
        print(f"Results saved in: {analyzer.output_dirs['data']}")
        print(f"Plots saved in: {analyzer.output_dirs['plots']}")
        
        # Print summary statistics
        print("\nSummary Statistics:")
        print(f"Total sites analyzed: {stats['total_sites']}")
        print(f"Phishing sites: {stats['phishing_sites']}")
        print(f"Normal sites: {stats['normal_sites']}")
        print(f"Unique certificate issuers: {stats['unique_issuers']}")
        print(f"Average certificate chain length: {stats['avg_chain_length']:.2f}")
        print(f"Average public key size: {stats['avg_key_size']:.2f} bits")
        
    except Exception as e:
        print(f"Error occurred during analysis: {str(e)}")
        logging.error(f"Error in main execution: {str(e)}")
        raise

def main():
    """Main execution function"""
    try:
        project_root = setup_environment()
        
        # Verify the config file exists
        config_path = os.path.join(project_root, 'config', 'database.json')
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Config file not found at: {config_path}")
            
        run_analysis(project_root)
        
    except Exception as e:
        print(f"Critical error: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
