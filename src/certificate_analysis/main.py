#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Main Script for Certificate Analysis
Executes the SSL certificate analysis for the RAPIDS project.
This script should be placed at: RAPIDS/src/certificate_analysis/main.py

Author: RAPIDS Project Team
Date: 2024-01-05

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
import json
from datetime import datetime
from pathlib import Path

def setup_logging(project_root: str) -> logging.Logger:
    """
    Set up logging configuration
    
    Args:
        project_root: Project root directory path
        
    Returns:
        logging.Logger: Configured logger instance
    """
    # Create logs directory if it doesn't exist
    log_dir = os.path.join(project_root, 'data', 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    # Configure logging
    log_file = os.path.join(log_dir, f'cert_analysis_{datetime.now():%Y%m%d}.log')
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    return logging.getLogger(__name__)

def setup_environment() -> str:
    """
    Set up the project environment
    
    Returns:
        str: Project root directory path
    """
    # Get the current script directory (RAPIDS/src/certificate_analysis)
    current_dir = Path(__file__).resolve().parent
    
    # Navigate up to the RAPIDS root directory
    project_root = current_dir.parent.parent
    
    # Add the src directory to Python path for package imports
    src_dir = project_root / 'src'
    if src_dir not in sys.path:
        sys.path.insert(0, str(src_dir))
    
    return str(project_root)

def verify_config(project_root: str, logger: logging.Logger) -> dict:
    """
    Verify and load configuration files
    
    Args:
        project_root: Project root directory path
        logger: Logger instance
        
    Returns:
        dict: Loaded configuration
        
    Raises:
        FileNotFoundError: If config file is missing
        json.JSONDecodeError: If config file is invalid
    """
    config_path = os.path.join(project_root, 'config', 'database.json')
    
    if not os.path.exists(config_path):
        logger.error(f"Config file not found: {config_path}")
        raise FileNotFoundError(f"Config file not found at: {config_path}")
    
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        logger.info("Configuration loaded successfully")
        return config
    except json.JSONDecodeError as e:
        logger.error(f"Invalid config file: {str(e)}")
        raise

def run_analysis(project_root: str, logger: logging.Logger):
    """
    Execute the certificate analysis
    
    Args:
        project_root: Project root directory path
        logger: Logger instance
    """
    try:
        # Import the analyzer here to ensure the environment is set up first
        from certificate_analysis.analyzer import CertificateAnalyzer
        
        # Initialize analyzer
        analyzer = CertificateAnalyzer(project_root)
        logger.info("Certificate Analyzer initialized")
        
        # Run analysis
        logger.info("Starting certificate analysis")
        results_df, stats = analyzer.analyze_certificates()
        
        # Save results
        analyzer.save_results(results_df, stats)
        logger.info("Analysis results saved successfully")
        
        # Print summary statistics
        print("\nAnalysis Summary:")
        print("-" * 50)
        print(f"Total sites analyzed: {stats['total_sites']}")
        print(f"├── Phishing sites: {stats['phishing_sites']}")
        print(f"└── Normal sites: {stats['normal_sites']}")
        print("\nCertificate Statistics:")
        print("-" * 50)
        print(f"Unique certificate issuers: {stats['unique_issuers']}")
        print(f"Average certificate chain length: {stats['avg_chain_length']:.2f}")
        print(f"Average public key size: {stats['avg_key_size']:.2f} bits")
        print("\nOutput Locations:")
        print("-" * 50)
        print(f"Results: {analyzer.output_dirs['data']}")
        print(f"Plots: {analyzer.output_dirs['plots']}")
        
    except ImportError as e:
        logger.error(f"Failed to import analyzer package: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}")
        raise

def main():
    """Main execution function"""
    try:
        # Setup environment
        project_root = setup_environment()
        
        # Setup logging
        logger = setup_logging(project_root)
        logger.info("Starting certificate analysis process")
        
        # Verify configuration
        config = verify_config(project_root, logger)
        
        # Run analysis
        run_analysis(project_root, logger)
        
        logger.info("Certificate analysis completed successfully")
        return 0
        
    except Exception as e:
        print(f"Critical error: {str(e)}")
        if 'logger' in locals():
            logger.error(f"Critical error: {str(e)}")
        return 1

if __name__ == "__main__":
    exit(main())