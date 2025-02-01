#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Certificate Analyzer Script for RAPIDS Project
Place this file at: RAPIDS/src/certificate_analysis/certificate_analyzer.py
"""

import sys
from pathlib import Path
import logging

# Add the parent directory to the Python path
project_root = Path(__file__).resolve().parents[2]
sys.path.append(str(project_root / 'src'))

from database_analysis.database_handler import DatabaseHandler
from certificate_analysis.certificate_parser import CertificateParser

def setup_logging():
    """Configure logging settings."""
    log_dir = project_root / 'data' / 'logs'
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f'certificate_analyzer_{datetime.now():%Y%m%d}.log'
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

def main():
    """Main function for certificate analysis."""
    logger = setup_logging()
    
    try:
        config_path = project_root / 'config' / 'database.json'
        logger.info(f"Using config from: {config_path}")
        
        # Initialize handlers
        db_handler = DatabaseHandler(config_path)
        cert_parser = CertificateParser(config_path)

        logger.info("Retrieving certificate data from databases...")
        
        # Get certificate data from both databases
        phish_cert_data = db_handler.get_certificate_data('website_data')
        logger.info(f"Retrieved {len(phish_cert_data)} records from phishing database")
        
        normal_cert_data = db_handler.get_certificate_data('normal_sites')
        logger.info(f"Retrieved {len(normal_cert_data)} records from normal sites database")

        # Check if we have data
        if phish_cert_data.empty and normal_cert_data.empty:
            logger.error("No certificate data retrieved from either database")
            return

        # Process phishing certificates
        logger.info("Analyzing phishing site certificates...")
        phish_results = None
        if not phish_cert_data.empty:
            phish_results = cert_parser.analyze_certificates(phish_cert_data)
            if phish_results is not None and not phish_results.empty:
                phish_results['is_phishing'] = True
                logger.info(f"Successfully analyzed {len(phish_results)} phishing certificates")
            else:
                logger.warning("No results obtained from phishing certificate analysis")

        # Process normal certificates
        logger.info("Analyzing normal site certificates...")
        normal_results = None
        if not normal_cert_data.empty:
            normal_results = cert_parser.analyze_certificates(normal_cert_data)
            if normal_results is not None and not normal_results.empty:
                normal_results['is_phishing'] = False
                logger.info(f"Successfully analyzed {len(normal_results)} normal certificates")
            else:
                logger.warning("No results obtained from normal certificate analysis")

        # Print analysis results
        print("\n=== Certificate Analysis Results ===")
        total_analyzed = 0
        if phish_results is not None:
            total_analyzed += len(phish_results)
        if normal_results is not None:
            total_analyzed += len(normal_results)
        print(f"Total certificates analyzed: {total_analyzed}")
        print(f"Phishing sites: {len(phish_results) if phish_results is not None else 0}")
        print(f"Normal sites: {len(normal_results) if normal_results is not None else 0}")

        print("\n=== Security Score Comparison ===")
        print("Phishing sites:")
        if phish_results is not None and not phish_results.empty and 'security_score' in phish_results.columns:
            print(f"  Mean: {phish_results['security_score'].mean():.3f}")
            print(f"  Median: {phish_results['security_score'].median():.3f}")
            print(f"  Std Dev: {phish_results['security_score'].std():.3f}")
        else:
            print("  No security score data available")

        print("\nNormal sites:")
        if normal_results is not None and not normal_results.empty and 'security_score' in normal_results.columns:
            print(f"  Mean: {normal_results['security_score'].mean():.3f}")
            print(f"  Median: {normal_results['security_score'].median():.3f}")
            print(f"  Std Dev: {normal_results['security_score'].std():.3f}")
        else:
            print("  No security score data available")

        # Save combined results if available
        if phish_results is not None or normal_results is not None:
            results_list = []
            if phish_results is not None and not phish_results.empty:
                results_list.append(phish_results)
            if normal_results is not None and not normal_results.empty:
                results_list.append(normal_results)
            
            if results_list:
                all_results = pd.concat(results_list, ignore_index=True)
                
                # Save results
                output_dir = project_root / 'data' / 'processed' / 'certificates'
                output_dir.mkdir(parents=True, exist_ok=True)
                
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_file = output_dir / f'certificate_analysis_combined_{timestamp}.csv'
                all_results.to_csv(output_file, index=False)
                logger.info(f"Combined results saved to: {output_file}")

        db_handler.close_connections()
        logger.info("Analysis completed successfully")

    except Exception as e:
        logger.error(f"Error in analysis: {str(e)}", exc_info=True)
        raise

if __name__ == "__main__":
    from datetime import datetime
    import pandas as pd
    main()
