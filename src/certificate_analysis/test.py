#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test script for retrieving certificate data
Place this file at: RAPIDS/src/database_analysis/test_cert_data.py
"""

from pathlib import Path
import logging
import pandas as pd
from database_handler import DatabaseHandler

def main():
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    try:
        # Initialize database handler
        config_path = Path('/home/asomura/waseda/nextstep/RAPIDS/config/database.json')
        db_handler = DatabaseHandler(config_path)

        # Test phishing site database
        logger.info("Testing phishing site database...")
        phish_cert = db_handler.get_certificate_data('website_data')
        print(f"\nPhishing site certificates found: {len(phish_cert)}")
        if not phish_cert.empty:
            print("\nSample columns:", phish_cert.columns.tolist())
            print("\nFirst record:")
            print(phish_cert.iloc[0])

        # Test normal site database
        logger.info("\nTesting normal site database...")
        normal_cert = db_handler.get_certificate_data('normal_sites')
        print(f"\nNormal site certificates found: {len(normal_cert)}")
        if not normal_cert.empty:
            print("\nSample columns:", normal_cert.columns.tolist())
            print("\nFirst record:")
            print(normal_cert.iloc[0])

        db_handler.close_connections()

    except Exception as e:
        logger.error(f"Error in test: {str(e)}", exc_info=True)
        raise

if __name__ == "__main__":
    main()
