#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Database Connection Test Program for RAPIDS Project

This script performs basic connection tests to both the phishing and normal website databases.
It verifies the connection and retrieves basic record counts.

Place this script at: RAPIDS/src/database_analysis/01_database_connection_test.py

Output: Prints connection status and basic record counts to console
        Logs detailed information to: RAPIDS/data/logs/db_connection_test_YYYYMMDD.log
"""

import json
import logging
from pathlib import Path
from datetime import datetime
from sqlalchemy import create_engine, text

def setup_logging(log_dir: Path) -> logging.Logger:
    """
    Set up logging configuration
    
    Args:
        log_dir: Directory path for log files
        
    Returns:
        Configured logger instance
    """
    log_dir.mkdir(parents=True, exist_ok=True)
    
    log_file = log_dir / f'db_connection_test_{datetime.now():%Y%m%d}.log'
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
    return logging.getLogger(__name__)

def load_config(config_path: Path) -> dict:
    """
    Load database configuration from JSON file
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Dictionary containing database configuration
        
    Raises:
        FileNotFoundError: If config file does not exist
        json.JSONDecodeError: If config file is not valid JSON
    """
    try:
        with open(config_path) as f:
            return json.load(f)['database']
    except FileNotFoundError:
        raise FileNotFoundError(f"Configuration file not found at {config_path}")
    except json.JSONDecodeError:
        raise ValueError(f"Invalid JSON in configuration file {config_path}")

def test_database_connection(db_config: dict, db_name: str, host: str, logger: logging.Logger) -> bool:
    """
    Test connection to specified database and get record count
    
    Args:
        db_config: Database configuration dictionary
        db_name: Name of the database to test
        host: Database host address
        logger: Logger instance
        
    Returns:
        Boolean indicating successful connection and query
    """
    try:
        # Create database URL
        db_url = f"postgresql://{db_config['user']}:{db_config['password']}@{host}/{db_name}"
        engine = create_engine(db_url)
        
        # Test connection
        with engine.connect() as conn:
            # Test basic connection
            logger.info(f"Testing connection to {db_name}...")
            result = conn.execute(text("SELECT 1")).fetchone()
            if result[0] == 1:
                logger.info(f"Successfully connected to {db_name}")
            
            # Get record count
            logger.info(f"Counting records in {db_name}...")
            result = conn.execute(text(
                "SELECT COUNT(*) FROM website_data WHERE status = 7"
            )).fetchone()
            count = result[0]
            logger.info(f"Found {count} records with status=7 in {db_name}")
            
        return True
        
    except Exception as e:
        logger.error(f"Error connecting to {db_name}: {str(e)}")
        return False

def main():
    """Main function to test database connections"""
    # Set up paths
    project_root = Path('/home/asomura/waseda/nextstep/RAPIDS')
    config_path = project_root / 'config' / 'database.json'
    log_dir = project_root / 'data' / 'logs'
    
    # Set up logging
    logger = setup_logging(log_dir)
    logger.info("Starting database connection tests")
    
    try:
        # Load configuration
        logger.info(f"Loading configuration from {config_path}")
        db_config = load_config(config_path)
        
        # Test connections
        databases = {
            'website_data': 'localhost',
            'normal_sites': '192.168.1.92'
        }
        
        success = True
        for db_name, host in databases.items():
            if not test_database_connection(db_config, db_name, host, logger):
                success = False
                
        # Final status
        if success:
            logger.info("All database connection tests completed successfully")
        else:
            logger.error("Some database connection tests failed")
            
    except Exception as e:
        logger.error(f"Error in main process: {str(e)}")
        raise

if __name__ == "__main__":
    main()
