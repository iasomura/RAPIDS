#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Database Handler for RAPIDS Project

This module provides a comprehensive interface for database operations in the RAPIDS project.
Place this file at: RAPIDS/src/database_analysis/database_handler.py

Features:
- Unified database connection management
- Data retrieval for both phishing and normal sites
- Query optimization
- Error handling and logging
"""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Any, Union

import pandas as pd
from sqlalchemy import create_engine, text, Engine
from sqlalchemy.exc import SQLAlchemyError

class DatabaseHandler:
    """Handles all database operations for the RAPIDS project."""

    def __init__(self, config_path: Path):
        """
        Initialize DatabaseHandler with configuration.

        Args:
            config_path: Path to database configuration file
        """
        self.config_path = config_path
        self.setup_paths()
        self.setup_logging()
        self.load_config()
        self.engines: Dict[str, Engine] = {}

    def setup_paths(self) -> None:
        """Set up necessary directory paths."""
        self.project_root = Path('/home/asomura/waseda/nextstep/RAPIDS')
        self.log_dir = self.project_root / 'data' / 'logs'
        self.output_dir = self.project_root / 'data' / 'processed'

        # Create directories if they don't exist
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def setup_logging(self) -> None:
        """Configure logging settings."""
        log_file = self.log_dir / f'database_handler_{datetime.now():%Y%m%d}.log'
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def load_config(self) -> None:
        """Load database configuration from JSON file."""
        try:
            with open(self.config_path) as f:
                self.config = json.load(f)['database']
            self.logger.info("Database configuration loaded successfully")
        except Exception as e:
            self.logger.error(f"Error loading config: {str(e)}")
            raise

    def get_engine(self, db_name: str) -> Engine:
        """
        Get SQLAlchemy engine for specified database.

        Args:
            db_name: Name of the database to connect to

        Returns:
            SQLAlchemy Engine instance
        """
        if db_name not in self.engines:
            host = 'localhost' if db_name == 'website_data' else '192.168.1.92'
            db_url = f"postgresql://{self.config['user']}:{self.config['password']}@{host}/{db_name}"
            self.engines[db_name] = create_engine(db_url)
            self.logger.info(f"Created new engine for {db_name}")
        return self.engines[db_name]

    def get_active_records(self, db_name: str, limit: Optional[int] = None) -> pd.DataFrame:
        """
        Retrieve active records (status=7) from specified database.

        Args:
            db_name: Name of the database to query
            limit: Optional limit on number of records to retrieve

        Returns:
            DataFrame containing the records
        """
        try:
            engine = self.get_engine(db_name)
            query = """
                SELECT *
                FROM website_data
                WHERE status = 7
                {}
            """.format(f"LIMIT {limit}" if limit else "")

            df = pd.read_sql_query(query, engine)
            self.logger.info(f"Retrieved {len(df)} records from {db_name}")
            return df

        except SQLAlchemyError as e:
            self.logger.error(f"Database error in get_active_records: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error in get_active_records: {str(e)}")
            raise

def get_certificate_data(self, db_name: str) -> pd.DataFrame:
    """
    Retrieve certificate-related data from specified database.

    Args:
        db_name: Name of the database to query

    Returns:
        DataFrame containing certificate data
    """
    try:
        engine = self.get_engine(db_name)
        query = """
            SELECT 
                id,
                domain,
                https_certificate_body,
                https_certificate_issuer,
                https_certificate_domain,
                https_certificate_expiry,
                https_certificate_public_key,
                https_certificate_signature_algorithm,
                https_certificate_extensions
            FROM website_data
            WHERE status = 7
            AND https_certificate_body IS NOT NULL
        """
        
        df = pd.read_sql_query(query, engine)
        self.logger.info(f"Retrieved {len(df)} certificate records from {db_name}")
        
        # Log sample of data for verification
        if not df.empty:
            self.logger.debug(f"Sample certificate data from {db_name}:")
            self.logger.debug(df.iloc[0].to_dict())
        
        return df

    except SQLAlchemyError as e:
        self.logger.error(f"Database error in get_certificate_data for {db_name}: {str(e)}")
        raise
    except Exception as e:
        self.logger.error(f"Unexpected error in get_certificate_data for {db_name}: {str(e)}")
        raise

        
    def get_whois_data(self, db_name: str) -> pd.DataFrame:
        """
        Retrieve WHOIS-related data from specified database.

        Returns:
            DataFrame containing WHOIS data
        """
        try:
            engine = self.get_engine(db_name)
            query = """
                SELECT 
                    id,
                    domain,
                    whois_date,
                    whois_domain,
                    registrant_name,
                    admin_name,
                    tech_name,
                    domain_registrar
                FROM website_data
                WHERE status = 7
                AND whois_domain IS NOT NULL
            """
            
            df = pd.read_sql_query(query, engine)
            self.logger.info(f"Retrieved WHOIS data for {len(df)} records from {db_name}")
            return df

        except SQLAlchemyError as e:
            self.logger.error(f"Database error in get_whois_data: {str(e)}")
            raise

    def get_domain_features(self, db_name: str) -> pd.DataFrame:
        """
        Retrieve and calculate domain-related features.

        Returns:
            DataFrame containing domain features
        """
        try:
            engine = self.get_engine(db_name)
            query = """
                SELECT 
                    id,
                    domain,
                    domain_status,
                    ip_address,
                    ip_organization,
                    ip_location,
                    hosting_provider
                FROM website_data
                WHERE status = 7
            """
            
            df = pd.read_sql_query(query, engine)
            self.logger.info(f"Retrieved domain features for {len(df)} records from {db_name}")
            return df

        except SQLAlchemyError as e:
            self.logger.error(f"Database error in get_domain_features: {str(e)}")
            raise

    def execute_query(self, db_name: str, query: str, params: Optional[Dict] = None) -> pd.DataFrame:
        """
        Execute a custom SQL query.

        Args:
            db_name: Name of the database to query
            query: SQL query string
            params: Optional parameters for the query

        Returns:
            DataFrame containing query results
        """
        try:
            engine = self.get_engine(db_name)
            df = pd.read_sql_query(query, engine, params=params)
            self.logger.info(f"Custom query executed successfully on {db_name}")
            return df

        except SQLAlchemyError as e:
            self.logger.error(f"Database error in execute_query: {str(e)}")
            raise

    def get_database_stats(self, db_name: str) -> Dict[str, Any]:
        """
        Get basic statistics about the database.

        Returns:
            Dictionary containing database statistics
        """
        try:
            engine = self.get_engine(db_name)
            stats = {}

            # Get total record count
            query_total = "SELECT COUNT(*) FROM website_data WHERE status = 7"
            stats['total_records'] = engine.execute(text(query_total)).scalar()

            # Get record count by certificate issuer
            query_cert = """
                SELECT https_certificate_issuer, COUNT(*) as count
                FROM website_data
                WHERE status = 7 AND https_certificate_issuer IS NOT NULL
                GROUP BY https_certificate_issuer
                ORDER BY count DESC
                LIMIT 5
            """
            stats['certificate_issuers'] = pd.read_sql_query(query_cert, engine).to_dict('records')

            # Get record count by registrar
            query_registrar = """
                SELECT domain_registrar, COUNT(*) as count
                FROM website_data
                WHERE status = 7 AND domain_registrar IS NOT NULL
                GROUP BY domain_registrar
                ORDER BY count DESC
                LIMIT 5
            """
            stats['registrars'] = pd.read_sql_query(query_registrar, engine).to_dict('records')

            self.logger.info(f"Retrieved database statistics for {db_name}")
            return stats

        except SQLAlchemyError as e:
            self.logger.error(f"Database error in get_database_stats: {str(e)}")
            raise

    def close_connections(self) -> None:
        """Close all database connections."""
        for db_name, engine in self.engines.items():
            engine.dispose()
            self.logger.info(f"Closed connection to {db_name}")
        self.engines.clear()

def main():
    """Main function for testing the DatabaseHandler."""
    try:
        config_path = Path('/home/asomura/waseda/nextstep/RAPIDS/config/database.json')
        handler = DatabaseHandler(config_path)

        # Test basic functionality
        for db_name in ['website_data', 'normal_sites']:
            print(f"\nTesting {db_name}:")
            
            # Get and print basic stats
            stats = handler.get_database_stats(db_name)
            print(f"Total records: {stats['total_records']}")
            
            # Get sample certificate data
            cert_data = handler.get_certificate_data(db_name)
            print(f"Certificate records: {len(cert_data)}")
            
            # Get sample WHOIS data
            whois_data = handler.get_whois_data(db_name)
            print(f"WHOIS records: {len(whois_data)}")

        handler.close_connections()

    except Exception as e:
        logging.error(f"Error in main process: {str(e)}")
        raise

if __name__ == "__main__":
    main()
