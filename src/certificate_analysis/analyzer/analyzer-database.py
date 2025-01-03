#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Database Handler Module
Manages database connections and data retrieval for certificate analysis.
"""

import os
import json
import logging
import pandas as pd
from sqlalchemy import create_engine, text

class DatabaseHandler:
    """Handles database operations for certificate analysis"""
    
    def __init__(self, project_root: str):
        """
        Initialize database handler
        
        Args:
            project_root: Project root directory path
        """
        self.project_root = project_root
        self.logger = logging.getLogger(__name__)
        self.connect_databases()

    def connect_databases(self):
        """Establish database connections using SQLAlchemy"""
        try:
            # Load database configuration
            config_path = os.path.join(self.project_root, 'config', 'database.json')
            with open(config_path, 'r') as f:
                db_config = json.load(f)

            # Create connection strings
            phish_conn_str = f"postgresql://{db_config['database']['user']}:{db_config['database']['password']}@{db_config['database']['host']}/website_data"
            normal_conn_str = "postgresql://postgres:asomura@192.168.1.92/normal_sites"

            # Create engines with error handling
            self.phish_engine = create_engine(phish_conn_str)
            self.normal_engine = create_engine(normal_conn_str)
            
            # Test connections
            with self.phish_engine.connect() as connection:
                connection.execute(text("SELECT 1")).fetchone()
                
            with self.normal_engine.connect() as connection:
                connection.execute(text("SELECT 1")).fetchone()
                
            self.logger.info("Database connections established successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to connect to databases: {str(e)}")
            raise

    def get_data(self, site_type: str) -> pd.DataFrame:
        """
        Retrieve and process data from appropriate database
        
        Args:
            site_type: Type of sites ('phishing' or 'normal')
            
        Returns:
            Processed DataFrame
        """
        engine = self.phish_engine if site_type == 'phishing' else self.normal_engine
        
        query = """
        SELECT 
            domain_registrar,
            https_certificate_issuer,
            https_certificate_all,
            https_certificate_expiry,
            domain,
            whois_domain,
            https_certificate_domain,
            domain_status,
            whois_date,
            https_certificate_date
        FROM 
            website_data
        WHERE 
            status = 7
        """
        
        try:
            df = pd.read_sql_query(query, engine)
            df['site_type'] = site_type
            
            return df
            
        except Exception as e:
            self.logger.error(f"Error retrieving data for {site_type} sites: {str(e)}")
            raise