#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Basic Data Retrieval and Analysis Program for RAPIDS Project

This script performs basic data retrieval and analysis from both databases:
- Shows table structure
- Analyzes NULL value distribution
- Retrieves sample data from key columns
- Outputs basic statistics

Place this script at: RAPIDS/src/database_analysis/02_basic_data_retrieval.py

Output: 
- Console output for immediate viewing
- CSV files with detailed analysis in RAPIDS/reports/data_analysis/
- Log file in RAPIDS/data/logs/
"""

import json
import logging
from pathlib import Path
from datetime import datetime
import pandas as pd
from sqlalchemy import create_engine, text
import os

class DataRetriever:
    """Handles basic data retrieval and analysis from databases"""
    
    def __init__(self, config_path: Path):
        """
        Initialize DataRetriever
        
        Args:
            config_path: Path to database configuration file
        """
        self.config_path = config_path
        self.setup_paths()
        self.setup_logging()
        self.load_config()
        
    def setup_paths(self):
        """Set up necessary directory paths"""
        self.project_root = Path('/home/asomura/waseda/nextstep/RAPIDS')
        self.log_dir = self.project_root / 'data' / 'logs'
        self.report_dir = self.project_root / 'reports' / 'data_analysis'
        
        # Create directories if they don't exist
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        
    def setup_logging(self):
        """Configure logging settings"""
        log_file = self.log_dir / f'data_retrieval_{datetime.now():%Y%m%d}.log'
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def load_config(self):
        """Load database configuration"""
        try:
            with open(self.config_path) as f:
                self.config = json.load(f)['database']
        except Exception as e:
            self.logger.error(f"Error loading config: {str(e)}")
            raise
            
    def get_engine(self, db_name: str):
        """
        Create database engine for specified database
        
        Args:
            db_name: Name of the database to connect to
        """
        host = 'localhost' if db_name == 'website_data' else '192.168.1.92'
        return create_engine(
            f"postgresql://{self.config['user']}:{self.config['password']}@{host}/{db_name}"
        )
        
    def analyze_table_structure(self, db_name: str):
        """
        Analyze table structure and output column information
        
        Args:
            db_name: Name of the database to analyze
        """
        self.logger.info(f"Analyzing table structure for {db_name}")
        engine = self.get_engine(db_name)
        
        try:
            # Get column information
            query = """
                SELECT 
                    column_name,
                    data_type,
                    character_maximum_length,
                    is_nullable
                FROM 
                    information_schema.columns
                WHERE 
                    table_name = 'website_data'
                ORDER BY 
                    ordinal_position
            """
            
            df = pd.read_sql_query(query, engine)
            
            # Save to CSV
            output_file = self.report_dir / f'{db_name}_structure_{datetime.now():%Y%m%d}.csv'
            df.to_csv(output_file, index=False)
            self.logger.info(f"Table structure saved to {output_file}")
            
            return df
            
        except Exception as e:
            self.logger.error(f"Error analyzing table structure for {db_name}: {str(e)}")
            return pd.DataFrame()
            
    def analyze_null_distribution(self, db_name: str):
        """
        Analyze NULL value distribution in the database
        
        Args:
            db_name: Name of the database to analyze
        """
        self.logger.info(f"Analyzing NULL value distribution for {db_name}")
        engine = self.get_engine(db_name)
        
        try:
            # Get column names first
            columns_query = """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = 'website_data'
            """
            
            columns_df = pd.read_sql_query(columns_query, engine)
            
            # Initialize results
            results = []
            
            # Check each column for NULL values
            for column in columns_df['column_name']:
                null_query = f"""
                    SELECT 
                        '{column}' as column_name,
                        COUNT(*) as total_rows,
                        COUNT(*) - COUNT({column}) as null_count,
                        CAST(((COUNT(*) - COUNT({column}))::float * 100 / COUNT(*)) as numeric(10,2)) as null_percentage
                    FROM website_data
                    WHERE status = 7
                    HAVING COUNT(*) - COUNT({column}) > 0
                """
                
                try:
                    result = pd.read_sql_query(null_query, engine)
                    if not result.empty:
                        results.append(result)
                except Exception as e:
                    self.logger.warning(f"Error analyzing column {column}: {str(e)}")
                    continue
            
            # Combine results
            if results:
                df = pd.concat(results, ignore_index=True)
                df = df.sort_values('null_percentage', ascending=False)
            else:
                df = pd.DataFrame(columns=['column_name', 'total_rows', 'null_count', 'null_percentage'])
                
            # Save to CSV
            output_file = self.report_dir / f'{db_name}_null_analysis_{datetime.now():%Y%m%d}.csv'
            df.to_csv(output_file, index=False)
            self.logger.info(f"NULL analysis saved to {output_file}")
            
            return df
            
            df = pd.read_sql_query(query, engine)
            
            # Save to CSV
            output_file = self.report_dir / f'{db_name}_null_analysis_{datetime.now():%Y%m%d}.csv'
            df.to_csv(output_file, index=False)
            self.logger.info(f"NULL analysis saved to {output_file}")
            
            return df
            
        except Exception as e:
            self.logger.error(f"Error analyzing NULL distribution for {db_name}: {str(e)}")
            return pd.DataFrame()
            
    def get_sample_data(self, db_name: str):
        """
        Retrieve sample data from key columns
        
        Args:
            db_name: Name of the database to analyze
        """
        self.logger.info(f"Retrieving sample data from {db_name}")
        engine = self.get_engine(db_name)
        
        try:
            # Select key columns for analysis
            query = """
                SELECT 
                    domain,
                    domain_registrar,
                    https_certificate_issuer,
                    https_certificate_domain,
                    domain_status,
                    last_update
                FROM 
                    website_data
                WHERE 
                    status = 7
                LIMIT 100
            """
            
            df = pd.read_sql_query(query, engine)
            
            # Save to CSV
            output_file = self.report_dir / f'{db_name}_sample_data_{datetime.now():%Y%m%d}.csv'
            df.to_csv(output_file, index=False)
            self.logger.info(f"Sample data saved to {output_file}")
            
            return df
            
        except Exception as e:
            self.logger.error(f"Error retrieving sample data from {db_name}: {str(e)}")
            return pd.DataFrame()
            
    def run_analysis(self):
        """Run complete analysis for both databases"""
        databases = ['website_data', 'normal_sites']
        
        for db_name in databases:
            self.logger.info(f"\nAnalyzing {db_name}...")
            
            # Analyze table structure
            structure_df = self.analyze_table_structure(db_name)
            if not structure_df.empty:
                self.logger.info(f"Found {len(structure_df)} columns in {db_name}")
                
            # Analyze NULL distribution
            null_df = self.analyze_null_distribution(db_name)
            if not null_df.empty:
                self.logger.info(f"Found {len(null_df)} columns with NULL values in {db_name}")
                
            # Get sample data
            sample_df = self.get_sample_data(db_name)
            if not sample_df.empty:
                self.logger.info(f"Retrieved {len(sample_df)} sample records from {db_name}")
                
        self.logger.info("\nAnalysis complete")

def main():
    """Main function to run data retrieval and analysis"""
    try:
        config_path = Path('/home/asomura/waseda/nextstep/RAPIDS/config/database.json')
        retriever = DataRetriever(config_path)
        retriever.run_analysis()
        
    except Exception as e:
        logging.error(f"Error in main process: {str(e)}")
        raise

if __name__ == "__main__":
    main()
