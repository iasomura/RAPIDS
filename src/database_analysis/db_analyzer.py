#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Database Analyzer Module for RAPIDS Project
Analyzes and compares phishing and normal website databases.

This script should be placed at: RAPIDS/src/database_analysis/db_analyzer.py

Outputs will be saved to: RAPIDS/reports/database_analysis/
    - CSV files with analysis results
    - PNG files with visualizations

Author: RAPIDS Project Team
Date: 2024-12-31
"""

import pandas as pd
from sqlalchemy import create_engine
from pathlib import Path
import json
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import os
import logging

class DatabaseAnalyzer:
    """Database analyzer for comparing phishing and normal websites."""
    
    def __init__(self, config_path):
        """
        Initialize the DatabaseAnalyzer.
        
        Args:
            config_path: Path to the database configuration file
        """
        # Load database configuration
        with open(config_path) as f:
            self.config = json.load(f)['database']
        
        # Set output directory
        self.base_output_dir = Path('/home/asomura/waseda/nextstep/RAPIDS/reports/database_analysis')
        
        # Setup logging
        self._setup_logging()
        
    def _setup_logging(self):
        """Configure logging settings."""
        log_dir = self.base_output_dir / 'logs'
        log_dir.mkdir(parents=True, exist_ok=True)
        
        logging.basicConfig(
            filename=log_dir / f'db_analysis_{datetime.now():%Y%m%d}.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
    def get_engine(self, db_name):
        """
        Create SQLAlchemy engine for database connection.
        
        Args:
            db_name: Name of the database ('website_data' or 'normal_sites')
            
        Returns:
            SQLAlchemy engine
        
        Raises:
            ValueError: If unknown database name is provided
        """
        if db_name == 'website_data':
            host = 'localhost'
        elif db_name == 'normal_sites':
            host = '192.168.1.92'
        else:
            raise ValueError(f"Unknown database: {db_name}")
            
        return create_engine(
            f'postgresql://{self.config["user"]}:{self.config["password"]}@{host}/{db_name}'
        )

    def get_basic_stats(self, db_name):
        """
        Get basic statistics from the specified database.
        
        Args:
            db_name: Name of the database to analyze
        """
        self.logger.info(f"Starting analysis for {db_name}")
        engine = self.get_engine(db_name)
        
        # Create output directory
        output_dir = self.base_output_dir / db_name
        output_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # Define analysis queries
            queries = {
                'row_count': """
                    SELECT COUNT(*) 
                    FROM website_data 
                    WHERE status = 7
                """,
                'null_counts': """
                    SELECT 
                        column_name, 
                        COUNT(*) - COUNT(column_name) as null_count,
                        CAST(((COUNT(*) - COUNT(column_name))::float * 100 / COUNT(*)) as numeric(10,2)) as null_percentage
                    FROM website_data, 
                         information_schema.columns
                    WHERE table_name = 'website_data'
                    AND status = 7
                    GROUP BY column_name
                    HAVING COUNT(*) - COUNT(column_name) > 0
                    ORDER BY null_percentage DESC
                """,
                'domain_tld_distribution': """
                    SELECT 
                        SUBSTRING(domain FROM '[^.]*$') as tld,
                        COUNT(*) as count,
                        CAST((COUNT(*)::float * 100 / SUM(COUNT(*)) OVER()) as numeric(10,2)) as percentage
                    FROM website_data
                    WHERE status = 7
                    GROUP BY tld
                    ORDER BY count DESC
                    LIMIT 20
                """,
                'registrar_distribution': """
                    SELECT 
                        domain_registrar,
                        COUNT(*) as count,
                        CAST((COUNT(*)::float * 100 / SUM(COUNT(*)) OVER()) as numeric(10,2)) as percentage
                    FROM website_data
                    WHERE status = 7 
                    AND domain_registrar IS NOT NULL
                    GROUP BY domain_registrar
                    ORDER BY count DESC
                    LIMIT 20
                """
            }
            
            # Execute queries and save results
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            for name, query in queries.items():
                self.logger.info(f"Executing {name} query for {db_name}")
                try:
                    df = pd.read_sql_query(query, engine)
                    
                    # Save to CSV
                    csv_path = output_dir / f'{name}_{timestamp}.csv'
                    df.to_csv(csv_path, index=False)
                    self.logger.info(f"Saved results to {csv_path}")
                    
                    # Create visualizations for distributions
                    if name in ['domain_tld_distribution', 'registrar_distribution']:
                        self._create_distribution_plot(df, name, db_name, output_dir, timestamp)
                        
                except Exception as e:
                    self.logger.error(f"Error in {name} analysis for {db_name}: {str(e)}")
            
            # Analyze SSL certificates
            self._analyze_certificates(engine, db_name, output_dir, timestamp)
            
            # Analyze temporal patterns
            self._analyze_temporal_patterns(engine, db_name, output_dir, timestamp)
            
        except Exception as e:
            self.logger.error(f"Error during analysis of {db_name}: {str(e)}")
            raise
            
    def _create_distribution_plot(self, df, name, db_name, output_dir, timestamp):
        """Create and save distribution plots."""
        if len(df) > 0:
            plt.figure(figsize=(12, 6))
            sns.barplot(data=df.head(10), x='count', y=df.columns[0])
            plt.title(f'{name} Top 10 - {db_name}')
            plt.tight_layout()
            
            plot_path = output_dir / f'{name}_{timestamp}.png'
            plt.savefig(plot_path)
            plt.close()
            self.logger.info(f"Saved plot to {plot_path}")
            
    def _analyze_certificates(self, engine, db_name, output_dir, timestamp):
        """Analyze SSL certificate distributions."""
        cert_query = """
            SELECT 
                https_certificate_issuer,
                COUNT(*) as count,
                CAST((COUNT(*)::float * 100 / SUM(COUNT(*)) OVER()) as numeric(10,2)) as percentage
            FROM website_data
            WHERE status = 7 
            AND https_certificate_issuer IS NOT NULL
            GROUP BY https_certificate_issuer
            ORDER BY count DESC
            LIMIT 20
        """
        
        self.logger.info(f"Analyzing certificates for {db_name}")
        try:
            cert_df = pd.read_sql_query(cert_query, engine)
            cert_path = output_dir / f'certificate_analysis_{timestamp}.csv'
            cert_df.to_csv(cert_path, index=False)
            self.logger.info(f"Saved certificate analysis to {cert_path}")
            
            # Create certificate issuer distribution plot
            self._create_distribution_plot(cert_df, 'certificate_issuers', db_name, output_dir, timestamp)
            
        except Exception as e:
            self.logger.error(f"Error in certificate analysis for {db_name}: {str(e)}")
            
    def _analyze_temporal_patterns(self, engine, db_name, output_dir, timestamp):
        """Analyze temporal patterns in the data."""
        temporal_query = """
            SELECT 
                DATE_TRUNC('month', last_update) as month,
                COUNT(*) as count
            FROM website_data
            WHERE status = 7 
            AND last_update IS NOT NULL
            GROUP BY month
            ORDER BY month
        """
        
        self.logger.info(f"Analyzing temporal patterns for {db_name}")
        try:
            temporal_df = pd.read_sql_query(temporal_query, engine)
            
            if len(temporal_df) > 0:
                # Create temporal plot
                plt.figure(figsize=(12, 6))
                plt.plot(temporal_df['month'], temporal_df['count'])
                plt.title(f'Monthly Website Count - {db_name}')
                plt.xticks(rotation=45)
                plt.tight_layout()
                
                temporal_plot_path = output_dir / f'temporal_analysis_{timestamp}.png'
                plt.savefig(temporal_plot_path)
                plt.close()
                self.logger.info(f"Saved temporal plot to {temporal_plot_path}")
                
                # Save temporal data
                temporal_csv_path = output_dir / f'temporal_analysis_{timestamp}.csv'
                temporal_df.to_csv(temporal_csv_path, index=False)
                self.logger.info(f"Saved temporal analysis to {temporal_csv_path}")
                
        except Exception as e:
            self.logger.error(f"Error in temporal analysis for {db_name}: {str(e)}")
            
    def analyze_all(self):
        """Analyze both phishing and normal websites databases."""
        self.logger.info("Starting complete database analysis")
        for db_name in ['website_data', 'normal_sites']:
            self.logger.info(f"\nAnalyzing {db_name}...")
            try:
                self.get_basic_stats(db_name)
                self.logger.info(f"Analysis complete for {db_name}")
            except Exception as e:
                self.logger.error(f"Failed to analyze {db_name}: {str(e)}")
        self.logger.info("Complete database analysis finished")

if __name__ == "__main__":
    # Example usage
    config_path = "/home/asomura/waseda/nextstep/RAPIDS/config/database.json"
    analyzer = DatabaseAnalyzer(config_path)
    analyzer.analyze_all()
