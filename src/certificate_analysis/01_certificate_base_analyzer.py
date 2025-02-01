# 01_certificate_base_analyzer.py
# Location: RAPIDS/src/certificate_analysis/01_certificate_base_analyzer.py

"""
Base class for certificate analysis providing database connection and basic data extraction.
This module handles:
- Database configuration
- Logging setup
- Basic data extraction
- Common utility functions
"""

from certificate_base_analyzer import CertificateBaseAnalyzer
import pandas as pd
from sqlalchemy import create_engine
from pathlib import Path
import json
import logging
from datetime import datetime
from typing import Dict, Optional

class CertificateBaseAnalyzer:
    """Base class for certificate analysis with fundamental functionality"""
    
    def __init__(self, config_path: str = '/home/asomura/waseda/nextstep/RAPIDS/config/database.json'):
        """
        Initialize the base analyzer
        
        Args:
            config_path: Path to database configuration file
        """
        self.setup_environment(config_path)
        self.setup_logging()
        
    def setup_environment(self, config_path: str) -> None:
        """
        Setup analysis environment and load configuration
        
        Args:
            config_path: Path to configuration file
        """
        # Load database configuration
        with open(config_path) as f:
            self.config = json.load(f)['database']
            
        # Setup directory structure
        self.base_dir = Path('/home/asomura/waseda/nextstep/RAPIDS')
        self.output_dir = self.base_dir / 'reports' / 'lifecycle_analysis'
        self.data_dir = self.base_dir / 'data' / 'processed'
        
        # Create necessary directories
        for dir_path in [self.output_dir, self.data_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
            
    def setup_logging(self) -> None:
        """Configure logging settings"""
        log_dir = self.base_dir / 'data' / 'logs'
        log_dir.mkdir(parents=True, exist_ok=True)
        
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        logging.basicConfig(
            filename=log_dir / f'certificate_analysis_{self.timestamp}.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def get_database_engine(self, db_name: str) -> create_engine:
        """
        Create database connection engine
        
        Args:
            db_name: Name of the database to connect
            
        Returns:
            SQLAlchemy engine
        """
        host = 'localhost' if db_name == 'website_data' else '192.168.1.92'
        return create_engine(
            f"postgresql://{self.config['user']}:{self.config['password']}@{host}/{db_name}"
        )

    def extract_certificate_data(self, db_name: str) -> pd.DataFrame:
        """
        Extract certificate data from database
        
        Args:
            db_name: Name of the database to query
            
        Returns:
            DataFrame containing certificate data
        """
        self.logger.info(f"Extracting certificate data from {db_name}")
        
        query = """
        SELECT 
            domain,
            https_certificate_issuer,
            https_certificate_expiry,
            last_update,
            domain_registrar,
            https_certificate_domain,
            https_certificate_body,
            https_certificate_public_key,
            https_certificate_signature_algorithm,
            EXTRACT(EPOCH FROM (last_update - LAG(last_update) 
                OVER (PARTITION BY domain ORDER BY last_update))) / 86400 as days_since_last_cert
        FROM website_data 
        WHERE status = 7 
        AND https_certificate_issuer IS NOT NULL
        AND last_update IS NOT NULL
        ORDER BY domain, last_update
        """
        
        try:
            engine = self.get_database_engine(db_name)
            df = pd.read_sql_query(query, engine)
            df['last_update'] = pd.to_datetime(df['last_update'])
            self.logger.info(f"Successfully extracted {len(df)} records from {db_name}")
            return df
        except Exception as e:
            self.logger.error(f"Error extracting data from {db_name}: {str(e)}")
            raise

    def save_results(self, results: Dict, db_name: str, analysis_type: str) -> None:
        """
        Save analysis results to JSON file
        
        Args:
            results: Dictionary containing analysis results
            db_name: Name of the database analyzed
            analysis_type: Type of analysis performed
        """
        output_path = self.data_dir / f'{analysis_type}_{db_name}_{self.timestamp}.json'
        try:
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            self.logger.info(f"Saved {analysis_type} results to {output_path}")
        except Exception as e:
            self.logger.error(f"Error saving results: {str(e)}")
            raise

# Example usage in Jupyter notebook:
if __name__ == "__main__":
    # Create analyzer instance
    analyzer = CertificateBaseAnalyzer()
    
    # Extract data from both databases
    for db_name in ['website_data', 'normal_sites']:
        try:
            df = analyzer.extract_certificate_data(db_name)
            print(f"\nData extracted from {db_name}:")
            print(f"Total records: {len(df)}")
            print("\nSample data:")
            print(df.head())
        except Exception as e:
            print(f"Error processing {db_name}: {str(e)}")
