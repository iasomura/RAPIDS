#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Database Registrar Updater
Location: RAPIDS/src/data/registrar_extraction/03_update_registrars.py

This script updates the domain_registrar field in the database using validated registrar information.
Features:
- Updates only high-confidence matches
- Detailed logging of all changes
- Transaction-based updates with rollback capability
- Progress tracking and statistics

Input: validated_registrars_{timestamp}.json from step 2
Output: update_log_{timestamp}.log
"""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple
import psycopg2
from psycopg2.extras import execute_batch

class DatabaseUpdater:
    """Updates database with validated registrar information."""
    
    def __init__(self, config_path: str):
        """Initialize the updater with database configuration."""
        self.setup_environment(config_path)
        self.setup_logging()
        
    def setup_environment(self, config_path: str):
        """Setup working environment and load configuration."""
        # Load database configuration
        with open(config_path) as f:
            self.config = json.load(f)['database']
            
        # Setup directories
        self.base_dir = Path('/home/asomura/waseda/nextstep/RAPIDS')
        self.input_dir = self.base_dir / 'data' / 'processed' / 'registrar_validation'
        self.output_dir = self.base_dir / 'data' / 'processed' / 'registrar_updates'
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def setup_logging(self):
        """Configure logging settings."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_file = self.output_dir / f'update_log_{timestamp}.log'
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def get_database_connection(self) -> psycopg2.extensions.connection:
        """Create database connection."""
        return psycopg2.connect(
            host='localhost',
            database='normal_sites',
            user=self.config['user'],
            password=self.config['password']
        )
        
    def get_latest_validation_file(self) -> Path:
        """Get the most recent validation results file."""
        validation_files = list(self.input_dir.glob('validated_registrars_*.json'))
        if not validation_files:
            raise FileNotFoundError("No validation files found")
        return max(validation_files, key=lambda x: x.stat().st_mtime)
        
    def prepare_updates(self, validated_data: List[Dict]) -> List[Dict]:
        """Prepare update data from validation results."""
        updates = []
        for item in validated_data:
            if item['confidence_score'] >= 0.9:  # Only high confidence matches
                updates.append({
                    'id': item['id'],
                    'domain': item['domain'],
                    'registrar': item['matched_registrar'],
                    'confidence': item['confidence_score']
                })
        return updates
        
    def update_database(self, updates: List[Dict]) -> Tuple[int, List[Dict]]:
        """Update database with validated registrar information."""
        conn = self.get_database_connection()
        update_count = 0
        failed_updates = []
        
        try:
            with conn:
                with conn.cursor() as cur:
                    # Prepare update statement
                    update_query = """
                    UPDATE website_data 
                    SET 
                        domain_registrar = %s,
                        last_update = NOW()
                    WHERE id = %s 
                    AND status = 7 
                    AND (domain_registrar IS NULL OR domain_registrar = '')
                    """
                    
                    # Process updates in batches
                    batch_size = 100
                    for i in range(0, len(updates), batch_size):
                        batch = updates[i:i + batch_size]
                        update_data = [
                            (item['registrar'], item['id']) 
                            for item in batch
                        ]
                        
                        try:
                            execute_batch(cur, update_query, update_data)
                            update_count += len(batch)
                            
                            # Log successful updates
                            for item in batch:
                                self.logger.info(
                                    f"Updated {item['domain']} (ID: {item['id']}) "
                                    f"with registrar: {item['registrar']}"
                                )
                                
                        except Exception as e:
                            self.logger.error(f"Failed to update batch: {str(e)}")
                            failed_updates.extend(batch)
                            
        except Exception as e:
            self.logger.error(f"Database connection error: {str(e)}")
            raise
            
        finally:
            conn.close()
            
        return update_count, failed_updates
        
    def process_updates(self):
        """Process and apply all updates."""
        try:
            # Load validation results
            validation_file = self.get_latest_validation_file()
            self.logger.info(f"Processing validation file: {validation_file}")
            
            with open(validation_file, 'r', encoding='utf-8') as f:
                validated_data = json.load(f)
                
            # Prepare updates
            updates = self.prepare_updates(validated_data)
            self.logger.info(f"Prepared {len(updates)} updates from {len(validated_data)} records")
            
            if not updates:
                self.logger.info("No high-confidence updates to process")
                return
                
            # Apply updates
            update_count, failed_updates = self.update_database(updates)
            
            # Log results
            self.logger.info("\nUpdate Statistics:")
            self.logger.info(f"Total records processed: {len(validated_data)}")
            self.logger.info(f"Updates attempted: {len(updates)}")
            self.logger.info(f"Successful updates: {update_count}")
            self.logger.info(f"Failed updates: {len(failed_updates)}")
            
            if failed_updates:
                failed_file = self.output_dir / f'failed_updates_{datetime.now():%Y%m%d_%H%M%S}.json'
                with open(failed_file, 'w', encoding='utf-8') as f:
                    json.dump(failed_updates, f, ensure_ascii=False, indent=2)
                self.logger.info(f"Failed updates saved to: {failed_file}")
                
        except Exception as e:
            self.logger.error(f"Error during update process: {str(e)}")
            raise

def main():
    config_path = "/home/asomura/waseda/nextstep/RAPIDS/config/database.json"
    updater = DatabaseUpdater(config_path)
    updater.process_updates()

if __name__ == "__main__":
    main()
