#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Improved WHOIS Registrar Information Extractor
Location: RAPIDS/src/data/registrar_extraction/01_extract_registrars_improved.py

This script provides improved extraction of registrar information from WHOIS data,
with better handling of different formats and cleaning of extracted data.

Output files will be saved to: RAPIDS/data/processed/registrar_extraction/
- extracted_registrars_{timestamp}.json
- extraction_log_{timestamp}.log
"""

import pandas as pd
from sqlalchemy import create_engine
import json
from pathlib import Path
import logging
from datetime import datetime
import re
import unicodedata

class ImprovedRegistrarExtractor:
    """Enhanced registrar information extractor with improved pattern matching."""
    
    def __init__(self, config_path: str):
        """Initialize the extractor with database configuration."""
        self.setup_environment(config_path)
        self.setup_logging()
        self.setup_patterns()
        
    def setup_environment(self, config_path: str):
        """Setup working environment and load configuration."""
        with open(config_path) as f:
            self.config = json.load(f)['database']
            
        self.base_dir = Path('/home/asomura/waseda/nextstep/RAPIDS')
        self.output_dir = self.base_dir / 'data' / 'processed' / 'registrar_extraction'
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def setup_logging(self):
        """Configure logging settings."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_file = self.output_dir / f'extraction_log_{timestamp}.log'
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def setup_patterns(self):
        """Setup improved regex patterns for WHOIS format matching."""
        self.patterns = {
            'registrar': [
                # English patterns
                r'Registrar:\s*([^(\n]+?)(?:\s*\(|$)',
                r'Registrar Name:\s*([^(\n]+?)(?:\s*\(|$)',
                r'Registration Service Provider:\s*([^(\n]+?)(?:\s*\(|$)',
                # Korean patterns
                r'등록대행자:\s*([^(\n]+?)(?:\s*\(|$)',
                r'등록기관:\s*([^(\n]+?)(?:\s*\(|$)',
                # Japanese patterns
                r'レジストラ:\s*([^(\n]+?)(?:\s*\(|$)',
                # Chinese patterns
                r'注册服务机构:\s*([^(\n]+?)(?:\s*\(|$)',
                # Additional generic patterns
                r'registrar:\s*([^(\n]+?)(?:\s*\(|$)',
            ],
            'exclude': [
                r'Name servers:.*',
                r'Keys:.*',
                r'DNS:.*',
                r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                r'[\w\.-]+@[\w\.-]+\.\w+',
            ]
        }

        # Common noise patterns to clean from registrar names
        self.noise_patterns = [
            r'\[Tag\s*=\s*[^\]]+\]',
            r'\(http[s]?://[^\)]+\)',
            r'URL:.*$',
            r'Website:.*$',
            r'Tel:.*$',
            r'\s+$',
        ]
        
    def get_database_connection(self):
        """Create database connection."""
        return create_engine(
            f'postgresql://{self.config["user"]}:{self.config["password"]}@localhost/normal_sites'
        )
        
    def normalize_text(self, text: str) -> str:
        """Normalize and clean text data."""
        if pd.isna(text):
            return ""
        
        # Normalize Unicode characters
        text = unicodedata.normalize('NFKC', str(text))
        
        # Remove excluded patterns
        for pattern in self.patterns['exclude']:
            text = re.sub(pattern, '', text)
            
        # Remove noise patterns
        for pattern in self.noise_patterns:
            text = re.sub(pattern, '', text)
            
        # Clean up whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text

    def clean_registrar_name(self, registrar: str) -> str:
        """Clean and normalize registrar name."""
        if not registrar:
            return None
            
        # Remove common suffixes and legal entity types
        suffixes = [
            r'\s+Limited$', r'\s+Ltd\.?$', r'\s+Inc\.?$', r'\s+LLC$', r'\s+Corp\.?$',
            r'\s+Corporation$', r'\s+GmbH$', r'\s+B\.V\.?$', r'\s+AG$'
        ]
        
        cleaned = registrar
        for suffix in suffixes:
            cleaned = re.sub(suffix, '', cleaned, flags=re.IGNORECASE)
            
        # Remove any remaining parentheses and their contents
        cleaned = re.sub(r'\([^)]*\)', '', cleaned)
        
        # Clean up whitespace and normalize case
        cleaned = ' '.join(cleaned.split())
        
        return cleaned if cleaned else None

    def extract_registrar(self, whois_data: str) -> str:
        """Extract registrar information with improved accuracy."""
        if pd.isna(whois_data):
            return None
            
        whois_data = self.normalize_text(whois_data)
        
        for pattern in self.patterns['registrar']:
            match = re.search(pattern, whois_data, re.IGNORECASE | re.MULTILINE)
            if match:
                registrar = match.group(1).strip()
                cleaned_registrar = self.clean_registrar_name(registrar)
                if cleaned_registrar:
                    return cleaned_registrar
                    
        return None

    def process_records(self):
        """Process records with improved extraction and validation."""
        engine = self.get_database_connection()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        query = """
        SELECT id, domain, whois_domain, domain_registrar
        FROM website_data
        WHERE status = 7
        AND (domain_registrar IS NULL OR domain_registrar = '')
        ORDER BY id
        """
        
        self.logger.info("Starting improved registrar extraction process")
        extracted_data = []
        chunk_size = 1000
        
        for chunk_df in pd.read_sql_query(query, engine, chunksize=chunk_size):
            self.logger.info(f"Processing chunk of {len(chunk_df)} records")
            
            for _, row in chunk_df.iterrows():
                registrar = self.extract_registrar(row['whois_domain'])
                
                if registrar:
                    extracted_data.append({
                        'id': int(row['id']),
                        'domain': row['domain'],
                        'extracted_registrar': registrar,
                        'original_whois': row['whois_domain'][:200]  # Store first 200 chars for verification
                    })
                    self.logger.info(f"Extracted registrar for {row['domain']}: {registrar}")
                    
        # Save extracted data
        output_file = self.output_dir / f'extracted_registrars_{timestamp}.json'
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(extracted_data, f, ensure_ascii=False, indent=2)
            
        self.logger.info(f"Extraction complete. Processed {len(extracted_data)} records")
        self.logger.info(f"Results saved to {output_file}")
        
        # Log extraction statistics
        self.log_extraction_statistics(extracted_data)
        
        return len(extracted_data)

    def log_extraction_statistics(self, extracted_data):
        """Log statistics about the extraction process."""
        if not extracted_data:
            self.logger.info("No registrars extracted")
            return
            
        registrar_counts = {}
        for record in extracted_data:
            registrar = record['extracted_registrar']
            registrar_counts[registrar] = registrar_counts.get(registrar, 0) + 1
            
        self.logger.info("\nExtraction Statistics:")
        self.logger.info(f"Total unique registrars found: {len(registrar_counts)}")
        self.logger.info("\nTop 10 most common registrars:")
        
        for registrar, count in sorted(registrar_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            self.logger.info(f"{registrar}: {count} domains")

def main():
    config_path = "/home/asomura/waseda/nextstep/RAPIDS/config/database.json"
    extractor = ImprovedRegistrarExtractor(config_path)
    extracted_count = extractor.process_records()
    print(f"Extraction complete. Found {extracted_count} registrars.")

if __name__ == "__main__":
    main()
