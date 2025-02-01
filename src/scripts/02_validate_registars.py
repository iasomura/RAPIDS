#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WHOIS Registrar Validator
Location: RAPIDS/src/data/registrar_extraction/02_validate_registrars.py

This script validates and normalizes registrar information extracted from WHOIS data.
It performs the following tasks:
1. Normalizes registrar names
2. Validates against known registrar lists
3. Assigns confidence scores
4. Generates validation report

Input: extracted_registrars_{timestamp}.json from step 1
Output: validated_registrars_{timestamp}.json and validation_report_{timestamp}.log
"""

import json
import logging
from pathlib import Path
from datetime import datetime
import re
from typing import Dict, List, Tuple, Optional
import difflib
import unicodedata

class RegistrarValidator:
    """Validates and normalizes extracted registrar information."""
    
    def __init__(self):
        """Initialize the validator with necessary configurations."""
        self.setup_environment()
        self.setup_logging()
        self.load_known_registrars()
        
    def setup_environment(self):
        """Setup working environment and directories."""
        self.base_dir = Path('/home/asomura/waseda/nextstep/RAPIDS')
        self.input_dir = self.base_dir / 'data' / 'processed' / 'registrar_extraction'
        self.output_dir = self.base_dir / 'data' / 'processed' / 'registrar_validation'
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def setup_logging(self):
        """Configure logging settings."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_file = self.output_dir / f'validation_report_{timestamp}.log'
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def load_known_registrars(self):
        """Load list of known registrars."""
        # Major registrars list
        self.known_registrars = {
            'godaddy': ['GoDaddy.com, LLC', 'GoDaddy'],
            'namecheap': ['NameCheap, Inc.', 'NAMECHEAP INC'],
            'name.com': ['Name.com, Inc.', 'NAME.COM'],
            'tucows': ['Tucows Domains Inc.', 'TUCOWS'],
            'enom': ['eNom, LLC', 'ENOM'],
            'network_solutions': ['Network Solutions, LLC'],
            'register.com': ['Register.com, Inc.'],
            'markmonitor': ['MarkMonitor Inc.', 'MARKMONITOR'],
            'gandi': ['Gandi SAS', 'GANDI'],
            'ovh': ['OVH SAS', 'OVH'],
            'cloudflare': ['Cloudflare, Inc.', 'CLOUDFLARE'],
            '1and1': ['1&1 IONOS SE', '1AND1'],
            'amazon': ['Amazon Registrar, Inc.'],
            'google': ['Google LLC'],
            'alibaba': ['Alibaba Cloud Computing Ltd.'],
            'fastdomain': ['FastDomain Inc.'],
            'hostgator': ['HostGator'],
            'bluehost': ['Bluehost Inc.'],
            'dreamhost': ['DreamHost, LLC'],
            'namesilo': ['NameSilo, LLC']
        }
        
        # Compile regex patterns for each registrar
        self.registrar_patterns = {}
        for key, variations in self.known_registrars.items():
            patterns = [re.compile(rf'\b{re.escape(var)}\b', re.IGNORECASE) 
                       for var in variations]
            self.registrar_patterns[key] = patterns
    
    def normalize_registrar_name(self, name: str) -> str:
        """Normalize registrar name by removing noise and standardizing format."""
        if not name:
            return ""
            
        # Convert to string and normalize Unicode characters
        name = str(name)
        name = unicodedata.normalize('NFKC', name)
        
        # Remove common noise patterns
        noise_patterns = [
            r'http[s]?://\S+',  # URLs
            r'[\w\.-]+@[\w\.-]+',  # Email addresses
            r'\+?\d{1,4}[-\s\.]?\d{1,12}',  # Phone numbers
            r'Address:.*$',  # Addresses
            r'Tel:.*$',  # Telephone info
            r'Fax:.*$',  # Fax info
            r'Website:.*$',  # Website info
            r'\[.*?\]',  # Content in square brackets
            r'\(.*?\)',  # Content in parentheses
        ]
        
        for pattern in noise_patterns:
            name = re.sub(pattern, '', name, flags=re.IGNORECASE | re.MULTILINE)
        
        # Clean up whitespace and punctuation
        name = re.sub(r'\s+', ' ', name)
        name = name.strip(' ,.;:-')
        
        return name
        
    def match_known_registrar(self, name: str) -> Tuple[str, float]:
        """Match normalized name against known registrars."""
        max_score = 0
        matched_registrar = None
        
        normalized_name = self.normalize_registrar_name(name)
        
        # Try exact matches first
        for key, patterns in self.registrar_patterns.items():
            for pattern in patterns:
                if pattern.search(normalized_name):
                    return key, 1.0
        
        # If no exact match, try fuzzy matching
        for key, variations in self.known_registrars.items():
            for variation in variations:
                score = difflib.SequenceMatcher(None, normalized_name.lower(), 
                                              variation.lower()).ratio()
                if score > max_score and score > 0.8:  # 80% similarity threshold
                    max_score = score
                    matched_registrar = key
        
        return matched_registrar or "unknown", max_score
        
    def validate_registrar(self, registrar_info: Dict) -> Dict:
        """Validate and enrich registrar information."""
        extracted_registrar = registrar_info.get('extracted_registrar', '')
        normalized_name = self.normalize_registrar_name(extracted_registrar)
        matched_name, confidence = self.match_known_registrar(normalized_name)
        
        return {
            'id': registrar_info['id'],
            'domain': registrar_info['domain'],
            'original_registrar': extracted_registrar,
            'normalized_name': normalized_name,
            'matched_registrar': matched_name,
            'confidence_score': confidence
        }
        
    def get_latest_extraction_file(self) -> Optional[Path]:
        """Get the most recent extraction file."""
        extraction_files = list(self.input_dir.glob('extracted_registrars_*.json'))
        if not extraction_files:
            return None
        return max(extraction_files, key=lambda x: x.stat().st_mtime)
        
    def process_registrars(self):
        """Process and validate all extracted registrars."""
        input_file = self.get_latest_extraction_file()
        if not input_file:
            self.logger.error("No extraction file found")
            return
            
        self.logger.info(f"Processing extraction file: {input_file}")
        
        with open(input_file, 'r', encoding='utf-8') as f:
            extracted_data = json.load(f)
            
        validated_data = []
        validation_stats = {
            'total': 0,
            'matched': 0,
            'unknown': 0,
            'high_confidence': 0
        }
        
        for item in extracted_data:
            validated = self.validate_registrar(item)
            validated_data.append(validated)
            
            validation_stats['total'] += 1
            if validated['matched_registrar'] != 'unknown':
                validation_stats['matched'] += 1
            else:
                validation_stats['unknown'] += 1
            if validated['confidence_score'] >= 0.9:
                validation_stats['high_confidence'] += 1
                
        # Save validated data
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = self.output_dir / f'validated_registrars_{timestamp}.json'
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(validated_data, f, ensure_ascii=False, indent=2)
            
        # Log statistics
        self.logger.info("\nValidation Statistics:")
        self.logger.info(f"Total registrars processed: {validation_stats['total']}")
        self.logger.info(f"Matched to known registrars: {validation_stats['matched']}")
        self.logger.info(f"Unknown registrars: {validation_stats['unknown']}")
        self.logger.info(f"High confidence matches: {validation_stats['high_confidence']}")
        self.logger.info(f"\nResults saved to {output_file}")
        
        return validated_data, validation_stats

def main():
    validator = RegistrarValidator()
    validator.process_registrars()

if __name__ == "__main__":
    main()
