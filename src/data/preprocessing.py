"""
Phishing Website Data Analysis Script
====================================

This script performs initial data analysis on the website_data table for phishing detection research.

Purpose:
--------
- Load and analyze website data from PostgreSQL database
- Perform basic statistical analysis on key features
- Generate visualizations of data distributions
- Create processed dataset for machine learning

Input:
------
PostgreSQL database table 'website_data' with the following key columns:
- id: unique identifier
- status: website status (analysis focuses on status = 7)
- url: website URL
- domain: domain name
- domain_registrar: registrar information
- whois_date: WHOIS record date
- registrant_name: domain registrant
- admin_name: administrative contact
- tech_name: technical contact
- ip_address: website IP
- https_certificate_issuer: SSL certificate issuer
- phishing_flag: phishing indication
- phishing_confirm_flag: confirmed phishing status

Output:
-------
1. CSV File (processed_website_data.csv):
   - Processed dataset with extracted features
   - Binary indicators for presence of registration info
   - Calculated domain age
   - Cleaned and formatted fields

2. Visualization (initial_analysis.png):
   - Missing values heatmap
   - Binary features distribution
   - Domain age distribution
   - Top domain registrars

3. Console Output:
   - Basic statistics
   - Data type information
   - Missing value analysis
   - Distribution of key features
   - Top categories in categorical variables

Requirements:
------------
- Python 3.8+
- Required packages:
  - pandas
  - psycopg2-binary
  - sqlalchemy
  - matplotlib
  - seaborn

Database Configuration:
---------------------
Update the following in connect_to_db():
- dbname: database name
- user: database username
- password: database password
- host: database host

Usage:
------
1. Configure database connection parameters
2. Run: python preprocessing.py
3. Check output files and console logs

Error Handling:
-------------
- Logs are written to console with timestamps
- Database connection errors are caught and reported
- Data processing errors are logged with details
"""

import pandas as pd
import psycopg2
from sqlalchemy import create_engine
import numpy as np
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def connect_to_db():
    """Database connection function with error handling"""
    try:
        conn = psycopg2.connect(
            dbname="website_data",  # データベース名を実際のものに変更してください
            user="postgres",
            password="asomura",  # 実際のパスワードに変更してください
            host="localhost"
        )
        logging.info("Successfully connected to database")
        return conn
    except Exception as e:
        logging.error(f"Database connection error: {e}")
        return None

def load_and_analyze_data():
    """Load and perform initial analysis with extensive error checking"""
    
    conn = connect_to_db()
    if not conn:
        return None

    try:
        # First, let's check what data we actually have
        check_query = """
        SELECT COUNT(*) as count, 
               COUNT(phishing_flag) as flag_count,
               COUNT(phishing_confirm_flag) as confirm_flag_count
        FROM website_data 
        WHERE status = 7
        """
        
        check_df = pd.read_sql_query(check_query, conn)
        logging.info(f"Data counts: {check_df.to_dict('records')[0]}")

        # Main data query with error handling
        query = """
        SELECT 
            id, 
            COALESCE(status, -1) as status,
            url,
            domain,
            domain_registrar,
            whois_date,
            registrant_name,
            admin_name,
            tech_name,
            ip_address,
            ip_organization,
            ip_location,
            https_certificate_issuer,
            COALESCE(phishing_flag, FALSE) as phishing_flag,
            COALESCE(phishing_confirm_flag, FALSE) as phishing_confirm_flag
        FROM website_data 
        WHERE status = 7
        """
        
        df = pd.read_sql_query(query, conn)
        logging.info(f"Loaded {len(df)} records from database")
        
        # Basic data analysis with error checking
        print("\n=== Basic Data Analysis ===")
        print(f"Total number of records: {len(df)}")
        
        # Check data types
        print("\nData Types:")
        print(df.dtypes)
        
        # Analyze missing values
        print("\nMissing values analysis:")
        missing_data = df.isnull().sum()
        print(missing_data)
        
        # Analyze boolean columns
        if 'phishing_flag' in df.columns and 'phishing_confirm_flag' in df.columns:
            print("\nPhishing flags distribution:")
            flag_dist = pd.DataFrame({
                'phishing_flag': df['phishing_flag'].value_counts(),
                'phishing_confirm_flag': df['phishing_confirm_flag'].value_counts()
            })
            print(flag_dist)
        
        # Analyze domain registrars (top 10)
        if 'domain_registrar' in df.columns:
            print("\nTop 10 domain registrars:")
            print(df['domain_registrar'].value_counts().head(10))
        
        # Analyze certificate issuers (top 10)
        if 'https_certificate_issuer' in df.columns:
            print("\nTop 10 certificate issuers:")
            print(df['https_certificate_issuer'].value_counts().head(10))
        
        # Create processed dataframe
        processed_df = df.copy()
        
        # Create binary features
        processed_df['has_registrant'] = processed_df['registrant_name'].notna().astype(int)
        processed_df['has_admin'] = processed_df['admin_name'].notna().astype(int)
        processed_df['has_tech'] = processed_df['tech_name'].notna().astype(int)
        
        # Process dates
        if 'whois_date' in processed_df.columns:
            processed_df['whois_date'] = pd.to_datetime(processed_df['whois_date'], errors='coerce')
            current_time = pd.Timestamp.now()
            processed_df['domain_age_days'] = (current_time - processed_df['whois_date']).dt.days
        
        # Save processed data
        processed_df.to_csv('processed_website_data.csv', index=False)
        logging.info("Saved processed data to CSV")
        
        return processed_df
        
    except Exception as e:
        logging.error(f"Error in data analysis: {e}")
        return None
    finally:
        conn.close()

def create_visualization(df):
    """Create visualizations with error checking"""
    if df is None or len(df) == 0:
        logging.error("No data available for visualization")
        return
    
    try:
        plt.figure(figsize=(15, 10))
        
        # Plot 1: Missing values heatmap
        plt.subplot(2, 2, 1)
        sns.heatmap(df.isnull(), yticklabels=False, cbar=False)
        plt.title('Missing Values Heatmap')
        
        # Plot 2: Binary features distribution
        plt.subplot(2, 2, 2)
        binary_features = df[['has_registrant', 'has_admin', 'has_tech']].sum()
        binary_features.plot(kind='bar')
        plt.title('Binary Features Distribution')
        
        # Plot 3: Domain age distribution (if available)
        if 'domain_age_days' in df.columns:
            plt.subplot(2, 2, 3)
            df['domain_age_days'].dropna().hist(bins=50)
            plt.title('Domain Age Distribution (days)')
        
        # Plot 4: Registrar distribution (top 10)
        if 'domain_registrar' in df.columns:
            plt.subplot(2, 2, 4)
            df['domain_registrar'].value_counts().head(10).plot(kind='bar')
            plt.title('Top 10 Domain Registrars')
            plt.xticks(rotation=45)
        
        plt.tight_layout()
        plt.savefig('initial_analysis.png', bbox_inches='tight')
        plt.close()
        logging.info("Successfully created visualizations")
        
    except Exception as e:
        logging.error(f"Error in visualization: {e}")

def main():
    logging.info("Starting data analysis")
    df = load_and_analyze_data()
    
    if df is not None and not df.empty:
        create_visualization(df)
        logging.info("Analysis completed successfully")
    else:
        logging.error("No data to analyze")

if __name__ == "__main__":
    main()
