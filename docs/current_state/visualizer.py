#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Enhanced Certificate Visualizer Module
Handles the visualization of SSL certificate analysis for the RAPIDS project.

Author: RAPIDS Project Team
Date: 2024-12-14
"""

import os
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from typing import Dict, Optional
from datetime import datetime

class CertificateVisualizer:
    """Enhanced visualizer for certificate analysis results"""
    
    def __init__(self, output_dir: str):
        """
        Initialize the visualizer
        
        Args:
            output_dir: Directory path for saving visualizations
        """
        self.output_dir = output_dir
        self.setup_style()

    def setup_style(self):
        """Configure visualization style settings"""
        plt.style.use('default')
        sns.set_style("whitegrid")
        
        # Color palette for different site types
        self.colors = {
            'normal': '#2ecc71',    # Green
            'phishing': '#e74c3c'   # Red
        }
        
        # Common plot settings
        self.plot_config = {
            'figure.figsize': (12, 6),
            'figure.dpi': 300,
            'axes.titlesize': 14,
            'axes.labelsize': 12,
            'xtick.labelsize': 10,
            'ytick.labelsize': 10
        }
        plt.rcParams.update(self.plot_config)

    def create_all_visualizations(self, df: pd.DataFrame, timestamp: str):
        """
        Create all visualizations for the certificate analysis
        
        Args:
            df: DataFrame containing analyzed certificate data
            timestamp: Timestamp string for file naming
        """
        self.plot_issuer_distribution(df, timestamp)
        self.plot_protocol_distribution(df, timestamp)
        self.plot_key_size_distribution(df, timestamp)
        self.plot_chain_length_distribution(df, timestamp)
        self.plot_domain_features(df, timestamp)
        self.plot_security_scores(df, timestamp)
        self.plot_cipher_strength(df, timestamp)
        self.plot_validity_periods(df, timestamp)
        self.create_summary_dashboard(df, timestamp)

    def plot_issuer_distribution(self, df: pd.DataFrame, timestamp: str):
        """Plot enhanced certificate issuer distribution heatmap"""
        plt.figure(figsize=(15, 8))
        
        # Calculate issuer distribution
        issuer_counts = df.groupby(['site_type', 'https_certificate_issuer']).size().unstack(fill_value=0)
        
        # Select top issuers based on total count
        top_issuers = issuer_counts.sum().nlargest(10).index
        issuer_counts = issuer_counts[top_issuers]
        
        # Create heatmap
        sns.heatmap(issuer_counts, cmap='RdYlBu_r', annot=True, fmt='g',
                    cbar_kws={'label': 'Number of Sites'})
        
        plt.title('Top 10 Certificate Issuer Distribution by Site Type')
        plt.xlabel('Certificate Issuer')
        plt.ylabel('Site Type')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        self._save_plot('issuer_distribution', timestamp)

    def plot_security_scores(self, df: pd.DataFrame, timestamp: str):
        """Plot security score distributions with component breakdown"""
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10))
        
        # Overall security score distribution
        for site_type in df['site_type'].unique():
            sns.kdeplot(
                data=df[df['site_type'] == site_type]['security_score'],
                ax=ax1,
                label=site_type,
                color=self.colors[site_type]
            )
        ax1.set_title('Security Score Distribution by Site Type')
        ax1.set_xlabel('Security Score')
        ax1.set_ylabel('Density')
        ax1.legend()
        
        # Component scores
        component_scores = ['tls_score', 'key_score', 'issuer_score', 
                          'domain_score', 'cipher_score']
        
        mean_scores = df.groupby('site_type')[component_scores].mean()
        mean_scores.plot(kind='bar', ax=ax2)
        ax2.set_title('Average Component Scores by Site Type')
        ax2.set_xlabel('Site Type')
        ax2.set_ylabel('Score')
        ax2.legend(title='Components')
        
        plt.tight_layout()
        self._save_plot('security_scores', timestamp)

    def plot_cipher_strength(self, df: pd.DataFrame, timestamp: str):
        """Plot cipher suite strength distribution"""
        plt.figure(figsize=(12, 6))
        
        # Create cipher strength category if not exists
        if 'cipher_category' not in df.columns:
            def categorize_cipher(cipher):
                if not cipher:
                    return 'unknown'
                cipher = str(cipher).upper()
                if any(x in cipher for x in ['GCM', 'CHACHA20', 'POLY1305']):
                    return 'strong'
                elif 'SHA384' in cipher:
                    return 'medium'
                else:
                    return 'weak'
            df['cipher_category'] = df['cipher_suite'].apply(categorize_cipher)
        
        # Create stacked bar plot
        cipher_dist = df.groupby(['site_type', 'cipher_category']).size().unstack()
        cipher_dist.plot(kind='bar', stacked=True)
        
        plt.title('Cipher Strength Distribution by Site Type')
        plt.xlabel('Site Type')
        plt.ylabel('Count')
        plt.legend(title='Cipher Strength')
        plt.tight_layout()
        
        self._save_plot('cipher_strength', timestamp)

    def plot_validity_periods(self, df: pd.DataFrame, timestamp: str):
        """Plot certificate validity period analysis"""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # Valid days distribution
        for site_type in df['site_type'].unique():
            site_data = df[df['site_type'] == site_type]['valid_days']
            sns.kdeplot(
                data=site_data,
                ax=ax1,
                label=site_type,
                color=self.colors[site_type]
            )
        ax1.set_title('Certificate Validity Period Distribution')
        ax1.set_xlabel('Days')
        ax1.set_ylabel('Density')
        
        # Expiration status
        now = datetime.now()
        df['cert_status'] = df.apply(
            lambda x: 'Not Yet Valid' if pd.to_datetime(x['cert_valid_from']) > now
            else ('Expired' if pd.to_datetime(x['cert_valid_to']) < now
            else 'Valid'),
            axis=1
        )
        
        status_counts = df.groupby(['site_type', 'cert_status']).size().unstack()
        status_counts.plot(kind='bar', ax=ax2)
        ax2.set_title('Certificate Status Distribution')
        ax2.set_xlabel('Site Type')
        ax2.set_ylabel('Count')
        
        plt.tight_layout()
        self._save_plot('validity_periods', timestamp)

    def create_summary_dashboard(self, df: pd.DataFrame, timestamp: str):
        """Create comprehensive summary dashboard"""
        fig = plt.figure(figsize=(20, 15))
        
        # Grid layout
        gs = fig.add_gridspec(3, 3)
        
        # Security score distribution
        ax1 = fig.add_subplot(gs[0, :])
        for site_type in df['site_type'].unique():
            sns.kdeplot(
                data=df[df['site_type'] == site_type]['security_score'],
                ax=ax1,
                label=site_type,
                color=self.colors[site_type]
            )
        ax1.set_title('Security Score Distribution')
        
        # Protocol version distribution
        ax2 = fig.add_subplot(gs[1, 0])
        protocol_counts = df.groupby(['site_type', 'protocol_version']).size().unstack()
        protocol_counts.plot(kind='bar', ax=ax2)
        ax2.set_title('Protocol Versions')
        ax2.tick_params(axis='x', rotation=45)
        
        # Key size distribution
        ax3 = fig.add_subplot(gs[1, 1])
        df.boxplot(column='public_key_bits', by='site_type', ax=ax3)
        ax3.set_title('Key Sizes')
        
        # Cipher strength distribution
        ax4 = fig.add_subplot(gs[1, 2])
        cipher_dist = df.groupby(['site_type', 'cipher_category']).size().unstack()
        cipher_dist.plot(kind='bar', stacked=True, ax=ax4)
        ax4.set_title('Cipher Strength')
        ax4.tick_params(axis='x', rotation=45)
        
        # Domain length distribution
        ax5 = fig.add_subplot(gs[2, 0])
        df.boxplot(column='domain_length', by='site_type', ax=ax5)
        ax5.set_title('Domain Lengths')
        
        # Certificate chain length
        ax6 = fig.add_subplot(gs[2, 1])
        df.boxplot(column='cert_chain_length', by='site_type', ax=ax6)
        ax6.set_title('Chain Lengths')
        
        # Validity periods
        ax7 = fig.add_subplot(gs[2, 2])
        df.boxplot(column='valid_days', by='site_type', ax=ax7)
        ax7.set_title('Validity Periods (Days)')
        
        plt.suptitle('Certificate Analysis Summary Dashboard', size=16)
        plt.tight_layout()
        
        self._save_plot('summary_dashboard', timestamp)

    def _save_plot(self, name: str, timestamp: str):
        """
        Save plot with proper naming and error handling
        
        Args:
            name: Base name for the plot file
            timestamp: Timestamp string for file naming
        """
        try:
            output_path = os.path.join(self.output_dir, f'{name}_{timestamp}.png')
            plt.savefig(output_path, bbox_inches='tight', dpi=300)
            plt.close()
        except Exception as e:
            print(f"Error saving plot {name}: {str(e)}")
            plt.close()
