import pandas as pd
import numpy as np
from sqlalchemy import create_engine
from datetime import datetime
import re
from tqdm import tqdm
import json

class PhishingDataProcessor:
    def __init__(self, db_connection_string):
        """
        データベース接続とデータ処理の初期化
        Args:
            db_connection_string: PostgreSQLの接続文字列
        """
        self.engine = create_engine(db_connection_string)
        self.data = None
        
    def load_data(self):
        """データベースからデータを読み込む"""
        query = """
        SELECT 
            id,
            status,
            phish_id,
            verified,
            online_status,
            target,
            domain,
            domain_registrar,
            registrant_name,
            admin_name,
            tech_name,
            ip_address,
            ip_organization,
            ip_location,
            hosting_provider,
            https_certificate_issuer,
            https_certificate_domain,
            phishing_flag,
            phishing_confirm_flag,
            actor,
            whois_domain,
            domain_status,
            url
        FROM website_data
        """
        self.data = pd.read_sql(query, self.engine)
        print(f"Loaded {len(self.data)} records")
        return self
    
    def analyze_data_quality(self):
        """データ品質の分析"""
        analysis = {
            'total_records': len(self.data),
            'missing_values': self.data.isnull().sum().to_dict(),
            'verified_distribution': self.data['verified'].value_counts().to_dict(),
            'phishing_flags': self.data['phishing_flag'].value_counts().to_dict(),
            'status_distribution': self.data['status'].value_counts().to_dict(),
            'unique_domains': len(self.data['domain'].unique()),
            'unique_registrars': len(self.data['domain_registrar'].unique()),
            'unique_issuers': len(self.data['https_certificate_issuer'].unique())
        }
        return analysis
    
    def extract_domain_features(self):
        """ドメインに関する特徴量の抽出"""
        def analyze_domain(domain):
            if pd.isna(domain):
                return {
                    'length': 0,
                    'num_digits': 0,
                    'num_special_chars': 0,
                    'num_segments': 0,
                    'has_suspicious_keywords': False
                }
            
            suspicious_keywords = ['secure', 'login', 'account', 'bank', 'verify', 'update']
            
            return {
                'length': len(domain),
                'num_digits': sum(c.isdigit() for c in domain),
                'num_special_chars': sum(not c.isalnum() for c in domain),
                'num_segments': len(domain.split('.')),
                'has_suspicious_keywords': any(keyword in domain.lower() for keyword in suspicious_keywords)
            }
        
        # ドメイン特徴量の抽出
        domain_features = self.data['domain'].apply(analyze_domain)
        domain_features_df = pd.DataFrame(domain_features.tolist())
        
        return domain_features_df
    
    def extract_whois_features(self):
        """WHOIS情報からの特徴量抽出"""
        def analyze_whois(row):
            return {
                'has_registrant': not pd.isna(row['registrant_name']),
                'has_admin': not pd.isna(row['admin_name']),
                'has_tech': not pd.isna(row['tech_name']),
                'registrar_present': not pd.isna(row['domain_registrar']),
                'status_present': not pd.isna(row['domain_status'])
            }
        
        whois_features = self.data.apply(analyze_whois, axis=1)
        whois_features_df = pd.DataFrame(whois_features.tolist())
        
        return whois_features_df
    
    def prepare_text_data_for_bert(self):
        """BERTモデル用のテキストデータ準備"""
        def combine_text_fields(row):
            text_fields = []
            
            # ドメイン情報
            if not pd.isna(row['domain']):
                text_fields.append(f"Domain: {row['domain']}")
            
            # WHOIS情報
            if not pd.isna(row['whois_domain']):
                text_fields.append(f"WHOIS: {row['whois_domain']}")
            
            # 証明書情報
            if not pd.isna(row['https_certificate_issuer']):
                text_fields.append(f"Certificate Issuer: {row['https_certificate_issuer']}")
            
            # 組織情報
            if not pd.isna(row['ip_organization']):
                text_fields.append(f"Organization: {row['ip_organization']}")
            
            return ' [SEP] '.join(text_fields)
        
        self.data['bert_input_text'] = self.data.apply(combine_text_fields, axis=1)
        return self.data['bert_input_text']
    
    def create_training_dataset(self):
        """トレーニングデータセットの作成"""
        # 特徴量の結合
        domain_features = self.extract_domain_features()
        whois_features = self.extract_whois_features()
        
        # ラベルの準備（phishing_flagとphishing_confirm_flagの組み合わせ）
        labels = (self.data['phishing_flag'] | self.data['phishing_confirm_flag']).astype(int)
        
        # テキストデータの準備
        text_data = self.prepare_text_data_for_bert()
        
        # データセットの作成
        dataset = pd.concat([
            domain_features,
            whois_features,
            pd.DataFrame({'text_data': text_data, 'label': labels})
        ], axis=1)
        
        return dataset
    
    def save_processed_data(self, output_path):
        """処理済みデータの保存"""
        dataset = self.create_training_dataset()
        dataset.to_csv(output_path, index=False)
        print(f"Saved processed dataset to {output_path}")

def main():
    # データベース接続文字列（適切な値に置き換えてください）
    db_connection = "postgresql://username:password@localhost:5432/database_name"
    
    # データ処理パイプラインの実行
    processor = PhishingDataProcessor(db_connection)
    
    # データの読み込みと分析
    processor.load_data()
    
    # データ品質の分析
    quality_analysis = processor.analyze_data_quality()
    print("\nData Quality Analysis:")
    print(json.dumps(quality_analysis, indent=2))
    
    # 処理済みデータの保存
    processor.save_processed_data('processed_phishing_data.csv')

if __name__ == "__main__":
    main()
