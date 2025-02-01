#!/usr/bin/env python3
"""
Registrar Information Extractor for RAPIDS Project
このスクリプトは、WHOISデータから非構造化のレジストラ情報を抽出します。

出力:
- ログファイル: ~/waseda/nextstep/RAPIDS/logs/registrar_extraction_{timestamp}.log
- 抽出結果: ~/waseda/nextstep/RAPIDS/data/processed/extracted_registrars_{timestamp}.csv

Author: RAPIDS Project Team
Date: 2025-01-18
"""

import pandas as pd
from sqlalchemy import create_engine
import json
from pathlib import Path
import logging
from datetime import datetime
import re
import os

class RegistrarExtractor:
    """WHOISデータからレジストラ情報を抽出するクラス"""
    
    def __init__(self, config_path):
        """
        初期化
        Args:
            config_path: データベース設定ファイルのパス
        """
        self.setup_paths()
        self.setup_logging()
        self.load_config(config_path)
        self.setup_regex_patterns()

    def setup_paths(self):
        """パスの設定"""
        self.base_dir = Path('/home/asomura/waseda/nextstep/RAPIDS')
        self.log_dir = self.base_dir / 'logs'
        self.data_dir = self.base_dir / 'data' / 'processed'
        
        # ディレクトリが存在しない場合は作成
        for dir_path in [self.log_dir, self.data_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)

    def setup_logging(self):
        """ログ設定"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_file = self.log_dir / f'registrar_extraction_{timestamp}.log'
        
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # コンソールにも出力
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

    def load_config(self, config_path):
        """データベース設定の読み込み"""
        with open(config_path) as f:
            self.config = json.load(f)['database']

    def setup_regex_patterns(self):
        """正規表現パターンの設定"""
        self.patterns = {
            'generic': [
                r'Registrar:\s*([^\n]+)',
                r'Registrar Name:\s*([^\n]+)',
                r'Registration Service Provider:\s*([^\n]+)'
            ],
            'kr': [
                r'등록대행자:\s*([^\n]+)'
            ],
            'cn': [
                r'Sponsoring Registrar:\s*([^\n]+)'
            ],
            'jp': [
                r'レジストラ:\s*([^\n]+)',
                r'Registrar:\s*([^\n]+)'
            ]
        }

    def get_database_connection(self):
        """データベース接続の作成"""
        return create_engine(
            f'postgresql://{self.config["user"]}:{self.config["password"]}@localhost/normal_sites'
        )

    def extract_registrar(self, whois_text):
        """
        WHOISテキストからレジストラ情報を抽出
        Args:
            whois_text: WHOIS情報のテキスト
        Returns:
            抽出されたレジストラ情報（見つからない場合はNone）
        """
        if pd.isna(whois_text):
            return None

        whois_text = str(whois_text)
        
        # 各パターンで検索
        for pattern_type, patterns in self.patterns.items():
            for pattern in patterns:
                match = re.search(pattern, whois_text)
                if match:
                    registrar = match.group(1).strip()
                    # 基本的なクリーニング
                    registrar = re.sub(r'\s+', ' ', registrar)
                    registrar = registrar.strip('[](){}"\'')
                    return registrar

        return None

    def extract_registrars(self):
        """メイン処理：レジストラ情報の抽出と保存"""
        self.logger.info("レジストラ情報の抽出を開始")
        
        engine = self.get_database_connection()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # 未指定レジストラのデータを取得
        query = """
        SELECT 
            id,
            domain,
            whois_domain
        FROM website_data 
        WHERE status = 7 
        AND (domain_registrar IS NULL OR domain_registrar = '')
        """
        
        try:
            df = pd.read_sql_query(query, engine)
            self.logger.info(f"取得レコード数: {len(df)}")
            
            # レジストラ情報の抽出
            results = []
            for _, row in df.iterrows():
                registrar = self.extract_registrar(row['whois_domain'])
                results.append({
                    'id': row['id'],
                    'domain': row['domain'],
                    'extracted_registrar': registrar
                })
            
            # 結果をDataFrameに変換
            results_df = pd.DataFrame(results)
            
            # 抽出結果の保存
            output_file = self.data_dir / f'extracted_registrars_{timestamp}.csv'
            results_df.to_csv(output_file, index=False)
            
            # 統計情報のログ出力
            total = len(results_df)
            extracted = results_df['extracted_registrar'].notna().sum()
            self.logger.info(f"総レコード数: {total}")
            self.logger.info(f"レジストラ抽出成功: {extracted}")
            self.logger.info(f"抽出成功率: {(extracted/total)*100:.2f}%")
            self.logger.info(f"結果を保存: {output_file}")
            
            return output_file
            
        except Exception as e:
            self.logger.error(f"エラーが発生: {str(e)}")
            raise

def main():
    config_path = "/home/asomura/waseda/nextstep/RAPIDS/config/database.json"
    extractor = RegistrarExtractor(config_path)
    extractor.extract_registrars()

if __name__ == "__main__":
    main()
