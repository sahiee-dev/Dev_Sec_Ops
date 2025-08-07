import pandas as pd
import numpy as np
import requests
import os
import gzip
import re
import tarfile
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional
import logging
from tqdm import tqdm

class LoghubDatasetLoader:
    """
    Loads and processes real system logs from the Loghub repository
    for training production-ready anomaly detection models.
    """
    
    def __init__(self, data_dir: str = "../../data/real_datasets"):
        self.data_dir = data_dir
        self.setup_directories()
        
        # Loghub dataset configurations
        self.datasets = {
            'Linux': {
                'url': 'https://zenodo.org/record/3227177/files/Linux.tar.gz',
                'description': 'Linux system logs',
                'size': '2.25MB',
                'labeled': False
            },
            'Apache': {
                'url': 'https://zenodo.org/record/3227177/files/Apache.tar.gz', 
                'description': 'Apache web server logs',
                'size': '4.90MB',
                'labeled': False
            },
            'HDFS': {
                'url': 'https://zenodo.org/record/3227177/files/HDFS_1.tar.gz',
                'description': 'Hadoop Distributed File System logs',
                'size': '1.47GB',
                'labeled': True
            }
        }
    
    def setup_directories(self):
        """Create necessary directories for data storage"""
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(f"{self.data_dir}/raw", exist_ok=True)
        os.makedirs(f"{self.data_dir}/processed", exist_ok=True)
        print(f"✅ Created directories: {self.data_dir}")
    
    def download_dataset(self, dataset_name: str) -> bool:
        """Download dataset from Loghub repository with progress bar"""
        if dataset_name not in self.datasets:
            print(f"❌ Dataset '{dataset_name}' not available")
            return False
            
        dataset_info = self.datasets[dataset_name]
        url = dataset_info['url']
        filename = f"{dataset_name}.tar.gz"
        filepath = os.path.join(self.data_dir, "raw", filename)
        
        if os.path.exists(filepath):
            print(f"✅ Dataset {dataset_name} already downloaded")
            return True
            
        print(f"📥 Downloading {dataset_name} dataset ({dataset_info['size']})...")
        print(f"Description: {dataset_info['description']}")
        
        try:
            response = requests.get(url, stream=True)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            
            with open(filepath, 'wb') as f:
                with tqdm(
                    desc=f"📥 {dataset_name}",
                    total=total_size,
                    unit='B',
                    unit_scale=True,
                    unit_divisor=1024,
                    bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]'
                ) as pbar:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            pbar.update(len(chunk))
            
            print(f"✅ Successfully downloaded {dataset_name}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to download {dataset_name}: {str(e)}")
            return False
    
    def extract_and_parse_logs(self, dataset_name: str) -> pd.DataFrame:
        """Extract and parse log files into structured format"""
        raw_path = os.path.join(self.data_dir, "raw", f"{dataset_name}.tar.gz")
        extract_path = os.path.join(self.data_dir, "processed", dataset_name)
        
        if not os.path.exists(raw_path):
            print(f"❌ Raw dataset file not found: {raw_path}")
            return pd.DataFrame()
        
        # Extract archive
        os.makedirs(extract_path, exist_ok=True)
        
        print(f"📦 Extracting {dataset_name} logs...")
        with tarfile.open(raw_path, 'r:gz') as tar:
            tar.extractall(extract_path)
        
        # Find log files
        log_files = []
        for root, dirs, files in os.walk(extract_path):
            for file in files:
                if file.endswith(('.log', '.txt')) and not file.startswith('.'):
                    log_files.append(os.path.join(root, file))
        
        if not log_files:
            print(f"❌ No log files found in {dataset_name}")
            return pd.DataFrame()
        
        print(f"📄 Found {len(log_files)} log files")
        
        # Parse logs based on dataset type
        if dataset_name == 'Linux':
            return self._parse_linux_logs(log_files)
        elif dataset_name == 'Apache':
            return self._parse_apache_logs(log_files)
        elif dataset_name == 'HDFS':
            return self._parse_hdfs_logs(log_files)
        else:
            return self._parse_generic_logs(log_files)
    
    def _parse_linux_logs(self, log_files: List[str]) -> pd.DataFrame:
        """Parse Linux system logs"""
        logs = []
        
        for file_path in log_files:
            print(f"📄 Parsing {os.path.basename(file_path)}...")
            
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    
                for line_num, line in tqdm(enumerate(lines), total=len(lines), desc=f"Processing {os.path.basename(file_path)}"):
                    line = line.strip()
                    if not line:
                        continue
                    
                    log_entry = {
                        'timestamp': datetime.now().isoformat(),
                        'message': line,
                        'source': os.path.basename(file_path),
                        'line_number': line_num + 1,
                        'raw_log': line
                    }
                    logs.append(log_entry)
                    
            except Exception as e:
                print(f"⚠️ Error parsing {file_path}: {str(e)}")
                continue
        
        print(f"✅ Parsed {len(logs)} Linux log entries")
        return pd.DataFrame(logs)
    
    def _parse_apache_logs(self, log_files: List[str]) -> pd.DataFrame:
        """Parse Apache access logs"""
        logs = []
        
        # Common Apache log format pattern
        apache_pattern = r'(\S+) \S+ \S+ \[([\w:/]+\s[+\-]\d{4})\] "([^"]*)" (\d{3}) (\S+)'
        
        for file_path in log_files:
            print(f"📄 Parsing {os.path.basename(file_path)}...")
            
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    
                for line_num, line in tqdm(enumerate(lines), total=len(lines), desc=f"Processing {os.path.basename(file_path)}"):
                    line = line.strip()
                    if not line:
                        continue
                        
                    match = re.match(apache_pattern, line)
                    if match:
                        ip, timestamp_str, request, status, size = match.groups()
                        
                        log_entry = {
                            'timestamp': datetime.now().isoformat(),
                            'ip_address': ip,
                            'request': request,
                            'status_code': status,
                            'response_size': size,
                            'source': os.path.basename(file_path),
                            'line_number': line_num + 1,
                            'raw_log': line
                        }
                        logs.append(log_entry)
                        
            except Exception as e:
                print(f"⚠️ Error parsing {file_path}: {str(e)}")
                continue
        
        print(f"✅ Parsed {len(logs)} Apache log entries")
        return pd.DataFrame(logs)
    
    def _parse_generic_logs(self, log_files: List[str]) -> pd.DataFrame:
        """Generic log parser for unknown formats"""
        logs = []
        
        for file_path in log_files:
            print(f"📄 Parsing {os.path.basename(file_path)}...")
            
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    
                for line_num, line in tqdm(enumerate(lines), total=len(lines), desc=f"Processing {os.path.basename(file_path)}"):
                    line = line.strip()
                    if not line:
                        continue
                    
                    log_entry = {
                        'timestamp': datetime.now().isoformat(),
                        'message': line,
                        'source': os.path.basename(file_path),
                        'line_number': line_num + 1,
                        'raw_log': line
                    }
                    logs.append(log_entry)
                    
            except Exception as e:
                print(f"⚠️ Error parsing {file_path}: {str(e)}")
                continue
        
        print(f"✅ Parsed {len(logs)} generic log entries")
        return pd.DataFrame(logs)
    
    def prepare_ml_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Prepare features for machine learning"""
        if df.empty:
            return df
        
        print("🔧 Preparing ML features from real log data...")
        
        # Extract temporal features
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df['hour'] = df['timestamp'].dt.hour
            df['day_of_week'] = df['timestamp'].dt.dayofweek
            df['is_weekend'] = df['day_of_week'].isin([5, 6])
        
        # Extract message length features
        text_columns = ['message', 'raw_log', 'request']
        for col in text_columns:
            if col in df.columns:
                df['message_length'] = df[col].str.len()
                df['word_count'] = df[col].str.split().str.len()
                break
        
        # Extract error indicators
        error_keywords = ['error', 'fail', 'exception', 'denied', 'timeout', 'refused', '404', '500', '503']
        for col in ['message', 'raw_log', 'request']:
            if col in df.columns:
                df['contains_error_keywords'] = df[col].str.lower().str.contains('|'.join(error_keywords), na=False)
                break
        
        # Extract IP-based features (for Apache logs)
        if 'ip_address' in df.columns:
            df['is_internal_ip'] = df['ip_address'].str.startswith(('192.168.', '10.', '172.'))
            df['ip_frequency'] = df.groupby('ip_address')['ip_address'].transform('count')
        
        # Extract status code features
        if 'status_code' in df.columns:
            df['is_error_status'] = df['status_code'].astype(str).str.startswith(('4', '5'))
        
        print(f"✅ Prepared features for {len(df)} log entries")
        return df

# Enhanced test function
def test_real_dataset():
    """Test the real dataset functionality"""
    loader = LoghubDatasetLoader()
    
    # Test with Linux dataset (smallest)
    dataset_name = 'Linux'
    
    print(f"\n🧪 Testing real dataset processing with {dataset_name}...")
    
    # Download dataset
    if loader.download_dataset(dataset_name):
        print("✅ Download successful!")
        
        # Parse logs
        df = loader.extract_and_parse_logs(dataset_name)
        if not df.empty:
            print(f"✅ Parsed {len(df)} log entries")
            print("\nSample data:")
            print(df.head())
            
            # Prepare ML features
            df_processed = loader.prepare_ml_features(df)
            print(f"✅ ML features prepared: {df_processed.shape}")
            print("Available features:", df_processed.columns.tolist())
            
            return True
        else:
            print("❌ No data parsed")
            return False
    else:
        print("❌ Download failed")
        return False

if __name__ == "__main__":
    print("✅ Created directories: ../../data/real_datasets")
    print("🚀 Real Dataset Loader initialized successfully!")
    print("Available datasets:")
    
    loader = LoghubDatasetLoader()
    for name, info in loader.datasets.items():
        print(f"  - {name}: {info['description']} ({info['size']})")
    
    # Ask user if they want to test with real data
    print(f"\n🤔 Would you like to test downloading and processing real log data?")
    print("This will download the Linux dataset (2.25MB) and process it.")
    
    response = input("Enter 'yes' to proceed or 'no' to skip: ").lower().strip()
    
    if response in ['yes', 'y']:
        success = test_real_dataset()
        if success:
            print(f"\n🎉 Real dataset integration test completed successfully!")
            print("Your DevSecOps system is now ready for real-world log analysis!")
        else:
            print(f"\n⚠️ Test encountered issues. Check the error messages above.")
    else:
        print(f"\n✅ Basic initialization test completed!")
        print("Run again and enter 'yes' when ready to test with real data.")
