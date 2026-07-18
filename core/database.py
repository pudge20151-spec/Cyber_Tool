"""
CyberTool Database Module - Local IOC database
"""
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from config import BASE_DIR
from core.logger import logger


class Database:
    """Local SQLite database for IOC storage"""

    def __init__(self):
        self.db_path = BASE_DIR / "cybertool.db"
        self.conn = sqlite3.connect(str(self.db_path))
        self._create_tables()

    def _create_tables(self):
        cursor = self.conn.cursor()
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS ioc_hashes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash TEXT UNIQUE NOT NULL,
                hash_type TEXT NOT NULL,
                threat_type TEXT,
                description TEXT,
                source TEXT,
                date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS ioc_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                threat_type TEXT,
                description TEXT,
                source TEXT,
                date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS ioc_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                threat_type TEXT,
                description TEXT,
                source TEXT,
                date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                result TEXT,
                risk_score INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        self.conn.commit()

    def add_hash_ioc(self, hash_value, hash_type, threat_type="unknown", description="", source="manual"):
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT OR IGNORE INTO ioc_hashes (hash, hash_type, threat_type, description, source) VALUES (?, ?, ?, ?, ?)",
                (hash_value, hash_type, threat_type, description, source)
            )
            self.conn.commit()
            return cursor.rowcount > 0
        except Exception:
            return False

    def check_hash(self, hash_value):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM ioc_hashes WHERE hash = ?", (hash_value,))
        return cursor.fetchone()

    def add_domain_ioc(self, domain, threat_type="unknown", description="", source="manual"):
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT OR IGNORE INTO ioc_domains (domain, threat_type, description, source) VALUES (?, ?, ?, ?)",
                (domain, threat_type, description, source)
            )
            self.conn.commit()
            return cursor.rowcount > 0
        except Exception:
            return False

    def check_domain(self, domain):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM ioc_domains WHERE domain = ?", (domain,))
        return cursor.fetchone()

    def add_ip_ioc(self, ip, threat_type="unknown", description="", source="manual"):
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT OR IGNORE INTO ioc_ips (ip, threat_type, description, source) VALUES (?, ?, ?, ?)",
                (ip, threat_type, description, source)
            )
            self.conn.commit()
            return cursor.rowcount > 0
        except Exception:
            return False

    def check_ip(self, ip):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM ioc_ips WHERE ip = ?", (ip,))
        return cursor.fetchone()

    def add_scan_history(self, scan_type, target, result, risk_score=0):
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO scan_history (scan_type, target, result, risk_score) VALUES (?, ?, ?, ?)",
                (scan_type, target, result, risk_score)
            )
            self.conn.commit()
        except Exception:
            pass

    def get_scan_history(self, limit=50):
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM scan_history ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )
        return cursor.fetchall()

    def load_ioc_from_file(self, file_path):
        """Load IOC from CSV file (format: hash,type,description,source)"""
        try:
            import csv
            with open(file_path, 'r') as f:
                reader = csv.DictReader(f)
                count = 0
                for row in reader:
                    hash_val = row.get('hash') or row.get('ioc')
                    threat_type = row.get('type', 'unknown')
                    desc = row.get('description', '')
                    source = row.get('source', 'csv_import')
                    
                    if hash_val:
                        self.add_hash_ioc(hash_val, 'unknown', threat_type, desc, source)
                        count += 1
            logger.info("Database", f"Loaded {count} IOC from {file_path}")
            return count
        except Exception as e:
            logger.error("Database", f"Failed to load IOC: {e}")
            return 0

    def load_ioc_from_url(self, url, ioc_type='hash'):
        """Load IOC from public feed (e.g., abuse.ch, PhishTank)"""
        try:
            import requests
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                lines = response.text.strip().split('\n')
                count = 0
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if ioc_type == 'hash':
                            self.add_hash_ioc(line, 'sha256', 'malware', f'from {url}', 'public_feed')
                        elif ioc_type == 'domain':
                            self.add_domain_ioc(line, 'phishing', f'from {url}', 'public_feed')
                        elif ioc_type == 'ip':
                            self.add_ip_ioc(line, 'malicious', f'from {url}', 'public_feed')
                        count += 1
                logger.info("Database", f"Loaded {count} IOC from {url}")
                return count
            return 0
        except Exception as e:
            logger.error("Database", f"Failed to load IOC from URL: {e}")
            return 0

    def close(self):
        self.conn.close()


db = Database()
