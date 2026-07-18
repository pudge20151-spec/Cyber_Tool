"""
CyberTool Database Module - Local IOC database
"""
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from config import BASE_DIR


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

    def close(self):
        self.conn.close()


db = Database()