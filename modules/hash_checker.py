"""
CyberTool Hash Checker Module
"""
from core.utils import calculate_hashes
from core.database import db
from core.logger import logger


class HashChecker:
    """Calculate and check file hashes against IOC database"""

    def __init__(self):
        self.results = {}

    def check(self, file_path):
        """Calculate hashes and check against IOC database"""
        hashes = calculate_hashes(file_path)
        if not hashes:
            return {"error": "Unable to calculate hashes"}

        self.results = {
            "hashes": hashes,
            "ioc_matches": {}
        }

        # Check each hash against IOC database
        for hash_type, hash_value in hashes.items():
            match = db.check_hash(hash_value)
            if match:
                self.results["ioc_matches"][hash_type] = {
                    "hash": match[1],
                    "threat_type": match[3],
                    "description": match[4],
                    "source": match[5]
                }

        self.results["malicious"] = len(self.results["ioc_matches"]) > 0
        logger.info("HashChecker", f"Checked hashes for {file_path}")
        return self.results

    def check_hash_value(self, hash_value):
        """Check a hash value directly against IOC database"""
        match = db.check_hash(hash_value)
        if match:
            return {
                "hash": match[1],
                "hash_type": match[2],
                "threat_type": match[3],
                "description": match[4],
                "source": match[5]
            }
        return None