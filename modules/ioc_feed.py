"""
CyberTool IOC Feed Importer Module
"""
import json
import csv
import re
import requests
from pathlib import Path
from datetime import datetime
from core.logger import logger
from core.database import db
from config import IOC_PATTERNS


class IOCFeed:
    """Import threat intelligence feeds"""

    def __init__(self):
        self.results = {}

    def import_from_file(self, file_path, feed_type="auto"):
        """Import IOCs from a file"""
        path = Path(file_path)
        if not path.exists():
            return {"error": "File not found"}

        self.results = {
            "file": str(path),
            "imported": 0,
            "skipped": 0,
            "errors": [],
            "iocs": [],
        }

        try:
            content = path.read_text(encoding='utf-8', errors='ignore')

            if feed_type == "auto":
                feed_type = self._detect_format(path, content)

            if feed_type == "json":
                self._parse_json(content)
            elif feed_type == "csv":
                self._parse_csv(content)
            elif feed_type == "txt":
                self._parse_txt(content)
            elif feed_type == "stix":
                self._parse_stix(content)
            elif feed_type == "openioc":
                self._parse_openioc(content)
            else:
                self._parse_txt(content)

            logger.info("IOCFeed", f"Imported {self.results['imported']} IOCs from {file_path}")

        except Exception as e:
            self.results["errors"].append(str(e))

        return self.results

    def _detect_format(self, path, content):
        """Auto-detect IOC format"""
        ext = path.suffix.lower()
        if ext == '.json':
            return "json"
        elif ext == '.csv':
            return "csv"
        elif ext == '.txt':
            return "txt"
        elif ext == '.xml':
            if 'ioc' in content[:500].lower():
                return "openioc"
            return "txt"
        elif 'stix' in content[:500].lower():
            return "stix"
        return "txt"

    def _parse_json(self, content):
        """Parse JSON IOC format"""
        try:
            data = json.loads(content)
            if isinstance(data, list):
                for item in data:
                    self._process_ioc_item(item)
            elif isinstance(data, dict):
                if "objects" in data:  # STIX-like
                    for obj in data["objects"]:
                        self._process_ioc_item(obj)
                else:
                    self._process_ioc_item(data)
        except json.JSONDecodeError:
            self.results["errors"].append("Invalid JSON")

    def _parse_csv(self, content):
        """Parse CSV IOC format"""
        reader = csv.DictReader(content.splitlines())
        for row in reader:
            self._process_ioc_item(row)

    def _parse_txt(self, content):
        """Parse plain text IOC format"""
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            self._process_ioc_value(line)

    def _parse_stix(self, content):
        """Parse STIX format"""
        try:
            data = json.loads(content)
            for obj in data.get("objects", []):
                if obj.get("type") == "indicator":
                    pattern = obj.get("pattern", "")
                    self._extract_stix_pattern(pattern)
        except Exception:
            self.results["errors"].append("Failed to parse STIX")

    def _parse_openioc(self, content):
        """Parse OpenIOC format"""
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(content)
            for indicator in root.iter('IndicatorItem'):
                value = indicator.findtext('.//Content', '')
                if value:
                    self._process_ioc_value(value)
        except Exception:
            self.results["errors"].append("Failed to parse OpenIOC")

    def _process_ioc_item(self, item):
        """Process a single IOC item from structured data"""
        if isinstance(item, dict):
            # Try common field names
            for field in ['indicator', 'value', 'ip', 'domain', 'hash',
                          'md5', 'sha1', 'sha256', 'url', 'hostname']:
                if field in item:
                    value = item[field]
                    if value:
                        self._process_ioc_value(str(value))
                        break

    def _process_ioc_value(self, value):
        """Process a single IOC value"""
        value = value.strip().strip('"').strip("'")

        # Check if it's a hash
        if re.match(r'^[a-fA-F0-9]{32}$', value):
            if db.add_hash_ioc(value, "md5"):
                self.results["imported"] += 1
                self.results["iocs"].append({"type": "md5", "value": value})
            return

        if re.match(r'^[a-fA-F0-9]{40}$', value):
            if db.add_hash_ioc(value, "sha1"):
                self.results["imported"] += 1
                self.results["iocs"].append({"type": "sha1", "value": value})
            return

        if re.match(r'^[a-fA-F0-9]{64}$', value):
            if db.add_hash_ioc(value, "sha256"):
                self.results["imported"] += 1
                self.results["iocs"].append({"type": "sha256", "value": value})
            return

        # Check if it's an IP
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
            if db.add_ip_ioc(value):
                self.results["imported"] += 1
                self.results["iocs"].append({"type": "ip", "value": value})
            return

        # Check if it's a domain
        if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            if db.add_domain_ioc(value):
                self.results["imported"] += 1
                self.results["iocs"].append({"type": "domain", "value": value})
            return

        self.results["skipped"] += 1

    def _extract_stix_pattern(self, pattern):
        """Extract IOCs from STIX pattern"""
        # Simple STIX pattern parser
        ip_match = re.findall(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern)
        for ip in ip_match:
            self._process_ioc_value(ip)

        domain_match = re.findall(r"domain-name:value\s*=\s*'([^']+)'", pattern)
        for domain in domain_match:
            self._process_ioc_value(domain)

        hash_match = re.findall(r"file:hashes\.(md5|sha1|sha256)\s*=\s*'([^']+)'", pattern)
        for algo, hash_val in hash_match:
            self._process_ioc_value(hash_val)

    def fetch_remote_feed(self, url):
        """Fetch IOCs from a remote feed URL"""
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                content = response.text
                # Save to temp file and import
                temp_file = Path("temp_ioc_feed.txt")
                temp_file.write_text(content)
                result = self.import_from_file(str(temp_file))
                temp_file.unlink(missing_ok=True)
                return result
            return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def export_iocs(self, output_file, ioc_type=None):
        """Export IOCs from database to file"""
        from core.database import db
        path = Path(output_file)
        ext = path.suffix.lower()

        iocs = []
        # Get from database
        try:
            # Export hashes
            cursor = db.conn.cursor()
            cursor.execute("SELECT hash, hash_type, threat_type, description FROM ioc_hashes")
            for row in cursor.fetchall():
                iocs.append({
                    "type": row[1],
                    "value": row[0],
                    "threat_type": row[2],
                    "description": row[3]
                })
            
            # Export domains
            cursor.execute("SELECT domain, threat_type, description FROM ioc_domains")
            for row in cursor.fetchall():
                iocs.append({
                    "type": "domain",
                    "value": row[0],
                    "threat_type": row[1],
                    "description": row[2]
                })
            
            # Export IPs
            cursor.execute("SELECT ip, threat_type, description FROM ioc_ips")
            for row in cursor.fetchall():
                iocs.append({
                    "type": "ip",
                    "value": row[0],
                    "threat_type": row[1],
                    "description": row[2]
                })
        except Exception as e:
            return {"error": f"Failed to export IOCs: {str(e)}"}

        if ext == '.json':
            path.write_text(json.dumps(iocs, indent=2))
        elif ext == '.csv':
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=["type", "value", "threat_type", "description"])
                writer.writeheader()
                writer.writerows(iocs)

        return {"exported": len(iocs), "file": str(path)}
