"""
CyberTool VirusTotal Integration Module
"""
import time
import requests
from core.logger import logger
from core.cache import cache


class VirusTotal:
    """Check files/hashes against VirusTotal"""

    def __init__(self, api_key=""):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {}

    def set_api_key(self, key):
        self.api_key = key
        self.headers = {"x-apikey": key}

    def _request_with_retry(self, url, max_retries=3):
        """Make request with retry logic for rate limiting"""
        retry_count = 0
        while retry_count < max_retries:
            try:
                response = requests.get(url, headers=self.headers, timeout=30)

                if response.status_code == 200:
                    return response

                elif response.status_code == 429:
                    retry_count += 1
                    wait_time = 2 ** retry_count  # 1, 2, 4 seconds
                    logger.warning("VirusTotal", f"Rate limited, waiting {wait_time}s before retry {retry_count}/{max_retries}")
                    time.sleep(wait_time)
                    continue

                elif response.status_code == 404:
                    return response

                else:
                    return response

            except requests.exceptions.ConnectionError:
                return None
            except Exception as e:
                logger.error("VirusTotal", f"Request error: {e}")
                return None

        return None  # Exhausted retries

    def check_hash(self, file_hash):
        """Check a hash against VirusTotal with retry logic"""
        if not self.api_key:
            return {"error": "No API key configured. Set in Settings > API Keys"}

        cache_key = f"vt_{file_hash}"
        cached = cache.get(cache_key)
        if cached:
            return cached

        url = f"{self.base_url}/files/{file_hash}"
        response = self._request_with_retry(url)

        if response is None:
            return {"error": "Rate limited after multiple retries or connection error"}

        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})

            stats = attributes.get("last_analysis_stats", {})
            results = attributes.get("last_analysis_results", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            harmless = stats.get("harmless", 0)

            # Get engine names that detected it
            detections = []
            for engine, result in results.items():
                if result.get("category") in ["malicious", "suspicious"]:
                    detections.append({
                        "engine": engine,
                        "result": result.get("result", ""),
                        "category": result.get("category", ""),
                    })

            info = {
                "hash": file_hash,
                "malicious": malicious,
                "suspicious": suspicious,
                "undetected": undetected,
                "harmless": harmless,
                "total_engines": malicious + suspicious + undetected + harmless,
                "detections": detections[:30],  # Limit
                "scan_date": attributes.get("last_analysis_date", ""),
                "meaningful_name": attributes.get("meaningful_name", ""),
                "type_description": attributes.get("type_description", ""),
                "tags": attributes.get("tags", []),
                "times_submitted": attributes.get("times_submitted", 0),
            }

            # Popular threat classification
            popular_threat = attributes.get("popular_threat_classification", {})
            if popular_threat:
                suggested = popular_threat.get("suggested_threat_label", "")
                info["threat_label"] = suggested

            cache.set(cache_key, info, ttl=3600)  # Cache 1 hour
            logger.info("VirusTotal", f"Checked hash: {file_hash} - {malicious}/{info['total_engines']} detections")
            return info

        elif response.status_code == 404:
            return {"hash": file_hash, "error": "Not found in VirusTotal"}
        else:
            return {"error": f"API error: {response.status_code}"}

    def get_file_report(self, file_path):
        """Upload and scan a file (or check hash first)"""
        import hashlib
        sha256 = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
            file_hash = sha256.hexdigest()
            return self.check_hash(file_hash)
        except Exception as e:
            return {"error": str(e)}

    def get_domain_report(self, domain):
        """Check a domain against VirusTotal with retry logic"""
        if not self.api_key:
            return {"error": "No API key configured"}

        cache_key = f"vt_domain_{domain}"
        cached = cache.get(cache_key)
        if cached:
            return cached

        url = f"{self.base_url}/domains/{domain}"
        response = self._request_with_retry(url)

        if response is None:
            return {"error": "Rate limited after multiple retries or connection error"}

        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})

            stats = attributes.get("last_analysis_stats", {})
            info = {
                "domain": domain,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "total_engines": sum(stats.values()),
                "categories": attributes.get("categories", {}),
                "reputation": attributes.get("reputation", 0),
            }
            cache.set(cache_key, info, ttl=3600)
            return info
        elif response.status_code == 404:
            return {"domain": domain, "error": "Not found"}
        else:
            return {"error": f"API error: {response.status_code}"}

    def get_ip_report(self, ip):
        """Check an IP against VirusTotal with retry logic"""
        if not self.api_key:
            return {"error": "No API key configured"}

        cache_key = f"vt_ip_{ip}"
        cached = cache.get(cache_key)
        if cached:
            return cached

        url = f"{self.base_url}/ip_addresses/{ip}"
        response = self._request_with_retry(url)

        if response is None:
            return {"error": "Rate limited after multiple retries or connection error"}

        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})

            stats = attributes.get("last_analysis_stats", {})
            info = {
                "ip": ip,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": sum(stats.values()),
                "country": attributes.get("country", ""),
                "asn": attributes.get("asn", ""),
                "as_owner": attributes.get("as_owner", ""),
                "reputation": attributes.get("reputation", 0),
            }
            cache.set(cache_key, info, ttl=3600)
            return info
        else:
            return {"error": f"API error: {response.status_code}"}