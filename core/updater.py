"""
CyberTool Updater Module
"""
import json
import requests
from datetime import datetime
from core.logger import logger
from config import APP_VERSION


class Updater:
    """Check for updates"""

    def __init__(self):
        self.update_url = "https://api.github.com/repos/cybertool/cybertool/releases/latest"

    def check(self):
        """Check for updates"""
        try:
            response = requests.get(self.update_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                latest_version = data.get("tag_name", "").lstrip("v")
                # Compare versions properly using tuple comparison
                if self._compare_versions(latest_version, APP_VERSION) > 0:
                    return {
                        "update_available": True,
                        "current_version": APP_VERSION,
                        "latest_version": latest_version,
                        "download_url": data.get("html_url", ""),
                        "release_notes": data.get("body", "")[:500],
                    }
            return {"update_available": False, "current_version": APP_VERSION}
        except Exception:
            return {"update_available": False, "current_version": APP_VERSION, "error": "Could not check for updates"}

    def _compare_versions(self, v1, v2):
        """Compare two version strings (e.g., '1.2.3' vs '1.2.4')"""
        try:
            parts1 = [int(x) for x in v1.split('.')]
            parts2 = [int(x) for x in v2.split('.')]
            
            # Pad shorter version with zeros
            while len(parts1) < len(parts2):
                parts1.append(0)
            while len(parts2) < len(parts1):
                parts2.append(0)
            
            # Compare each part
            for p1, p2 in zip(parts1, parts2):
                if p1 > p2:
                    return 1
                elif p1 < p2:
                    return -1
            return 0
        except Exception:
            # Fallback to string comparison if parsing fails
            return 1 if v1 > v2 else -1 if v1 < v2 else 0
