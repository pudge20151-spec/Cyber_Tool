"""
CyberTool Cache Module
"""
import json
import time
from pathlib import Path
from config import BASE_DIR


class Cache:
    """Simple file-based cache with TTL"""

    def __init__(self):
        self.cache_dir = BASE_DIR / "cache"
        self.cache_dir.mkdir(exist_ok=True)
        self.default_ttl = 3600  # 1 hour

    def _get_cache_path(self, key):
        safe_key = key.replace("/", "_").replace("\\", "_").replace(":", "_")
        return self.cache_dir / f"{safe_key}.json"

    def get(self, key):
        cache_file = self._get_cache_path(key)
        if not cache_file.exists():
            return None
        try:
            data = json.loads(cache_file.read_text())
            if time.time() > data["expires"]:
                cache_file.unlink(missing_ok=True)
                return None
            return data["value"]
        except Exception:
            return None

    def set(self, key, value, ttl=None):
        if ttl is None:
            ttl = self.default_ttl
        cache_file = self._get_cache_path(key)
        data = {
            "value": value,
            "expires": time.time() + ttl,
            "created": time.time()
        }
        cache_file.write_text(json.dumps(data, indent=2))

    def clear(self):
        for f in self.cache_dir.glob("*.json"):
            f.unlink(missing_ok=True)

    def clear_expired(self):
        for f in self.cache_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text())
                if time.time() > data["expires"]:
                    f.unlink(missing_ok=True)
            except Exception:
                f.unlink(missing_ok=True)


cache = Cache()