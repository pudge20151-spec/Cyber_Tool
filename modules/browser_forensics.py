"""
CyberTool Browser Forensics Module
"""
import os
import json
import sqlite3
import shutil
from pathlib import Path
from datetime import datetime, timedelta
from core.logger import logger


class BrowserForensics:
    """Extract and analyze browser artifacts"""

    def __init__(self):
        self.results = {}
        self.temp_dir = Path(os.environ.get("TEMP", "/tmp")) / "cybertool_browser"

    def analyze(self):
        """Analyze all browsers"""
        self.results = {
            "browsers_found": [],
            "history": [],
            "downloads": [],
            "cookies": [],
            "bookmarks": [],
            "extensions": [],
            "saved_passwords_warning": [],
            "suspicious_entries": [],
        }

        self.temp_dir.mkdir(exist_ok=True)

        # Check Chrome/Edge/Brave
        self._analyze_chromium("Chrome", self._get_chrome_path())
        self._analyze_chromium("Edge", self._get_edge_path())
        self._analyze_chromium("Brave", self._get_brave_path())
        self._analyze_chromium("Opera", self._get_opera_path())

        # Check Firefox
        self._analyze_firefox()

        # Cleanup
        shutil.rmtree(self.temp_dir, ignore_errors=True)

        logger.info("BrowserForensics", f"Analyzed {len(self.results['browsers_found'])} browsers")
        return self.results

    def _get_chrome_path(self):
        local = Path(os.environ.get("LOCALAPPDATA", ""))
        return local / "Google" / "Chrome" / "User Data"

    def _get_edge_path(self):
        local = Path(os.environ.get("LOCALAPPDATA", ""))
        return local / "Microsoft" / "Edge" / "User Data"

    def _get_brave_path(self):
        local = Path(os.environ.get("LOCALAPPDATA", ""))
        return local / "BraveSoftware" / "Brave-Browser" / "User Data"

    def _get_opera_path(self):
        appdata = Path(os.environ.get("APPDATA", ""))
        return appdata / "Opera Software" / "Opera Stable"

    def _analyze_chromium(self, name, profile_path):
        """Analyze Chromium-based browser"""
        if not profile_path.exists():
            return

        self.results["browsers_found"].append(name)

        # Check Default profile
        default_path = profile_path / "Default"
        if not default_path.exists():
            return

        # History
        try:
            history_db = default_path / "History"
            if history_db.exists():
                entries = self._parse_chromium_history(history_db)
                self.results["history"].extend([
                    {**e, "browser": name} for e in entries
                ])
                self._check_suspicious_urls(entries, name)
        except Exception:
            pass

        # Downloads
        try:
            history_db = default_path / "History"
            if history_db.exists():
                downloads = self._parse_chromium_downloads(history_db)
                self.results["downloads"].extend([
                    {**d, "browser": name} for d in downloads
                ])
        except Exception:
            pass

        # Bookmarks
        try:
            bookmarks_file = default_path / "Bookmarks"
            if bookmarks_file.exists():
                bookmarks = self._parse_chromium_bookmarks(bookmarks_file)
                self.results["bookmarks"].extend([
                    {**b, "browser": name} for b in bookmarks
                ])
        except Exception:
            pass

        # Extensions
        try:
            extensions_dir = default_path / "Extensions"
            if extensions_dir.exists():
                extensions = self._list_extensions(extensions_dir)
                self.results["extensions"].extend([
                    {**e, "browser": name} for e in extensions
                ])
        except Exception:
            pass

    def _parse_chromium_history(self, db_path):
        """Parse Chromium history database"""
        entries = []
        try:
            # Copy to temp to avoid locks
            temp_db = self.temp_dir / f"history_{db_path.parent.name}.db"
            shutil.copy2(db_path, temp_db)

            conn = sqlite3.connect(str(temp_db))
            cursor = conn.cursor()
            cursor.execute("""
                SELECT url, title, visit_count, last_visit_time
                FROM urls ORDER BY last_visit_time DESC LIMIT 200
            """)

            for row in cursor.fetchall():
                entries.append({
                    "url": row[0],
                    "title": row[1] or "",
                    "visit_count": row[2],
                    "last_visit": self._chrome_time_to_datetime(row[3]),
                })
            conn.close()
            temp_db.unlink(missing_ok=True)

        except Exception:
            pass

        return entries

    def _parse_chromium_downloads(self, db_path):
        """Parse Chromium downloads"""
        downloads = []
        try:
            temp_db = self.temp_dir / f"downloads_{db_path.parent.name}.db"
            shutil.copy2(db_path, temp_db)

            conn = sqlite3.connect(str(temp_db))
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT target_path, url, start_time, received_bytes, total_bytes
                    FROM downloads ORDER BY start_time DESC LIMIT 100
                """)
                for row in cursor.fetchall():
                    downloads.append({
                        "path": row[0],
                        "url": row[1],
                        "time": self._chrome_time_to_datetime(row[2]),
                        "size": f"{row[3]}/{row[4]} bytes" if row[4] else f"{row[3]} bytes",
                    })
            except Exception:
                pass
            conn.close()
            temp_db.unlink(missing_ok=True)

        except Exception:
            pass

        return downloads

    def _parse_chromium_bookmarks(self, bookmarks_file):
        """Parse Chromium bookmarks"""
        bookmarks = []
        try:
            data = json.loads(bookmarks_file.read_text(encoding='utf-8'))
            roots = data.get("roots", {})

            def extract_bookmarks(node, folder=""):
                items = []
                if node.get("type") == "folder":
                    folder_name = node.get("name", folder)
                    for child in node.get("children", []):
                        items.extend(extract_bookmarks(child, folder_name))
                elif node.get("type") == "url":
                    items.append({
                        "name": node.get("name", ""),
                        "url": node.get("url", ""),
                        "folder": folder,
                    })
                return items

            for root_name, root_node in roots.items():
                bookmarks.extend(extract_bookmarks(root_node))

        except Exception:
            pass

        return bookmarks

    def _list_extensions(self, extensions_dir):
        """List installed extensions"""
        extensions = []
        try:
            for ext_id in extensions_dir.iterdir():
                if ext_id.is_dir():
                    # Try to get manifest
                    versions = list(ext_id.iterdir())
                    if versions:
                        manifest_file = versions[0] / "manifest.json"
                        if manifest_file.exists():
                            try:
                                manifest = json.loads(manifest_file.read_text(encoding='utf-8'))
                                extensions.append({
                                    "id": ext_id.name,
                                    "name": manifest.get("name", "Unknown"),
                                    "version": manifest.get("version", "Unknown"),
                                    "permissions": manifest.get("permissions", []),
                                })
                            except Exception:
                                extensions.append({
                                    "id": ext_id.name,
                                    "name": "Unknown",
                                    "version": "Unknown",
                                    "permissions": [],
                                })
        except Exception:
            pass

        return extensions

    def _analyze_firefox(self):
        """Analyze Firefox browser"""
        appdata = Path(os.environ.get("APPDATA", ""))
        firefox_path = appdata / "Mozilla" / "Firefox" / "Profiles"

        if not firefox_path.exists():
            return

        self.results["browsers_found"].append("Firefox")

        for profile in firefox_path.iterdir():
            if profile.is_dir():
                # Places.sqlite (history + bookmarks)
                places_db = profile / "places.sqlite"
                if places_db.exists():
                    try:
                        temp_db = self.temp_dir / f"firefox_places.db"
                        shutil.copy2(places_db, temp_db)

                        conn = sqlite3.connect(str(temp_db))
                        cursor = conn.cursor()
                        try:
                            cursor.execute("""
                                SELECT url, title, visit_count
                                FROM moz_places
                                ORDER BY last_visit_date DESC LIMIT 200
                            """)
                            for row in cursor.fetchall():
                                self.results["history"].append({
                                    "url": row[0],
                                    "title": row[1] or "",
                                    "visit_count": row[2],
                                    "browser": "Firefox",
                                })
                        except Exception:
                            pass
                        conn.close()
                        temp_db.unlink(missing_ok=True)
                    except Exception:
                        pass

    def _chrome_time_to_datetime(self, chrome_time):
        """Convert Chrome time format to datetime"""
        if not chrome_time:
            return ""
        try:
            # Chrome time is microseconds since 1601-01-01
            epoch_start = datetime(1601, 1, 1)
            return (epoch_start + timedelta(microseconds=chrome_time)).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return str(chrome_time)

    def _check_suspicious_urls(self, entries, browser_name):
        """Check for suspicious URLs in history"""
        suspicious_keywords = [
            "login", "secure", "account", "verify", "update",
            "banking", "paypal", "bitcoin", "wallet", "password",
            "admin", "webmail", "mail.", "bank", "transfer",
        ]
        suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top"]

        for entry in entries[:50]:
            url = entry.get("url", "").lower()
            reasons = []

            # Check for suspicious keywords in URL
            for kw in suspicious_keywords:
                if kw in url:
                    reasons.append(f"Contains '{kw}'")

            # Check TLD
            for tld in suspicious_tlds:
                if tld in url:
                    reasons.append(f"Suspicious TLD: {tld}")

            if reasons:
                self.results["suspicious_entries"].append({
                    "url": entry["url"],
                    "browser": browser_name,
                    "reasons": reasons[:3],
                    "visit_count": entry.get("visit_count", 0),
                })