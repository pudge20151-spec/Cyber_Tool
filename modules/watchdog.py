"""
CyberTool Watchdog - Real-time File System Monitor
"""
import os
import time
import threading
from pathlib import Path
from datetime import datetime
from core.logger import logger
from core.utils import calculate_hashes, calculate_file_entropy


class Watchdog:
    """Monitor file system changes in real-time"""

    def __init__(self):
        self.monitoring = False
        self.thread = None
        self.callback = None
        self.watched_dirs = []
        self.snapshot = {}
        self.events = []

    def start(self, directories, callback=None, interval=2.0):
        """Start monitoring directories"""
        self.watched_dirs = [Path(d) for d in directories if Path(d).exists()]
        self.callback = callback
        self.monitoring = True
        self.events = []

        # Take initial snapshot
        self._take_snapshot()

        # Start monitoring thread
        self.thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval,),
            daemon=True
        )
        self.thread.start()
        logger.info("Watchdog", f"Started monitoring {len(self.watched_dirs)} directories")
        return {"status": "started", "directories": [str(d) for d in self.watched_dirs]}

    def stop(self):
        """Stop monitoring"""
        self.monitoring = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Watchdog", "Stopped monitoring")
        return {"status": "stopped", "total_events": len(self.events)}

    def _take_snapshot(self):
        """Take snapshot of current file system state"""
        self.snapshot = {}
        for directory in self.watched_dirs:
            for file_path in directory.rglob("*"):
                if file_path.is_file():
                    try:
                        stat = file_path.stat()
                        self.snapshot[str(file_path)] = {
                            "size": stat.st_size,
                            "mtime": stat.st_mtime,
                            "ctime": stat.st_ctime,
                        }
                    except Exception:
                        continue

    def _monitor_loop(self, interval):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                current_state = {}
                for directory in self.watched_dirs:
                    for file_path in directory.rglob("*"):
                        if file_path.is_file():
                            try:
                                stat = file_path.stat()
                                current_state[str(file_path)] = {
                                    "size": stat.st_size,
                                    "mtime": stat.st_mtime,
                                    "ctime": stat.st_ctime,
                                }
                            except Exception:
                                continue

                # Detect changes
                self._detect_changes(current_state)
                self.snapshot = current_state

            except Exception as e:
                logger.error("Watchdog", f"Monitor error: {e}")

            time.sleep(interval)

    def _detect_changes(self, current_state):
        """Detect file system changes"""
        # New files
        for path in current_state:
            if path not in self.snapshot:
                event = {
                    "type": "CREATED",
                    "path": path,
                    "timestamp": datetime.now().isoformat(),
                    "size": current_state[path]["size"],
                }
                self.events.append(event)
                if self.callback:
                    self.callback(event)
                logger.info("Watchdog", f"File created: {path}")

        # Deleted files
        for path in self.snapshot:
            if path not in current_state:
                event = {
                    "type": "DELETED",
                    "path": path,
                    "timestamp": datetime.now().isoformat(),
                }
                self.events.append(event)
                if self.callback:
                    self.callback(event)
                logger.info("Watchdog", f"File deleted: {path}")

        # Modified files
        for path in current_state:
            if path in self.snapshot:
                if current_state[path]["mtime"] != self.snapshot[path]["mtime"]:
                    event = {
                        "type": "MODIFIED",
                        "path": path,
                        "timestamp": datetime.now().isoformat(),
                        "old_size": self.snapshot[path]["size"],
                        "new_size": current_state[path]["size"],
                    }
                    self.events.append(event)
                    if self.callback:
                        self.callback(event)
                    logger.info("Watchdog", f"File modified: {path}")

    def get_events(self, event_type=None, limit=100):
        """Get monitoring events"""
        if event_type:
            filtered = [e for e in self.events if e["type"] == event_type]
        else:
            filtered = self.events
        return filtered[-limit:]

    def analyze_new_file(self, file_path):
        """Quick analysis of a newly created file"""
        path = Path(file_path)
        if not path.exists():
            return None

        hashes = calculate_hashes(file_path)
        entropy = calculate_file_entropy(file_path)
        ext = path.suffix.lower()

        suspicious_exts = {'.exe', '.dll', '.scr', '.bat', '.vbs', '.ps1',
                          '.js', '.jse', '.vbe', '.wsf', '.msi', '.cpl'}

        return {
            "file": file_path,
            "name": path.name,
            "size": path.stat().st_size,
            "hashes": hashes,
            "entropy": entropy,
            "suspicious_ext": ext in suspicious_exts,
            "risk_score": self._quick_risk(entropy, ext, path),
        }

    def _quick_risk(self, entropy, ext, path):
        """Quick risk assessment"""
        score = 0
        if entropy > 7.0:
            score += 30
        if ext in {'.exe', '.dll', '.scr', '.bat', '.vbs', '.ps1'}:
            score += 25
        if 'temp' in str(path).lower() or 'download' in str(path).lower():
            score += 15
        return min(score, 100)