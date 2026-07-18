"""
CyberTool Batch Directory Scanner Module
"""
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.logger import logger
from core.utils import calculate_hashes, calculate_file_entropy, get_file_size_str
from modules.file_analyzer import FileAnalyzer


class BatchScanner:
    """Scan entire directories for suspicious files"""

    def __init__(self, threads=4):
        self.threads = threads
        self.results = {}

    def scan_directory(self, directory, recursive=True, extensions=None):
        """Scan all files in a directory"""
        path = Path(directory)
        if not path.exists():
            return {"error": "Directory not found"}

        self.results = {
            "directory": str(path.absolute()),
            "total_files": 0,
            "scanned_files": 0,
            "suspicious_files": [],
            "errors": [],
            "summary": {
                "total_size": 0,
                "file_types": {},
                "high_entropy": 0,
                "unsigned": 0,
                "suspicious_extensions": 0,
            }
        }

        # Collect files
        if recursive:
            files = list(path.rglob("*"))
        else:
            files = list(path.iterdir())

        files = [f for f in files if f.is_file()]

        if extensions:
            files = [f for f in files if f.suffix.lower() in extensions]

        self.results["total_files"] = len(files)

        # Scan with thread pool
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_file = {
                executor.submit(self._scan_single_file, f): f
                for f in files
            }

            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    if result:
                        self.results["scanned_files"] += 1
                        self.results["suspicious_files"].append(result)
                        # Update summary
                        self.results["summary"]["total_size"] += result.get("size", 0)
                        ext = file_path.suffix.lower()
                        self.results["summary"]["file_types"][ext] = \
                            self.results["summary"]["file_types"].get(ext, 0) + 1
                        if result.get("entropy", 0) > 7:
                            self.results["summary"]["high_entropy"] += 1
                        if result.get("unsigned"):
                            self.results["summary"]["unsigned"] += 1
                except Exception as e:
                    self.results["errors"].append(str(file_path))

        # Sort by risk score
        self.results["suspicious_files"].sort(
            key=lambda x: x.get("risk_score", 0), reverse=True
        )

        logger.info("BatchScanner", f"Scanned {self.results['scanned_files']} files in {directory}")
        return self.results

    def _scan_single_file(self, file_path):
        """Scan a single file for suspicious indicators"""
        try:
            size = file_path.stat().st_size
            if size == 0:
                return None

            entropy = calculate_file_entropy(str(file_path))
            hashes = calculate_hashes(str(file_path))
            ext = file_path.suffix.lower()

            risk_score = 0
            reasons = []

            # Check entropy
            if entropy > 7.5:
                risk_score += 30
                reasons.append("Very high entropy")
            elif entropy > 6.5:
                risk_score += 15
                reasons.append("High entropy")

            # Check extension
            suspicious_exts = {'.exe', '.dll', '.scr', '.bat', '.vbs', '.ps1',
                              '.js', '.jse', '.vbe', '.wsf', '.wsh', '.msi',
                              '.msp', '.cpl', '.com', '.pif', '.hta', '.jar'}
            if ext in suspicious_exts:
                risk_score += 20
                reasons.append(f"Suspicious extension: {ext}")

            # Check size
            if size < 4096:
                risk_score += 5
                reasons.append("Very small file")

            # Check name for randomness
            from core.utils import is_random_name
            if is_random_name(file_path.name):
                risk_score += 15
                reasons.append("Randomized filename")

            # Check for suspicious paths
            path_str = str(file_path).lower()
            suspicious_paths = ['\\appdata\\', '\\temp\\', '\\downloads\\',
                                '\\desktop\\', '\\roaming\\', '\\startup\\']
            for sp in suspicious_paths:
                if sp in path_str:
                    risk_score += 10
                    reasons.append(f"Located in: {sp.strip('\\')}")
                    break

            if risk_score >= 20:
                return {
                    "file": str(file_path),
                    "name": file_path.name,
                    "size": size,
                    "size_str": get_file_size_str(size),
                    "entropy": entropy,
                    "sha256": hashes.get('sha256', ''),
                    "risk_score": min(risk_score, 100),
                    "reasons": reasons,
                    "unsigned": False,
                }
            return None

        except Exception:
            return None

    def find_duplicates(self, directory):
        """Find duplicate files by hash"""
        path = Path(directory)
        if not path.exists():
            return {"error": "Directory not found"}

        hash_map = {}
        duplicates = []

        for file_path in path.rglob("*"):
            if file_path.is_file():
                try:
                    hashes = calculate_hashes(str(file_path))
                    sha256 = hashes.get('sha256', '')
                    if sha256 in hash_map:
                        duplicates.append({
                            "original": hash_map[sha256],
                            "duplicate": str(file_path),
                            "sha256": sha256,
                        })
                    else:
                        hash_map[sha256] = str(file_path)
                except Exception:
                    continue

        return {
            "directory": str(path.absolute()),
            "total_duplicates": len(duplicates),
            "duplicates": duplicates,
        }

    def scan_by_ioc(self, directory, ioc_hashes):
        """Scan directory for files matching IOC hashes"""
        path = Path(directory)
        if not path.exists():
            return {"error": "Directory not found"}

        matches = []
        for file_path in path.rglob("*"):
            if file_path.is_file():
                try:
                    hashes = calculate_hashes(str(file_path))
                    for algo, hash_val in hashes.items():
                        if hash_val in ioc_hashes:
                            matches.append({
                                "file": str(file_path),
                                "algorithm": algo,
                                "hash": hash_val,
                            })
                            break
                except Exception:
                    continue

        return {
            "directory": str(path.absolute()),
            "ioc_matches": len(matches),
            "matches": matches,
        }