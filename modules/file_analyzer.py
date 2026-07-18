"""
CyberTool File Analyzer Module
"""
import os
import magic
from datetime import datetime
from pathlib import Path
from core.utils import (
    calculate_hashes, calculate_file_entropy, get_file_size_str,
    extract_strings, find_suspicious_strings
)
from config import SUSPICIOUS_STRINGS, SUSPICIOUS_APIS
from core.logger import logger


class FileAnalyzer:
    """Analyze files for suspicious characteristics"""

    def __init__(self):
        self.results = {}

    def analyze(self, file_path):
        """Perform full file analysis"""
        path = Path(file_path)
        if not path.exists():
            return {"error": "File not found"}

        self.results = {
            "filename": path.name,
            "file_path": str(path.absolute()),
            "size": path.stat().st_size,
            "size_str": get_file_size_str(path.stat().st_size),
        }

        # Hashes
        hashes = calculate_hashes(file_path)
        self.results.update(hashes)

        # Entropy
        self.results["entropy"] = calculate_file_entropy(file_path)

        # File type
        try:
            mime = magic.Magic(mime=True)
            self.results["mime_type"] = mime.from_file(str(file_path))
            desc = magic.Magic()
            self.results["file_type"] = desc.from_file(str(file_path))
        except Exception:
            self.results["mime_type"] = "N/A"
            self.results["file_type"] = "N/A"

        # Timestamps
        stat = path.stat()
        self.results["created"] = datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S")
        self.results["modified"] = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        self.results["accessed"] = datetime.fromtimestamp(stat.st_atime).strftime("%Y-%m-%d %H:%M:%S")

        # Strings analysis
        strings = extract_strings(file_path)
        self.results["total_strings"] = len(strings)
        suspicious = find_suspicious_strings(strings, SUSPICIOUS_STRINGS)
        self.results["suspicious_strings"] = suspicious[:50]  # Limit to 50

        # API calls detection
        apis_found = find_suspicious_strings(strings, SUSPICIOUS_APIS)
        self.results["suspicious_apis"] = apis_found[:30]

        # Packer detection (heuristic)
        self.results["packed"] = self._detect_packer(strings)

        # Digital signature check
        self.results["digital_signature"] = self._check_signature(file_path)

        logger.info("FileAnalyzer", f"Analyzed file: {path.name}")
        return self.results

    def _detect_packer(self, strings):
        """Heuristic packer detection"""
        packer_indicators = [
            "UPX", "UPX0", "UPX1", "UPX2", "UPX!", "MPRESS",
            "ASPack", "PECompact", "PEBundle",
            "Enigma", "VMProtect", "Themida", "Armadillo",
            "NSIS", "Inno", "RAR!", "PKZIP", "7zX",
        ]
        found = []
        for s in strings:
            for indicator in packer_indicators:
                if indicator.lower() in s.lower():
                    if indicator not in found:
                        found.append(indicator)
        return found

    def _check_signature(self, file_path):
        """Check digital signature (basic check)"""
        try:
            import subprocess
            result = subprocess.run(
                ["powershell", "-Command", f"Get-AuthenticodeSignature '{file_path}' | Select-Object -ExpandProperty Status"],
                capture_output=True, text=True, timeout=10
            )
            status = result.stdout.strip()
            if status:
                return status
            return "Not signed"
        except Exception:
            return "Unable to check"