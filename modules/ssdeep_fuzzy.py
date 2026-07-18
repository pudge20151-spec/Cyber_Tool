"""
CyberTool SSDEEP Fuzzy Hashing Module
"""
import os
import math
from core.logger import logger


class SSDEEP:
    """Fuzzy hashing for similarity matching (SSDEEP-like)"""

    def __init__(self):
        self.results = {}

    def hash_file(self, file_path):
        """Generate a fuzzy hash for a file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            result = self._fuzzy_hash(data)
            return result if result else ""
        except Exception as e:
            return ""

    def _fuzzy_hash(self, data):
        """Generate fuzzy hash using context-triggered piecewise hashing"""
        if not data:
            return ""

        # Calculate block size based on file size
        file_size = len(data)
        block_size = self._get_block_size(file_size)

        # Generate hash
        chunks = []
        for i in range(0, file_size, block_size):
            chunk = data[i:i + block_size]
            chunk_hash = self._hash_chunk(chunk)
            chunks.append(chunk_hash)

        # Create signature
        if chunks:
            signature = f"{block_size}:{''.join(chunks[:64])}"
            return signature
        return ""

    def _get_block_size(self, file_size):
        """Determine optimal block size"""
        if file_size < 256:
            return 4
        elif file_size < 1024:
            return 16
        elif file_size < 4096:
            return 64
        elif file_size < 16384:
            return 256
        elif file_size < 65536:
            return 1024
        elif file_size < 262144:
            return 4096
        else:
            return 16384

    def _hash_chunk(self, data):
        """Simple hash for a chunk of data"""
        if not data:
            return "0"

        hash_val = 0
        for byte in data:
            hash_val = ((hash_val << 5) - hash_val) + byte
            hash_val &= 0xFFFFFFFF

        # Convert to base64-like character
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
        return chars[hash_val % len(chars)]

    def compare(self, hash1, hash2):
        """Compare two fuzzy hashes and return similarity score (0-100)"""
        if not hash1 or not hash2:
            return 0

        try:
            # Parse signatures
            parts1 = hash1.split(':')
            parts2 = hash2.split(':')

            if len(parts1) < 2 or len(parts2) < 2:
                return 0

            block_size1 = int(parts1[0])
            block_size2 = int(parts2[0])
            sig1 = parts1[1]
            sig2 = parts2[1]

            # Compare block sizes
            if abs(block_size1 - block_size2) > max(block_size1, block_size2) // 2:
                return 0

            # Compare strings
            score = self._string_similarity(sig1, sig2)
            return score

        except Exception:
            return 0

    def _string_similarity(self, s1, s2):
        """Calculate string similarity using Dice coefficient"""
        if not s1 or not s2:
            return 0

        # Create bigrams
        def get_bigrams(s):
            return set(s[i:i+2] for i in range(len(s)-1))

        bigrams1 = get_bigrams(s1)
        bigrams2 = get_bigrams(s2)

        if not bigrams1 or not bigrams2:
            return 0

        # Dice coefficient
        intersection = len(bigrams1 & bigrams2)
        total = len(bigrams1) + len(bigrams2)
        if total == 0:
            return 0

        return int((2.0 * intersection / total) * 100)

    def find_similar_files(self, target_hash, hash_database, threshold=50):
        """Find files with similar fuzzy hashes"""
        similar = []
        for file_path, file_hash in hash_database.items():
            score = self.compare(target_hash, file_hash)
            if score >= threshold:
                similar.append({
                    "file": file_path,
                    "similarity": score,
                })

        similar.sort(key=lambda x: x["similarity"], reverse=True)
        return similar

    def scan_directory(self, directory):
        """Generate fuzzy hashes for all files in a directory"""
        from pathlib import Path
        path = Path(directory)
        if not path.exists():
            return {"error": "Directory not found"}

        results = {}
        for file_path in path.rglob("*"):
            if file_path.is_file():
                try:
                    fhash = self.hash_file(str(file_path))
                    if fhash and "error" not in fhash:
                        results[str(file_path)] = fhash
                except Exception:
                    continue

        return {
            "directory": directory,
            "files_hashed": len(results),
            "hashes": results,
        }