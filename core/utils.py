"""
CyberTool Utilities Module
"""
import hashlib
import math
import re
from pathlib import Path


def calculate_hashes(file_path):
    """Calculate MD5, SHA1, SHA256, SHA512 hashes of a file"""
    hashes = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256(),
        'sha512': hashlib.sha512(),
    }
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                for h in hashes.values():
                    h.update(chunk)
        return {name: h.hexdigest() for name, h in hashes.items()}
    except Exception:
        return {}


def calculate_entropy(data):
    """Calculate Shannon entropy of data"""
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return round(entropy, 2)


def calculate_file_entropy(file_path):
    """Calculate entropy of a file"""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        return calculate_entropy(data)
    except Exception:
        return 0.0


def get_file_size_str(size_bytes):
    """Convert bytes to human readable string"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


def extract_strings(file_path, min_length=4):
    """Extract ASCII and Unicode strings from a file"""
    strings = []
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        # ASCII strings
        current = b""
        for byte in data:
            if 32 <= byte <= 126:
                current += bytes([byte])
            else:
                if len(current) >= min_length:
                    strings.append(current.decode('ascii', errors='ignore'))
                current = b""
        if len(current) >= min_length:
            strings.append(current.decode('ascii', errors='ignore'))

        # Unicode strings (UTF-16LE)
        current = b""
        i = 0
        while i < len(data) - 1:
            if data[i] >= 32 and data[i] <= 126 and data[i+1] == 0:
                current += bytes([data[i]])
                i += 2
            else:
                if len(current) >= min_length:
                    strings.append(current.decode('ascii', errors='ignore'))
                current = b""
                i += 1
        if len(current) >= min_length:
            strings.append(current.decode('ascii', errors='ignore'))

    except Exception:
        pass

    return strings


def find_suspicious_strings(strings, patterns):
    """Find suspicious strings based on patterns"""
    found = []
    for s in strings:
        for pattern in patterns:
            if pattern.lower() in s.lower():
                if s not in found:
                    found.append(s)
    return found


def is_suspicious_filename(name):
    """Check if filename looks suspicious"""
    suspicious_patterns = [
        r'\.exe$', r'\.scr$', r'\.pif$', r'\.com$', r'\.bat$',
        r'\.vbs$', r'\.ps1$', r'\.js$', r'\.jse$', r'\.vbe$',
        r'\.wsf$', r'\.wsh$', r'\.msi$', r'\.msp$', r'\.cpl$',
    ]
    name_lower = name.lower()
    for pattern in suspicious_patterns:
        if re.search(pattern, name_lower):
            return True
    return False


def is_random_name(name):
    """Check if filename looks randomly generated"""
    stem = Path(name).stem
    if len(stem) < 6:
        return False
    # Check for high entropy in name
    entropy = calculate_entropy(stem.encode())
    return entropy > 3.5


def format_timestamp(ts):
    """Format timestamp to string"""
    if ts:
        return ts.strftime("%Y-%m-%d %H:%M:%S")
    return "N/A"