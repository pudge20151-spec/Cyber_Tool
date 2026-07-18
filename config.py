"""
CyberTool Configuration
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).parent
SIGNATURES_DIR = BASE_DIR / "signatures"
REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"

# Create directories if not exist
for d in [SIGNATURES_DIR, REPORTS_DIR, LOGS_DIR]:
    d.mkdir(exist_ok=True)

# App settings
APP_NAME = "CyberTool"
APP_VERSION = "0.1"
APP_AUTHOR = "CheckScam"

# Default settings
DEFAULT_SETTINGS = {
    "theme": "dark",
    "language": "en",
    "threads": 4,
    "timeout": 30,
    "api_keys": {},
    "proxy": "",
    "auto_update": True,
}

# Risk thresholds
RISK_THRESHOLDS = {
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 100,
}

# Suspicious API calls
SUSPICIOUS_APIS = [
    "CreateRemoteThread",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "NtOpenProcess",
    "LoadLibraryA",
    "GetProcAddress",
    "VirtualProtect",
    "CreateProcess",
    "WinExec",
    "ShellExecute",
    "RegSetValue",
    "CreateService",
    "OpenSCManager",
    "NtCreateFile",
    "DeviceIoControl",
    "CryptDecrypt",
    "CryptEncrypt",
    "InternetOpen",
    "URLDownloadToFile",
    "DeleteFile",
]

# Suspicious strings patterns
SUSPICIOUS_STRINGS = [
    "http://",
    "https://",
    "www.",
    ".exe",
    ".dll",
    ".bat",
    ".vbs",
    ".ps1",
    "cmd.exe",
    "powershell",
    "regsvr32",
    "rundll32",
    "mshta",
    "wscript",
    "cscript",
    "AppData",
    "Temp",
    "Startup",
    "Run",
    "RunOnce",
    "CurrentVersion\\Run",
    "CreateService",
    "StartService",
    "ServiceDLL",
]

# URL shorteners
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "shorturl.at", "tiny.cc", "tr.im", "cli.gs",
    "cur.lv", "q.gs", "po.st", "bc.vc", "u.to",
    "shorte.st", "adf.ly", "2.gp", "s.id", "rb.gy",
]

# IOC file patterns
IOC_PATTERNS = {
    "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "domain": r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
    "hash_md5": r"\b[a-fA-F0-9]{32}\b",
    "hash_sha1": r"\b[a-fA-F0-9]{40}\b",
    "hash_sha256": r"\b[a-fA-F0-9]{64}\b",
    "url": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*",
}