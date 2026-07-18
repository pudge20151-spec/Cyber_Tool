# CyberTool

**CyberTool** - Advanced Cybersecurity Analysis Toolkit

A comprehensive command-line cybersecurity tool for analyzing files, URLs, IPs, networks, and detecting potential threats. Features both English and Russian language support.

## Description

CyberTool is a modular security analysis toolkit designed for forensic analysis, malware detection, and threat intelligence gathering. It provides a unified interface for various cybersecurity tasks with an interactive menu system.

## Features

### File Analysis
- Calculate file hashes (MD5, SHA1, SHA256, SHA512)
- File type and MIME detection
- Entropy analysis for packed/encrypted content
- Suspicious string detection
- PE (Portable Executable) file analysis
- Digital signature verification

### URL Analysis
- URL parsing and structure analysis
- Phishing and typosquatting detection
- Security headers analysis
- SSL/TLS certificate inspection
- Redirect chain tracking
- Content analysis

### IP Intelligence
- Geolocation and network information
- DNSBL (DNS Blacklist) checking
- Proxy/VPN/Tor detection
- WHOIS lookup
- Reputation scoring

### Network Scanner
- Ping and port scanning
- Network sweep
- Traceroute
- OS detection

### Process Monitor
- Process listing
- Suspicious process detection
- CPU usage analysis

### Advanced Features
- YARA scanning for malware detection
- VirusTotal integration
- IOC (Indicators of Compromise) feed
- Correlation engine
- Browser forensics
- USB forensics
- Memory analysis
- Fraud detection
- Fuzzy hashing (SSDEEP)

## Modules

| Module | Description |
|--------|-------------|
| `file_analyzer.py` | File hashing and metadata extraction |
| `url_analyzer.py` | URL reputation and phishing detection |
| `ip_lookup.py` | IP geolocation and threat intelligence |
| `network.py` | Network scanning and reconnaissance |
| `process_monitor.py` | Process enumeration and analysis |
| `yara_scanner.py` | YARA rule-based malware scanning |
| `pe_analyzer.py` | PE executable analysis |
| `virustotal.py` | VirusTotal API integration |
| `batch_scanner.py` | Bulk file analysis |
| `ioc_feed.py` | Threat intelligence feeds |
| `correlation.py` | Cross-reference analysis |
| `browser_forensics.py` | Browser artifact analysis |
| `usb_forensics.py` | USB device forensics |
| `memory.py` | Memory dump analysis |
| `fraud_detector.py` | Fraud detection module |
| `ssdeep_fuzzy.py` | Fuzzy hashing engine |

## Requirements

- Python 3.8+
- See `requirements.txt` for dependencies:

```
rich==13.7.0
psutil==5.9.8
pefile==2023.2.7
lief==0.14.1
yara-python==4.5.0
python-magic==0.4.27
python-magic-bin==0.4.14
dnspython==2.6.1
python-whois==0.9.4
requests==2.31.0
scapy==2.5.0
cryptography==42.0.5
colorama==0.4.6
pyOpenSSL==24.1.0
```

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/cybertool.git
cd cybertool

# Install dependencies
pip install -r requirements.txt

# Run the tool
python main.py
```

Or on Windows, simply run:
```bash
run.bat
```

## Usage

Run CyberTool from the command line:

```bash
python main.py
```

On first launch, you'll be prompted to select your language (English or Russian).

### Example Run

```
╭────────────────────────────── CyberTool 0.1 ──────────────────────────────╮
│  Select Language / Выберите язык                                           │
│                                                                           │
│  1. English                                                               │
│  2. Russian                                                               │
╰───────────────────────────────────────────────────────────────────────────╯

Select language [1]: 1

======================================
1. File Analysis          2. URL Analysis
3. IP Intelligence        4. Network Scan
5. Process Monitor        6. Yara Scan
7. PE Analyzer            8. Hash Checker

======================================
Select option [1-9]: 
```

### Example Report

```
File: suspicious.exe
Path: C:\samples\suspicious.exe
Size: 245.00 KB

File Hashes:
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Algorithm ┃ Hash                                                            ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ MD5      │ a1b2c3d4e5f678901234567890123456                                │
│ SHA256   │ abc123def456...                                                  │
└──────────┴───────────────────────────────────────────────────────────────────┘

Risk Score: 45%
####################----------------------------------------
Overall Risk: MEDIUM

Reasons:
  X High entropy
  X Suspicious strings found (12)
  X Suspicious API calls detected
```

## Directory Structure

```
CyberTool/
├── main.py              # Main entry point
├── config.py            # Configuration settings
├── locale.py            # Multi-language support
├── requirements.txt     # Python dependencies
├── run.bat              # Windows launcher
├── .gitignore           # Git ignore rules
├── LICENSE              # MIT License
├── modules/             # Analysis modules
│   ├── autoruns.py
│   ├── batch_scanner.py
│   ├── browser_forensics.py
│   ├── correlation.py
│   ├── dns_lookup.py
│   ├── email_checker.py
│   ├── file_analyzer.py
│   ├── fraud_detector.py
│   ├── hash_checker.py
│   ├── ioc_feed.py
│   ├── ip_lookup.py
│   ├── memory.py
│   ├── network.py
│   ├── pe_analyzer.py
│   ├── process_monitor.py
│   ├── report.py
│   ├── ssdeep_fuzzy.py
│   ├── startup_checker.py
│   ├── url_analyzer.py
│   ├── usb_forensics.py
│   ├── virustotal.py
│   ├── watchdog.py
│   ├── whois.py
│   ├── yara_scanner.py
│   └── __init__.py
├── core/               # Core functionality
│   ├── __init__.py
│   ├── cache.py
│   ├── database.py
│   ├── logger.py
│   ├── updater.py
│   └── utils.py
└── signatures/         # YARA rules
    └── sample_rules.yar
```

**Note:** The following directories are excluded from version control via `.gitignore`:
- `cache/` - Cached lookup data
- `logs/` - Log files
- `reports/` - Generated reports

## Настройка

### API ключи
1. Создать файл `settings.json` в корне проекта (или он создастся автоматически)
2. Добавить:
```json
{
  "api_keys": {
    "virustotal": "your_key_here",
    "abuseipdb": "your_key_here"
  }
}
```

### Настройки через UI
- Изменить кол-во потоков, таймаут в меню Settings
- Очистить кэш при необходимости

### IOC база
1. Скачать IOC с abuse.ch, PhishTank, etc.
2. Положить CSV в любую папку
3. В приложении: Settings > Load IOC from file

## Configuration

Edit `config.py` to customize:
- Application settings (theme, threads, timeout)
- Risk thresholds
- Suspicious API patterns
- Suspicious string patterns
- URL shorteners list
- IOC patterns

Settings can also be saved persistently via `settings.json` using `load_user_settings()` and `save_user_settings()` functions.

## Запуск на Linux
```bash
sudo python main.py  # Для сетевого сканирования (port_scan, traceroute требуют root)
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**CheckScam**

## Disclaimer

This tool is intended for legitimate security analysis and research purposes only. Always ensure you have proper authorization before scanning systems or analyzing files.