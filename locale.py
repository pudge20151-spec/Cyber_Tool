#!/usr/bin/env python3
"""
CyberTool Localization Module
Supports English and Russian languages
"""

# Language translations
LOCALES = {
    "en": {
        # Application
        "app_name": "CyberTool",
        "app_version": "v2.0",
        "banner_title": "Advanced Cybersecurity Analysis Toolkit",
        
        # Menu
        "menu_title": "Main Menu",
        "menu_analysis_header": "── Analysis Tools ──",
        "menu_advanced_header": "── Advanced Tools ──",
        "menu_file_analysis": "File Analysis",
        "menu_url_analysis": "URL Analysis",
        "menu_ip_intelligence": "IP Intelligence",
        "menu_network_scan": "Network Scan",
        "menu_process_monitor": "Process Monitor",
        "menu_yara_scan": "YARA Scan",
        "menu_pe_analyzer": "PE Analyzer",
        "menu_hash_checker": "Hash Checker",
        "menu_virustotal": "VirusTotal",
        "menu_batch_scanner": "Batch Scanner",
        "menu_watchdog": "Watchdog Monitor",
        "menu_dns_whois": "DNS & WHOIS",
        "menu_fuzzy_hash": "Fuzzy Hash (SSDEEP)",
        "menu_ioc_feed": "IOC Feed",
        "menu_correlation": "Correlation Engine",
        "menu_report_generator": "Report Generator",
        "menu_view_reports": "View Reports",
        "menu_settings": "Settings",
        "menu_browser_forensics": "Browser Forensics",
        "menu_fraud_detection": "Fraud Detection",
        "menu_phishing_scan": "Phishing Scan",
        "menu_usb_forensics": "USB Forensics",
        "menu_memory_analysis": "Memory Analysis",
        "menu_exit": "Exit",
        "select_option": "Select option",
        "press_enter": "Press Enter to continue...",
        
        # Common
        "enter_path": "Enter file path",
        "enter_url": "Enter URL",
        "enter_ip": "Enter IP address",
        "enter_domain": "Enter domain",
        "file_not_found": "File not found!",
        "error": "Error",
        "analyzing": "Analyzing...",
        "scanning": "Scanning...",
        "lookup": "Looking up...",
        "yes": "Yes",
        "no": "No",
        
        # Risk levels
        "risk_low": "LOW",
        "risk_medium": "MEDIUM",
        "risk_high": "HIGH",
        "risk_critical": "CRITICAL",
        "overall_risk": "Overall Risk",
        "reasons": "Reasons",
        
        # Settings
        "settings_title": "Settings",
        "settings_theme": "Theme",
        "settings_threads": "Threads",
        "settings_timeout": "Timeout",
        "settings_change_threads": "Change Threads",
        "settings_change_timeout": "Change Timeout",
        "settings_clear_cache": "Clear Cache",
        "settings_check_updates": "Check for Updates",
        "settings_back": "Back to Main Menu",
        "ui_theme": "UI Theme",
        "parallel_threads": "Parallel threads",
        "request_timeout": "Request timeout",
        
        # File Analysis
        "file_analysis_title": "File Analysis",
        "file_hashes": "File Hashes",
        "file_info": "File Information",
        "suspicious_strings_found": "Suspicious Strings Found",
        "suspicious_apis_found": "Suspicious APIs Found",
        "packer_detected": "Packer Detected",
        "mime_type": "MIME Type",
        "file_type": "File Type",
        "entropy": "Entropy",
        "created": "Created",
        "modified": "Modified",
        "digital_signature": "Digital Signature",
        "size": "Size",
        
        # Risk assessment
        "risk_score": "Risk Score",
        
        # Exit
        "shutting_down": "Shutting down CyberTool...",
        "goodbye": "Goodbye!",
        
        # Network Scan
        "network_scan_title": "Network Scanner",
        "network_ping": "Ping Host",
        "network_port_scan": "Port Scan",
        "network_ping_sweep": "Ping Sweep",
        "network_traceroute": "Traceroute",
        "network_os_detection": "OS Detection",
        
        # Process Monitor
        "process_monitor_title": "Process Monitor",
        "process_list_all": "List All Processes",
        "process_suspicious": "Show Suspicious Processes",
        
        # YARA Scan
        "yara_scan_title": "YARA Scanner",
        
        # Reports
        "view_reports_title": "View Reports",
        "no_reports_found": "No reports found",
        
        # Batch Scanner
        "batch_scanner_title": "Batch Directory Scanner",
        
        # Fraud Detection
        "fraud_detection_title": "Fraud Detection & Phishing Scanner",
        
        # Browser Forensics
        "browser_forensics_title": "Browser Forensics",
        
        # USB Forensics
        "usb_forensics_title": "USB Forensics",
        
        # Memory Analysis
        "memory_analysis_title": "Memory Analysis",
        
        # IOC Feed
        "ioc_feed_title": "IOC Feed Manager",
        
        # DNS/WHOIS
        "dns_whois_title": "DNS & WHOIS Tools",
        
        # Correlation
        "correlation_title": "Correlation Engine",
        
        # VirusTotal
        "virustotal_title": "VirusTotal Integration",
    },
    
    "ru": {
        # Application
        "app_name": "CyberTool",
        "app_version": "v2.0",
        "banner_title": "Продвинутый Инструментарий Кибербезопасности",
        
        # Menu
        "menu_title": "Главное Меню",
        "menu_analysis_header": "── Инструменты Анализа ──",
        "menu_advanced_header": "── Дополнительные Инструменты ──",
        "menu_file_analysis": "Анализ Файлов",
        "menu_url_analysis": "Анализ URL",
        "menu_ip_intelligence": "Обнаружение IP",
        "menu_network_scan": "Сетевое Сканирование",
        "menu_process_monitor": "Монитор Процессов",
        "menu_yara_scan": "YARA Скан",
        "menu_pe_analyzer": "PE Анализатор",
        "menu_hash_checker": "Проверка Хешей",
        "menu_virustotal": "VirusTotal",
        "menu_batch_scanner": "Пакетный Сканер",
        "menu_watchdog": "Watchdog Монитор",
        "menu_dns_whois": "DNS и WHOIS",
        "menu_fuzzy_hash": "Фуззи Хеш (SSDEEP)",
        "menu_ioc_feed": "IOC Лента",
        "menu_correlation": "Движок Корреляции",
        "menu_report_generator": "Генератор Отчетов",
        "menu_view_reports": "Просмотр Отчетов",
        "menu_settings": "Настройки",
        "menu_browser_forensics": "Браузер Форензики",
        "menu_fraud_detection": "Обнаружение Мошенничества",
        "menu_phishing_scan": "Проверка Phishing",
        "menu_usb_forensics": "USB Форензики",
        "menu_memory_analysis": "Анализ Памяти",
        "menu_exit": "Выход",
        "select_option": "Выберите опцию",
        "press_enter": "Нажмите Enter для продолжения...",
        
        # Common
        "enter_path": "Введите путь к файлу",
        "enter_url": "Введите URL",
        "enter_ip": "Введите IP адрес",
        "enter_domain": "Введите домен",
        "file_not_found": "Файл не найден!",
        "error": "Ошибка",
        "analyzing": "Анализ...",
        "scanning": "Сканирование...",
        "lookup": "Поиск...",
        "yes": "Да",
        "no": "Нет",
        
        # Risk levels
        "risk_low": "НИЗКИЙ",
        "risk_medium": "СРЕДНИЙ",
        "risk_high": "ВЫСОКИЙ",
        "risk_critical": "КРИТИЧЕСКИЙ",
        "overall_risk": "Общий Риск",
        "reasons": "Причины",
        
        # Settings
        "settings_title": "Настройки",
        "settings_theme": "Тема",
        "settings_threads": "Потоки",
        "settings_timeout": "Таймаут",
        "settings_change_threads": "Изменить Потоки",
        "settings_change_timeout": "Изменить Таймаут",
        "settings_clear_cache": "Очистить Кеш",
        "settings_check_updates": "Проверить Обновления",
        "settings_back": "Вернуться в Главное Меню",
        "ui_theme": "Тема интерфейса",
        "parallel_threads": "Параллельные потоки",
        "request_timeout": "Таймаут запросов",
        
        # File Analysis
        "file_analysis_title": "Анализ Файлов",
        "file_hashes": "Хеши Файла",
        "file_info": "Информация о Файле",
        "suspicious_strings_found": "Найдены Подозрительные Строки",
        "suspicious_apis_found": "Найдены Подозрительные API",
        "packer_detected": "Обнаружен Упаковщик",
        "mime_type": "MIME Тип",
        "file_type": "Тип Файла",
        "entropy": "Энтропия",
        "created": "Создан",
        "modified": "Изменён",
        "digital_signature": "Цифровая Подпись",
        "size": "Размер",
        
        # Risk assessment
        "risk_score": "Оценка Риска",
        
        # Exit
        "shutting_down": "Завершение работы CyberTool...",
        "goodbye": "До свидания!",
        
        # Network Scan
        "network_scan_title": "Сетевой Сканер",
        "network_ping": "Пинг Хоста",
        "network_port_scan": "Скан Портов",
        "network_ping_sweep": "Скан Подсети",
        "network_traceroute": "Трассировка",
        "network_os_detection": "Определение OS",
        
        # Process Monitor
        "process_monitor_title": "Монитор Процессов",
        "process_list_all": "Все Процессы",
        "process_suspicious": "Подозрительные Процессы",
        
        # YARA Scan
        "yara_scan_title": "YARA Сканер",
        
        # Reports
        "view_reports_title": "Просмотр Отчетов",
        "no_reports_found": "Отчеты не найдены",
        
        # Batch Scanner
        "batch_scanner_title": "Пакетный Сканер",
        
        # Fraud Detection
        "fraud_detection_title": "Обнаружение Мошенничества и Phishing",
        
        # Browser Forensics
        "browser_forensics_title": "Браузер Форензики",
        
        # USB Forensics
        "usb_forensics_title": "USB Форензики",
        
        # Memory Analysis
        "memory_analysis_title": "Анализ Памяти",
        
        # IOC Feed
        "ioc_feed_title": "Менеджер IOC Ленты",
        
        # DNS/WHOIS
        "dns_whois_title": "DNS и WHOIS Инструменты",
        
        # Correlation
        "correlation_title": "Движок Корреляции",
        
        # VirusTotal
        "virustotal_title": "VirusTotal Интеграция",
    }
}

# Current language
_current_language = "en"

def set_language(lang_code):
    """Set the current language"""
    global _current_language
    if lang_code in LOCALES:
        _current_language = lang_code

def get_language():
    """Get the current language code"""
    return _current_language

def _(key):
    """Get translation for a key"""
    return LOCALES[_current_language].get(key, LOCALES["en"].get(key, key))