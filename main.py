#!/usr/bin/env python3
"""
CyberTool v0.1 - Cybersecurity Analysis Toolkit
"""
import sys
import os
import signal
import ipaddress
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm
from rich.layout import Layout
from rich.text import Text
from rich import box
from rich.columns import Columns
from rich.syntax import Syntax
from rich.markdown import Markdown
from rich.live import Live
from rich.tree import Tree
from rich import print as rprint

from config import APP_NAME, APP_VERSION, APP_AUTHOR, RISK_THRESHOLDS, REPORTS_DIR
from core.logger import logger
from core.database import db
from core.cache import cache
from core.updater import Updater
from locale import _, set_language, get_language

from modules.file_analyzer import FileAnalyzer
from modules.hash_checker import HashChecker
from modules.pe_analyzer import PEAnalyzer
from modules.url_analyzer import URLAnalyzer
from modules.ip_lookup import IPLookup
from modules.dns_lookup import DNSLookup
from modules.whois import WhoisLookup
from modules.network import NetworkScanner
from modules.email_checker import EmailChecker
from modules.process_monitor import ProcessMonitor
from modules.startup_checker import StartupChecker
from modules.autoruns import Autoruns
from modules.memory import MemoryAnalyzer
from modules.yara_scanner import YaraScanner
from modules.report import ReportGenerator
from modules.virustotal import VirusTotal
from modules.batch_scanner import BatchScanner
from modules.watchdog import Watchdog
from modules.ssdeep_fuzzy import SSDEEP
from modules.ioc_feed import IOCFeed
from modules.correlation import CorrelationEngine
from modules.browser_forensics import BrowserForensics
from modules.usb_forensics import USBForensics
from modules.fraud_detector import FraudDetector

console = Console()


class CyberTool:
    """Main CyberTool Application"""

    def __init__(self):
        self.running = True
        self.settings = {
            "theme": "dark",
            "threads": 4,
            "timeout": 30,
        }
        signal.signal(signal.SIGINT, self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

    def _shutdown(self, sig, frame):
        """Graceful shutdown on signal"""
        console.print("\n[yellow]⚠️  Shutting down...[/]")
        try:
            db.close()
            if hasattr(cache, 'close'):
                cache.close()
        except Exception as e:
            logger.error("Shutdown", str(e))
        console.print("[green]✓ Closed successfully[/]")
        exit(0)

    def clear_screen(self):
        """Clear terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_banner(self):
        """Print application banner with ASCII art"""
        banner_text = Text("""  ██████    ██      ██  ████████    ██████████  ████████    ██████████    ██████      ██████    ██          
  ██████    ██      ██  ████████    ██████████  ████████    ██████████    ██████      ██████    ██          
██            ██  ██    ██      ██  ██          ██      ██      ██      ██      ██  ██      ██  ██          
██            ██  ██    ██      ██  ██          ██      ██      ██      ██      ██  ██      ██  ██          
██              ██      ████████    ████████    ████████        ██      ██      ██  ██      ██  ██          
██              ██      ████████    ████████    ████████        ██      ██      ██  ██      ██  ██          
██              ██      ██      ██  ██          ██    ██        ██      ██      ██  ██      ██  ██          
██              ██      ██      ██  ██          ██    ██        ██      ██      ██  ██      ██  ██          
  ██████        ██      ████████    ██████████  ██      ██      ██        ██████      ██████    ██████████  
  ██████        ██      ████████    ██████████  ██      ██      ██        ██████      ██████    ██████████  """, style="bold cyan")
        
        version_text = Text(f"v{APP_VERSION} - Advanced Cybersecurity Analysis Toolkit", style="bold blue")
        author_text = Text(f"by {APP_AUTHOR}", style="dim")
        
        console.print(Panel(
            f"{banner_text}\n\n{version_text}\n{author_text}",
            border_style="cyan",
            box=box.DOUBLE
        ))
        console.print()

    def select_language(self):
        """Language selection at startup"""
        self.clear_screen()
        console.print(Panel.fit(
            "Select Language / Выберите язык\n\n"
            "1. English\n"
            "2. Russian",
            title="Language Selection",
            border_style="blue"
        ))
        choice = Prompt.ask("Select language", choices=["1", "2"], default="1")
        
        if choice == "2":
            set_language("ru")
        else:
            set_language("en")
        
        return choice

    def print_menu(self):
        """Print main menu"""
        menu = Panel.fit(
            f'{_("menu_analysis_header")}\n'
            f'1. {_("menu_file_analysis")}         2. {_("menu_url_analysis")}\n'
            f'3. {_("menu_ip_intelligence")}      4. {_("menu_network_scan")}\n'
            f'5. {_("menu_process_monitor")}      6. {_("menu_yara_scan")}\n'
            f'7. {_("menu_pe_analyzer")}          8. {_("menu_hash_checker")}\n'
            f'\n{_("menu_advanced_header")}\n'
            f'V. VirusTotal       B. {_("menu_batch_scanner")}\n'
            f'W. {_("menu_watchdog")}     D. {_("menu_dns_whois")}\n'
            f'F. {_("menu_fuzzy_hash")}  I. {_("menu_ioc_feed")}\n'
            f'C. {_("menu_correlation")}   R. {_("menu_browser_forensics")}\n'
            f'S. {_("menu_fraud_detection")}      P. {_("menu_phishing_scan")}\n'
            f'U. {_("menu_usb_forensics")}        M. {_("menu_memory_analysis")}\n'
            f'\n'
            f'9. {_("menu_report_generator")}       O. {_("menu_view_reports")}\n'
            f'T. {_("menu_settings")}             0. {_("menu_exit")}',
            title=f'CyberTool {APP_VERSION} - {_("menu_title")}',
            border_style="blue"
        )
        console.print(menu)

    def run(self):
        """Main application loop"""
        # Language selection at startup
        self.select_language()
        self.clear_screen()
        self.print_banner()

        while self.running:
            self.print_menu()
            choice = Prompt.ask(_("select_option"), choices=[
                "0","1","2","3","4","5","6","7","8","9",
                "v","V","b","B","w","W","d","D","f","F",
                "i","I","c","C","r","R","u","U","m","M",
                "s","S","p","P","t","T","o","O"
            ])
            choice = choice.upper()

            actions = {
                "1": self.file_analysis_menu,
                "2": self.url_analysis,
                "3": self.ip_intelligence,
                "4": self.network_scan,
                "5": self.process_monitor,
                "6": self.yara_scan,
                "7": self.pe_analyzer,
                "8": self.hash_checker_menu,
                "9": self.generate_report,
                "O": self.view_reports,
                "V": self.virustotal_menu,
                "B": self.batch_scanner_menu,
                "W": self.watchdog_menu,
                "D": self.dns_whois_menu,
                "F": self.fuzzy_hash_menu,
                "I": self.ioc_feed_menu,
                "C": self.correlation_menu,
                "R": self.browser_forensics_menu,
                "U": self.usb_forensics_menu,
                "M": self.memory_analysis_menu,
                "S": self.fraud_detection_menu,
                "P": self.phishing_scan_menu,
                "T": self.settings_menu,
                "0": self.exit_app,
            }

            action = actions.get(choice)
            if action:
                action()

            if self.running and choice != "0":
                console.print(f'\n{_("press_enter")}')
                input()

    def file_analysis_menu(self):
        """File Analysis menu"""
        self.clear_screen()
        console.print(Panel.fit("File Analysis", border_style="cyan"))

        file_path = Prompt.ask("Enter file path")
        if not os.path.exists(file_path):
            console.print("File not found!")
            return

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description="Analyzing file...", total=None)
            analyzer = FileAnalyzer()
            results = analyzer.analyze(file_path)

        if "error" in results:
            console.print(f"Error: {results['error']}")
            return

        # Display results
        console.print(f"\nFile: {results['filename']}")
        console.print(f"Path: {results['file_path']}")
        console.print(f"Size: {results['size_str']}")

        # Hashes
        hash_table = Table(title="File Hashes", box=box.ROUNDED)
        hash_table.add_column("Algorithm", style="cyan")
        hash_table.add_column("Hash", style="white")
        for algo in ['md5', 'sha1', 'sha256', 'sha512']:
            if algo in results:
                hash_table.add_row(algo.upper(), results[algo])
        console.print(hash_table)

        # File info
        info_table = Table(title="File Information", box=box.ROUNDED)
        info_table.add_column("Property", style="cyan")
        info_table.add_column("Value", style="white")
        info_table.add_row("MIME Type", results.get('mime_type', 'N/A'))
        info_table.add_row("File Type", results.get('file_type', 'N/A'))
        info_table.add_row("Entropy", str(results.get('entropy', 0)))
        info_table.add_row("Created", results.get('created', 'N/A'))
        info_table.add_row("Modified", results.get('modified', 'N/A'))
        info_table.add_row("Digital Signature", results.get('digital_signature', 'N/A'))
        console.print(info_table)

        # Suspicious strings
        if results.get('suspicious_strings'):
            console.print(f"\nSuspicious Strings Found: {len(results['suspicious_strings'])}")
            for s in results['suspicious_strings'][:15]:
                console.print(f"  ! {s}")

        # Suspicious APIs
        if results.get('suspicious_apis'):
            console.print(f"\nSuspicious APIs Found:")
            api_table = Table(box=box.SIMPLE)
            api_table.add_column("API", style="red")
            for api in results['suspicious_apis'][:10]:
                api_table.add_row(api)
            console.print(api_table)

        # Packer detection
        if results.get('packed'):
            console.print(f"\nPacker Detected: {', '.join(results['packed'])}")

        # Risk score
        risk_score = self.calculate_file_risk(results)
        self.display_risk_score(risk_score)

        # Log
        logger.info("FileAnalysis", f"Analyzed: {file_path}")

    def calculate_file_risk(self, results):
        """Calculate risk score for file analysis"""
        score = 0
        reasons = []

        # Entropy check
        entropy = results.get('entropy', 0)
        if entropy > 7.5:
            score += 25
            reasons.append("Very high entropy (packed/encrypted)")
        elif entropy > 6.5:
            score += 15
            reasons.append("High entropy")

        # Suspicious strings
        suspicious_count = len(results.get('suspicious_strings', []))
        if suspicious_count > 20:
            score += 20
            reasons.append(f"Many suspicious strings ({suspicious_count})")
        elif suspicious_count > 10:
            score += 10
            reasons.append(f"Suspicious strings found ({suspicious_count})")

        # Suspicious APIs
        api_count = len(results.get('suspicious_apis', []))
        if api_count > 5:
            score += 25
            reasons.append(f"Suspicious API calls ({api_count})")
        elif api_count > 0:
            score += 15
            reasons.append("Suspicious API calls detected")

        # Packer
        if results.get('packed'):
            score += 20
            reasons.append("Packed executable detected")

        # Digital signature
        sig = results.get('digital_signature', '')
        if 'NotSigned' in sig or 'Not signed' in sig:
            score += 10
            reasons.append("Unsigned executable")
        elif 'Unable' in sig:
            score += 5
            reasons.append("Could not verify signature")

        # Size check
        size = results.get('size', 0)
        if size < 4096:
            score += 5
            reasons.append("Very small file size")

        return {"score": min(score, 100), "reasons": reasons}

    def display_risk_score(self, risk_data):
        """Display risk score with visual bar"""
        score = risk_data["score"]
        reasons = risk_data["reasons"]

        if score <= 25:
            level = "LOW"
            color = "green"
        elif score <= 50:
            level = "MEDIUM"
            color = "yellow"
        elif score <= 75:
            level = "HIGH"
            color = "red"
        else:
            level = "CRITICAL"
            color = "bold red"

        # Progress bar
        bar_length = 40
        filled = int(bar_length * score / 100)
        bar = "#" * filled + "-" * (bar_length - filled)

        console.print(f"\nRisk Score: {score}%")
        console.print(f"[{color}]{bar}[/]")
        console.print(f"[bold {color}]Overall Risk: {level}[/]")

        if reasons:
            console.print(f"\nReasons:")
            for reason in reasons:
                console.print(f"  X {reason}")

    def url_analysis(self):
        """URL Analysis - Enhanced"""
        self.clear_screen()
        console.print(Panel.fit("URL Analysis", border_style="cyan"))

        url = Prompt.ask("Enter URL")
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description="Analyzing URL...", total=None)
            analyzer = URLAnalyzer()
            results = analyzer.analyze(url)

        if "error" in results:
            console.print(f"Error: {results['error']}")
            return

        # Basic URL Info
        parsed = results.get("parsed", {})
        checks = results.get("checks", {})

        info_table = Table(title=f"URL Analysis: {parsed.get('hostname', 'N/A')}", box=box.ROUNDED)
        info_table.add_column("Property", style="cyan")
        info_table.add_column("Value", style="white")
        info_table.add_row("Full URL", results.get("url", "")[:80])
        info_table.add_row("Scheme", parsed.get("scheme", "N/A"))
        info_table.add_row("Hostname", parsed.get("hostname", "N/A"))
        info_table.add_row("Path", parsed.get("path", "N/A")[:60])
        info_table.add_row("Query", parsed.get("query", "N/A")[:60])
        info_table.add_row("Fragment", parsed.get("fragment", "N/A"))
        info_table.add_row("Port", str(parsed.get("port", "Default")))
        info_table.add_row("URL Length", str(checks.get("url_length", 0)))
        info_table.add_row("HTTPS", "Yes" if checks.get("https") else "No")
        info_table.add_row("Punycode", "Yes" if checks.get("punycode") else "No")
        info_table.add_row("IP Instead of Domain", "Yes" if checks.get("ip_instead_domain") else "No")
        info_table.add_row("URL Shortener", "Yes" if checks.get("is_shortener") else "No")
        info_table.add_row("Suspicious Length", "Yes" if checks.get("suspicious_length") else "No")
        info_table.add_row("Subdomains", str(checks.get("subdomain_count", 0)))
        info_table.add_row("Many Subdomains", "Yes" if checks.get("many_subdomains") else "No")
        console.print(info_table)

        # Suspicious characters
        if checks.get("suspicious_characters"):
            console.print(f"\nSuspicious Characters: {', '.join(checks['suspicious_characters'])}")

        # TLD ANALYSIS
        tld = checks.get("tld_analysis", {})
        if tld:
            tld_table = Table(title="TLD Analysis", box=box.ROUNDED)
            tld_table.add_column("Property", style="cyan")
            tld_table.add_column("Value", style="white")
            tld_table.add_row("TLD", tld.get("tld", "N/A"))
            tld_table.add_row("Suspicious", "Yes" if tld.get("suspicious") else "No")
            if tld.get("reasons"):
                tld_table.add_row("Reasons", ", ".join(tld["reasons"]))
            console.print(tld_table)

        # PHISHING DETECTION
        phishing = results.get("phishing", {})
        if phishing:
            phish_color = "red" if phishing.get("is_phishing") else "green"
            phish_table = Table(title="Phishing Detection", box=box.ROUNDED)
            phish_table.add_column("Check", style="cyan")
            phish_table.add_column("Result", style="white")
            phish_table.add_row("Phishing Risk", f"[{phish_color}]{'YES' if phishing.get('is_phishing') else 'No'}[/]")
            phish_table.add_row("Risk Score", f"{phishing.get('risk_score', 0)}/100")
            if phishing.get("brand_impersonation"):
                phish_table.add_row("Brand Impersonation", ", ".join(phishing["brand_impersonation"]))
            if phishing.get("indicators"):
                for indicator in phishing["indicators"][:5]:
                    phish_table.add_row("Indicator", f"{indicator}")
            console.print(phish_table)

        # TYPOSQUATTING DETECTION
        typosquatting = results.get("typosquatting", {})
        if typosquatting and typosquatting.get("is_typosquatting"):
            ts_table = Table(title="Typosquatting Detection", box=box.ROUNDED)
            ts_table.add_column("Brand", style="cyan")
            ts_table.add_column("Legitimate Domain", style="white")
            ts_table.add_column("Similarity", style="yellow")
            for score in typosquatting.get("similarity_scores", []):
                sim = score.get("similarity", "")
                technique = score.get("technique", "")
                sim_str = f"{sim}%" if sim else technique
                ts_table.add_row(
                    score.get("brand", ""),
                    score.get("legitimate_domain", ""),
                    sim_str,
                )
            console.print(ts_table)

        # QUERY PARAMETER ANALYSIS
        query_params = checks.get("query_params", {})
        if query_params and query_params.get("param_count", 0) > 0:
            qp_table = Table(title="Query Parameter Analysis", box=box.ROUNDED)
            qp_table.add_column("Property", style="cyan")
            qp_table.add_column("Value", style="white")
            qp_table.add_row("Parameter Count", str(query_params.get("param_count", 0)))
            qp_table.add_row("Open Redirect Param", "Yes" if query_params.get("has_redirect_param") else "No")
            qp_table.add_row("Base64 Encoded URL", "Yes" if query_params.get("has_base64") else "No")
            if query_params.get("suspicious_params"):
                for sp in query_params["suspicious_params"]:
                    qp_table.add_row("Suspicious", f"{sp}")
            console.print(qp_table)

        # REDIRECTS
        redirects = checks.get("redirects", {})
        if redirects and "error" not in redirects:
            redirect_table = Table(title="Redirect Chain", box=box.ROUNDED)
            redirect_table.add_column("Property", style="cyan")
            redirect_table.add_column("Value", style="white")
            redirect_table.add_row("Redirect Count", str(redirects.get("redirect_count", 0)))
            redirect_table.add_row("Final URL", redirects.get("final_url", "N/A")[:80])
            redirect_table.add_row("Status Code", str(redirects.get("status_code", "N/A")))
            if redirects.get("redirect_count", 0) > 0:
                for r in redirects.get("redirects", []):
                    redirect_table.add_row("Redirect", f"{r['status']} -> {r['from'][:60]}")
            console.print(redirect_table)
        elif redirects and "error" in redirects:
            console.print(f"\nRedirect Check Error: {redirects['error']}")

        # CERTIFICATE
        cert = checks.get("certificate", {})
        if cert and "error" not in cert:
            cert_table = Table(title="SSL Certificate", box=box.ROUNDED)
            cert_table.add_column("Property", style="cyan")
            cert_table.add_column("Value", style="white")
            cert_table.add_row("Issuer", str(cert.get("issuer", {})))
            cert_table.add_row("Subject", str(cert.get("subject", {})))
            cert_table.add_row("Valid From", cert.get("valid_from", "N/A"))
            cert_table.add_row("Valid To", cert.get("valid_to", "N/A"))
            cert_table.add_row("Expired", "YES" if cert.get("is_expired") else "No")
            cert_table.add_row("Days Remaining", str(cert.get("days_remaining", "N/A")))
            cert_table.add_row("Serial", str(cert.get("serial", "N/A"))[:30])
            cert_table.add_row("SAN Count", str(len(cert.get("san", []))))
            if cert.get("san"):
                cert_table.add_row("SANs", ", ".join(cert["san"][:5]))
            console.print(cert_table)
        elif cert and "error" in cert:
            console.print(f"\nCertificate Error: {cert['error']}")

        # OPEN PORTS
        open_ports = checks.get("open_ports", [])
        if open_ports:
            port_table = Table(title="Open Ports", box=box.ROUNDED)
            port_table.add_column("Port", style="cyan")
            port_table.add_column("Banner", style="white")
            for p in open_ports:
                port_table.add_row(str(p.get("port", "")), p.get("banner", "")[:40])
            console.print(port_table)

        # SECURITY HEADERS
        sec_headers = results.get("security_headers", {})
        if sec_headers and "error" not in sec_headers:
            sec_table = Table(title="Security Headers", box=box.ROUNDED)
            sec_table.add_column("Header", style="cyan")
            sec_table.add_column("Status", style="white")
            sec_table.add_column("Value", style="dim")

            for header, info in sec_headers.get("headers", {}).items():
                if info.get("present"):
                    status = "Present"
                    value = info.get("value", "")[:50]
                else:
                    status = "Missing"
                    value = info.get("description", "")
                sec_table.add_row(header, status, value)

            # Cookie flags
            cookie_info = sec_headers.get("headers", {}).get("Set-Cookie", {})
            if isinstance(cookie_info, dict) and cookie_info.get("present"):
                cookie_flags = []
                if cookie_info.get("has_secure"):
                    cookie_flags.append("Secure")
                if cookie_info.get("has_httponly"):
                    cookie_flags.append("HttpOnly")
                if cookie_info.get("has_samesite"):
                    cookie_flags.append("SameSite")
                if cookie_flags:
                    sec_table.add_row("Cookie Flags", ", ".join(cookie_flags), "")

            sec_table.add_row("Security Score", f"{sec_headers.get('security_score', 0)}/100", "")
            console.print(sec_table)

        # CONTENT ANALYSIS
        content = results.get("content_analysis", {})
        if content.get("has_content"):
            content_table = Table(title="Page Content Analysis", box=box.ROUNDED)
            content_table.add_column("Check", style="cyan")
            content_table.add_column("Result", style="white")
            content_table.add_row("Page Title", content.get("title", "N/A")[:80])
            content_table.add_row("Content Length", f"{content.get('content_length', 0)} bytes")
            content_table.add_row("Login Form", "Yes" if content.get("has_login_form") else "No")
            content_table.add_row("Iframe", "Yes" if content.get("has_iframe") else "No")
            content_table.add_row("External Scripts", "Yes" if content.get("has_external_scripts") else "No")
            content_table.add_row("Trackers", "Yes" if content.get("has_trackers") else "No")
            content_table.add_row("External Form Action", "Yes" if content.get("form_action_external") else "No")
            if content.get("suspicious_elements"):
                for elem in content["suspicious_elements"][:5]:
                    content_table.add_row("Element", f"{elem}")
            console.print(content_table)

        # DNS INFO
        dns_info = results.get("dns_info", {})
        if dns_info:
            dns_table = Table(title="DNS Information", box=box.ROUNDED)
            dns_table.add_column("Property", style="cyan")
            dns_table.add_column("Value", style="white")
            if dns_info.get("has_dns"):
                dns_table.add_row("DNS Resolution", "Resolved")
                dns_table.add_row("IP Addresses", ", ".join(dns_info.get("ip_addresses", [])))
            else:
                dns_table.add_row("DNS Resolution", f"{dns_info.get('dns_error', 'Failed')}")
            console.print(dns_table)

        # REPUTATION SCORE
        rep = results.get("reputation", {})
        if rep:
            score = rep.get("score", 50)
            severity = rep.get("severity", "unknown")
            reasons = rep.get("reasons", [])

            sev_colors = {
                "malicious": "bold red",
                "suspicious": "red",
                "neutral": "yellow",
                "likely_safe": "green",
                "safe": "bold green",
            }
            sev_color = sev_colors.get(severity, "white")

            bar_length = 40
            filled = int(bar_length * score / 100)
            bar = "#" * filled + "-" * (bar_length - filled)

            rep_panel = Panel(
                f"Reputation Score: {score}%\n"
                f"[{sev_color}]{bar}[/]\n"
                f"[bold {sev_color}]Severity: {severity.upper()}[/]\n"
                + ("\nReasons:\n" + "\n".join(f"  X {r}" for r in reasons) if reasons else ""),
                title="URL Reputation Assessment",
                border_style="blue"
            )
            console.print(rep_panel)

        logger.info("URLAnalysis", f"Enhanced analysis: {url}")

    def ip_intelligence(self):
        """IP Intelligence - Enhanced"""
        self.clear_screen()
        console.print(Panel.fit("IP Intelligence", border_style="cyan"))

        ip = Prompt.ask("Enter IP address")

        cache_key = f"ip_lookup_{ip}"
        cached = cache.get(cache_key)
        if cached:
            results = cached
            from_cache = True
            lookup = IPLookup()
        else:
            from_cache = False
            lookup = IPLookup()

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description="Looking up IP...", total=None)
            if not from_cache:
                results = lookup.lookup(ip)
                cache.set(cache_key, results, ttl=86400)

        # Show cache indicator
        if from_cache:
            console.print("[dim yellow]Loaded from cache[/]")

        # BASIC INFO
        basic = results.get("basic", {})
        info_table = Table(title="Basic Information", box=box.ROUNDED)
        info_table.add_column("Property", style="cyan")
        info_table.add_column("Value", style="white")
        info_table.add_row("IP Address", ip)
        info_table.add_row("IP Version", f"IPv{basic.get('ip_version', '?')}")
        info_table.add_row("Primary Type", basic.get("ip_type", "N/A"))
        
        # Full Classifications
        classifications = basic.get("classifications", [])
        if classifications:
            info_table.add_row("Classifications", ", ".join(classifications))
        
        info_table.add_row("Range Description", basic.get("range_description", "N/A"))
        info_table.add_row("RIR", basic.get("rir", "N/A"))
        console.print(info_table)

        # REVERSE DNS
        if not self._is_special_address_simple(ip):
            ptr_result = lookup._reverse_dns_validated(ip)
            ptr_table = Table(title="Reverse DNS", box=box.ROUNDED)
            ptr_table.add_column("Property", style="cyan")
            ptr_table.add_column("Value", style="white")
            ptr_table.add_row("Hostname", ptr_result.get("hostname", "N/A"))
            ptr_table.add_row("Validated", "Yes" if ptr_result.get("validated") else "No (not forward-confirmed)" if ptr_result.get("hostname") != "PTR Missing" else "Missing")
            console.print(ptr_table)

        # NETWORK INFO (Combined ASN/ISP)
        geo = results.get("geo", {})
        net = results.get("network", {})
        
        # Only show network section if we have real data (not N/A)
        if geo.get("asn") and geo.get("asn") != "N/A":
            net_table = Table(title="Network Information", box=box.ROUNDED)
            net_table.add_column("Property", style="cyan")
            net_table.add_column("Value", style="white")
            net_table.add_row("ASN", geo.get("asn", "N/A"))
            net_table.add_row("AS Name", geo.get("as_name", "N/A"))
            net_table.add_row("ISP", geo.get("isp", "N/A"))
            net_table.add_row("Organization", geo.get("org", "N/A"))
            
            # CIDR from RDAP if available
            rdap = results.get("rdap", {})
            if rdap.get("cidr"):
                net_table.add_row("BGP Prefix", rdap["cidr"])
            
            # Owner type detection
            owner_type = self._detect_owner_type(geo, net)
            net_table.add_row("Owner Type", owner_type)
            
            net_table.add_row("Hosting Provider", "Yes" if net.get("is_hosting") or geo.get("hosting") else "No")
            if net.get("hosting_indicators"):
                net_table.add_row("Hosting Indicators", ", ".join(net["hosting_indicators"]))
            net_table.add_row("Mobile Network", "Yes" if geo.get("mobile") else "No")
            console.print(net_table)

        # GEOLOCATION
        if geo.get("country") and geo.get("country") != "N/A":
            geo_table = Table(title="Location", box=box.ROUNDED)
            geo_table.add_column("Property", style="cyan")
            geo_table.add_column("Value", style="white")
            geo_table.add_row("Country", f"{geo.get('country', 'N/A')} ({geo.get('country_code', 'N/A')})")
            geo_table.add_row("Region", geo.get("region", "N/A"))
            geo_table.add_row("City", geo.get("city", "N/A"))
            geo_table.add_row("ZIP/Postal", geo.get("zip", "N/A"))
            geo_table.add_row("Coordinates", f"{geo.get('lat', 'N/A')}, {geo.get('lon', 'N/A')}")
            geo_table.add_row("Timezone", geo.get("timezone", "N/A"))
            console.print(geo_table)
        elif geo.get("reason"):
            # Special address
            geo_table = Table(title="Location", box=box.ROUNDED)
            geo_table.add_column("Property", style="cyan")
            geo_table.add_column("Value", style="white")
            geo_table.add_row("Geolocation", "N/A")
            geo_table.add_row("Reason", geo.get("reason", "Special Address Range"))
            console.print(geo_table)

        # WHOIS SUMMARY
        rdap = results.get("rdap", {})
        if rdap and rdap.get("registration_date"):
            whois_table = Table(title="WHOIS Summary", box=box.ROUNDED)
            whois_table.add_column("Property", style="cyan")
            whois_table.add_column("Value", style="white")
            whois_table.add_row("Created", rdap.get("registration_date", "N/A"))
            whois_table.add_row("Updated", rdap.get("last_changed", "N/A"))
            whois_table.add_row("Abuse Email", rdap.get("abuse_contact", "N/A"))
            whois_table.add_row("Country", rdap.get("country", "N/A"))
            console.print(whois_table)

        # DNSBL CHECK
        dnsbl = results.get("dnsbl", {})
        if dnsbl:
            dnsbl_table = Table(title="DNSBL Check", box=box.ROUNDED)
            dnsbl_table.add_column("Status", style="cyan")
            dnsbl_table.add_column("Details", style="white")
            if dnsbl.get("listed"):
                dnsbl_table.add_row("[red]Listed[/]", f"Found on {dnsbl.get('count', 0)} DNSBL(s)")
                for entry in dnsbl.get("lists", []):
                    dnsbl_table.add_row("", f"  - {entry.get('dnsbl', '')}")
            else:
                dnsbl_table.add_row("[green]Clean[/]", "Not listed on any checked DNSBL")
            console.print(dnsbl_table)

        # PROXY/VPN/TOR DETECTION
        proxy = results.get("proxy_vpn", {})
        if proxy:
            proxy_table = Table(title="Proxy / VPN / Tor Detection", box=box.ROUNDED)
            proxy_table.add_column("Check", style="cyan")
            proxy_table.add_column("Result", style="white")
            proxy_table.add_row("Tor Exit Node", "Yes" if proxy.get("is_tor") else "No")
            proxy_table.add_row("Proxy Detected", "Yes" if proxy.get("is_proxy") else "No")
            proxy_table.add_row("VPN Detected", "Yes" if proxy.get("is_vpn") else "No")
            proxy_table.add_row("Datacenter IP", "Yes" if proxy.get("is_datacenter") else "No")
            if proxy.get("details"):
                for d in proxy["details"]:
                    proxy_table.add_row("Detail", f"  - {d}")
            console.print(proxy_table)

        # REPUTATION SCORE
        rep = results.get("reputation", {})
        if rep:
            score = rep.get("score", 50)
            severity = rep.get("severity", "unknown")
            reasons = rep.get("reasons", [])

            # Color based on severity
            sev_colors = {
                "dangerous": "bold red",
                "suspicious": "red",
                "warning": "yellow",
                "likely_safe": "green",
                "safe": "bold green",
            }
            sev_color = sev_colors.get(severity, "white")

            # Progress bar with color
            bar_length = 40
            filled = int(bar_length * score / 100)
            bar = "#" * filled + "-" * (bar_length - filled)

            # Format reasons with checkmarks
            formatted_reasons = ""
            for r in reasons:
                if r.startswith("X"):
                    formatted_reasons += f"  [red]{r}[/]\n"
                elif r.startswith("OK"):
                    formatted_reasons += f"  [green]{r}[/]\n"
                else:
                    formatted_reasons += f"  {r}\n"

            rep_panel = Panel(
                f"Score: {score}%\n"
                f"[{sev_color}]{bar}[/]\n"
                f"[bold {sev_color}]Status: {severity.upper()}[/]\n"
                + (f"\nReasons:\n{formatted_reasons}" if reasons else ""),
                title="Reputation Assessment",
                border_style="blue"
            )
            console.print(rep_panel)

        # THREAT INTELLIGENCE
        threat = results.get("threat", {})
        if threat.get("abuseipdb") or threat.get("local_ioc"):
            threat_table = Table(title="Threat Intelligence", box=box.ROUNDED)
            threat_table.add_column("Source", style="cyan")
            threat_table.add_column("Details", style="white")

            if threat.get("local_ioc"):
                ioc = threat["local_ioc"]
                threat_table.add_row(
                    "Local IOC Database",
                    f"Type: {ioc.get('threat_type', 'Unknown')} | {ioc.get('description', '')}"
                )

            if threat.get("abuseipdb"):
                abuse = threat["abuseipdb"]
                confidence = abuse.get("abuse_confidence_score", 0)
                conf_color = "red" if confidence > 50 else "yellow" if confidence > 0 else "green"
                threat_table.add_row(
                    "AbuseIPDB",
                    f"Confidence: [{conf_color}]{confidence}%[/] | "
                    f"Reports: {abuse.get('total_reports', 0)}"
                )

            console.print(threat_table)

        # TIMING
        timing = results.get("timing", {})
        if timing.get("lookup_time_ms"):
            console.print(f"\n[dim]Lookup Time: {timing['lookup_time_ms']} ms[/]")

        logger.info("IPIntelligence", f"Enhanced lookup: {ip}")

    def _is_special_address_simple(self, ip):
        """Simple check for special addresses - used for PTR validation"""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_multicast or addr.is_unspecified
        except Exception:
            return False

    def _detect_owner_type(self, geo, net):
        """Detect owner type based on geo and network data"""
        isp = (geo.get("isp", "") + " " + geo.get("org", "")).lower()
        
        # Check for hosting/datacenter
        hosting_keywords = ["amazon", "aws", "azure", "gcp", "google cloud", "digitalocean", 
                           "linode", "vultr", "ovh", "hetzner", "cloudflare", "akamai"]
        if any(kw in isp for kw in hosting_keywords):
            return "Hosting"
        
        # Check for mobile
        if geo.get("mobile"):
            return "Mobile"
        
        # Check for government
        gov_keywords = ["gov", "government", "mil", "military", "edu"]
        if any(kw in isp for kw in gov_keywords):
            return "Government/Education"
        
        # Default
        return "Residential/Enterprise"

    def network_scan(self):
        """Network Scanner"""
        self.clear_screen()
        console.print(Panel.fit("Network Scanner", border_style="cyan"))

        console.print("Options:")
        console.print("  1. Ping Host")
        console.print("  2. Port Scan")
        console.print("  3. Ping Sweep")
        console.print("  4. Traceroute")
        console.print("  5. OS Detection")

        choice = Prompt.ask("Select option", choices=["1", "2", "3", "4", "5"])
        scanner = NetworkScanner()

        if choice == "1":
            host = Prompt.ask("Enter host")
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
                progress.add_task(description="Pinging...", total=None)
                result = scanner.ping(host)
            if result.get("alive"):
                console.print(f"Host is alive (Response: {result.get('response_time', 0)}ms)")
            else:
                console.print("Host is unreachable")

        elif choice == "2":
            host = Prompt.ask("Enter host")
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
                progress.add_task(description="Scanning ports...", total=None)
                result = scanner.port_scan(host)
            if result.get("open_ports"):
                port_table = Table(title=f"Open Ports on {host}", box=box.ROUNDED)
                port_table.add_column("Port", style="cyan")
                port_table.add_column("Service", style="green")
                port_table.add_column("Banner", style="white")
                for p in result["open_ports"]:
                    port_table.add_row(str(p["port"]), p["service"], p.get("banner", "")[:50])
                console.print(port_table)
            else:
                console.print("No open ports found")

        elif choice == "3":
            subnet = Prompt.ask("Enter subnet (e.g., 192.168.1)")
            console.print("This may take a while...")
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
                progress.add_task(description="Ping sweeping...", total=None)
                result = scanner.ping_sweep(subnet)
            if result.get("alive_hosts"):
                console.print("Alive hosts:")
                for host in result["alive_hosts"]:
                    console.print(f"  + {host}")
            else:
                console.print("No alive hosts found")

        elif choice == "4":
            host = Prompt.ask("Enter host")
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
                progress.add_task(description="Tracing route...", total=None)
                result = scanner.traceroute(host)
            if result.get("hops"):
                console.print(f"Traceroute to {host}:")
                for hop in result["hops"]:
                    console.print(f"  {hop}")
            else:
                console.print("Traceroute failed")

        elif choice == "5":
            host = Prompt.ask("Enter host")
            os_type = scanner.os_detect(host)
            console.print(f"Detected OS: {os_type}")

        logger.info("NetworkScan", f"Performed network scan")

    def process_monitor(self):
        """Process Monitor"""
        self.clear_screen()
        console.print(Panel.fit("Process Monitor", border_style="cyan"))

        console.print("Options:")
        console.print("  1. List All Processes")
        console.print("  2. Show Suspicious Processes")
        console.print("  3. CPU Usage Analyzer")

        choice = Prompt.ask("Select option", choices=["1", "2", "3"])
        monitor = ProcessMonitor()

        if choice == "3":
            self.cpu_usage_analyzer(monitor)
            return

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description="Analyzing processes...", total=None)

            if choice == "1":
                results = monitor.list_processes()
                processes = results.get("processes", [])
            else:
                processes = monitor.get_suspicious_processes()

        if choice == "1" and "error" in results:
            console.print(f"Error: {results.get('error', 'Unknown')}")
            return

        if not processes:
            console.print("No processes found")
            return

        # Create table
        proc_table = Table(title=f"Processes ({len(processes)})", box=box.ROUNDED)
        proc_table.add_column("PID", style="cyan", no_wrap=True)
        proc_table.add_column("Name", style="white")
        proc_table.add_column("Parent", style="dim")
        proc_table.add_column("CPU%", style="green")
        proc_table.add_column("MEM%", style="yellow")
        proc_table.add_column("Signed", style="blue")
        proc_table.add_column("NetConn", style="magenta")

        for proc in processes[:50]:  # Limit display
            signed = "+" if proc.get("signed") else "-"
            proc_table.add_row(
                str(proc.get("pid", "")),
                proc.get("name", "")[:30],
                proc.get("parent_name", "")[:20],
                f"{proc.get('cpu', 0):.1f}",
                f"{proc.get('memory', 0):.1f}",
                signed,
                str(proc.get("connections", 0)),
            )

        console.print(proc_table)

        # Show suspicious details
        if choice == "2":
            for proc in processes:
                reasons = proc.get("suspicious_reasons", [])
                if reasons:
                    console.print(f"\nSuspicious PID {proc['pid']} ({proc['name']})")
                    for reason in reasons:
                        console.print(f"  X {reason}")

        logger.info("ProcessMonitor", f"Listed {len(processes)} processes")

    def cpu_usage_analyzer(self, monitor):
        """CPU Usage Analyzer - Shows processes consuming CPU"""
        self.clear_screen()
        console.print(Panel.fit("CPU Usage Analyzer", border_style="cyan"))

        # Get threshold from user
        threshold = Prompt.ask(
            "CPU threshold (%)",
            default="5.0"
        )

        try:
            threshold = float(threshold)
        except ValueError:
            threshold = 5.0

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description="Analyzing CPU usage...", total=None)
            analysis = monitor.analyze_cpu_usage(cpu_threshold=threshold)

        if "error" in analysis:
            console.print(f"Error: {analysis['error']}")
            return

        # Display summary
        summary = analysis.get("summary", {})
        console.print(f"\nAnalysis Summary:")
        console.print(f"  Total Processes: {analysis.get('total_processes', 0)}")
        console.print(f"  Total CPU Usage: {summary.get('total_cpu_usage', 0)}%")
        console.print(f"  Average CPU/Process: {summary.get('average_cpu_per_process', 0)}%")
        console.print(f"  Processes Above {threshold}%: {summary.get('processes_above_threshold', 0)}")
        console.print(f"  Suspicious High-CPU Processes: {summary.get('suspicious_high_cpu_count', 0)}")

        # Display top CPU consumers
        top_cpu = analysis.get("top_cpu_consumers", [])
        if top_cpu:
            console.print(f"\nTop 20 CPU Consumers:")
            cpu_table = Table(title="CPU Usage Ranking", box=box.ROUNDED)
            cpu_table.add_column("Rank", style="cyan", no_wrap=True)
            cpu_table.add_column("PID", style="cyan")
            cpu_table.add_column("Name", style="white")
            cpu_table.add_column("CPU%", style="green")
            cpu_table.add_column("MEM%", style="yellow")
            cpu_table.add_column("Signed", style="blue")
            cpu_table.add_column("ExecPath", style="dim")

            for idx, proc in enumerate(top_cpu, 1):
                signed = "+" if proc.get("signed") else "-"
                cpu_val = proc.get("cpu", 0)
                cpu_color = "red" if cpu_val > 50 else "yellow" if cpu_val > 20 else "green"
                cpu_table.add_row(
                    str(idx),
                    str(proc.get("pid", "")),
                    proc.get("name", "")[:25],
                    f"[{cpu_color}]{cpu_val:.1f}[/]",
                    f"{proc.get('memory', 0):.1f}",
                    signed,
                    proc.get("path", "")[:40]
                )

            console.print(cpu_table)

        # Display suspicious high-CPU processes
        suspicious_cpu = analysis.get("suspicious_cpu_processes", [])
        if suspicious_cpu:
            console.print(f"\nSuspicious High-CPU Processes:")
            for proc in suspicious_cpu:
                console.print(f"\nSuspicious PID {proc['pid']} - {proc['name']}")
                console.print(f"  CPU: {proc.get('cpu', 0):.1f}% | Memory: {proc.get('memory', 0):.1f}%")
                console.print(f"  Path: {proc.get('path', 'N/A')}")
                console.print(f"  Risk Factors:")
                for reason in proc.get("cpu_risk_reasons", []):
                    console.print(f"    X {reason}")

        # Display all high-CPU processes (above threshold)
        high_cpu = analysis.get("high_cpu_processes", [])
        if high_cpu and len(high_cpu) > 20:
            console.print(f"\nAll Processes Above {threshold}% CPU ({len(high_cpu)} total):")
            console.print("[dim]Showing first 50 entries[/]")
            all_cpu_table = Table(box=box.SIMPLE)
            all_cpu_table.add_column("PID", style="cyan")
            all_cpu_table.add_column("Name", style="white")
            all_cpu_table.add_column("CPU%", style="green")
            all_cpu_table.add_column("MEM%", style="yellow")
            all_cpu_table.add_column("NetConns", style="magenta")

            for proc in high_cpu[:50]:
                signed = "+" if proc.get("signed") else "-"
                all_cpu_table.add_row(
                    str(proc.get("pid", "")),
                    proc.get("name", "")[:30],
                    f"{proc.get('cpu', 0):.1f}",
                    f"{proc.get('memory', 0):.1f}",
                    str(proc.get("connections", 0))
                )

            console.print(all_cpu_table)

        logger.info("ProcessMonitor", f"CPU analysis complete: {summary.get('processes_above_threshold', 0)} processes above {threshold}%")

    def yara_scan(self):
        """YARA Scanner"""
        self.clear_screen()
        console.print(Panel.fit("YARA Scanner", border_style="cyan"))

        scanner = YaraScanner()

        # Create sample rules if none exist
        rules_dir = Path(__file__).parent / "signatures"
        if not list(rules_dir.glob("*.yar")) and not list(rules_dir.glob("*.yara")):
            if Confirm.ask("No YARA rules found. Create sample rules?"):
                scanner.create_sample_rule()
                console.print("Sample rules created!")

        file_path = Prompt.ask("Enter file path to scan")
        if not os.path.exists(file_path):
            console.print("File not found!")
            return

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description="Scanning with YARA...", total=None)
            results = scanner.scan(file_path)

        if results.get("error"):
            console.print(f"Error: {results['error']}")
            return

        matches = results.get("matches", [])
        if not matches:
            console.print("No YARA matches found")
        else:
            console.print(f"{len(matches)} YARA rule(s) matched!")
            for match in matches:
                rule_panel = Panel(
                    f"Rule: {match['rule']}\n"
                    f"Tags: {', '.join(match.get('tags', []))}\n"
                    f"Description: {match.get('meta', {}).get('description', 'N/A')}",
                    title="YARA Match",
                    border_style="red"
                )
                console.print(rule_panel)

        logger.info("YaraScan", f"Scanned: {file_path}")

    def pe_analyzer(self):
        """PE Analyzer"""
        self.clear_screen()
        console.print(Panel.fit("PE Analyzer", border_style="cyan"))

        file_path = Prompt.ask("Enter PE file path")
        if not os.path.exists(file_path):
            console.print("File not found!")
            return

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description="Analyzing PE file...", total=None)
            analyzer = PEAnalyzer()
            results = analyzer.analyze(file_path)

        if "error" in results:
            console.print(f"Error: {results['error']}")
            return

        # DOS Header
        dos = results.get("dos_header", {})
        if dos:
            dos_table = Table(title="DOS Header", box=box.ROUNDED)
            dos_table.add_column("Field", style="cyan")
            dos_table.add_column("Value", style="white")
            dos_table.add_row("e_magic", dos.get("e_magic", "N/A"))
            dos_table.add_row("e_lfanew", dos.get("e_lfanew", "N/A"))
            console.print(dos_table)

        # PE Header
        pe = results.get("pe_header", {})
        if pe:
            pe_table = Table(title="PE Header", box=box.ROUNDED)
            pe_table.add_column("Field", style="cyan")
            pe_table.add_column("Value", style="white")
            pe_table.add_row("Machine", pe.get("machine", "N/A"))
            pe_table.add_row("Number of Sections", str(pe.get("number_of_sections", 0)))
            pe_table.add_row("Timestamp", pe.get("timestamp_str", "N/A"))
            pe_table.add_row("Characteristics", pe.get("characteristics", "N/A"))
            console.print(pe_table)

        # Optional Header
        oh = results.get("optional_header", {})
        if oh:
            oh_table = Table(title="Optional Header", box=box.ROUNDED)
            oh_table.add_column("Field", style="cyan")
            oh_table.add_column("Value", style="white")
            oh_table.add_row("Entry Point", oh.get("entry_point", "N/A"))
            oh_table.add_row("Image Base", oh.get("image_base", "N/A"))
            oh_table.add_row("Subsystem", oh.get("subsystem", "N/A"))
            oh_table.add_row("OS Version", oh.get("major_os_version", "N/A"))
            oh_table.add_row("Size of Image", oh.get("size_of_image", "N/A"))
            console.print(oh_table)

        # Sections
        sections = results.get("sections", [])
        if sections:
            sec_table = Table(title="Sections", box=box.ROUNDED)
            sec_table.add_column("Name", style="cyan")
            sec_table.add_column("Virtual Address", style="white")
            sec_table.add_column("Virtual Size", style="white")
            sec_table.add_column("Raw Size", style="white")
            sec_table.add_column("Entropy", style="yellow")
            for sec in sections:
                entropy = sec.get("entropy", 0)
                entropy_str = f"{entropy:.2f}" if entropy > 7 else f"{entropy:.2f}"
                sec_table.add_row(
                    sec.get("name", ""),
                    sec.get("virtual_address", ""),
                    sec.get("virtual_size", ""),
                    str(sec.get("raw_size", 0)),
                    entropy_str,
                )
            console.print(sec_table)

        # Imports
        imports = results.get("imports", [])
        if imports:
            console.print(f"\nImports ({len(imports)} DLLs):")
            for imp in imports:
                dll = imp.get("dll", "")
                funcs = imp.get("functions", [])
                console.print(f"  {dll} ({len(funcs)} functions)")
                for func in funcs[:10]:
                    console.print(f"    - {func}")
                if len(funcs) > 10:
                    console.print(f"    - ... and {len(funcs) - 10} more")

        # Exports
        exports = results.get("exports", [])
        if exports:
            console.print(f"\nExports: {len(exports)} functions")
            for exp in exports[:20]:
                console.print(f"  > {exp}")

        # Resources
        resources = results.get("resources", [])
        if resources:
            console.print(f"\nResources: {len(resources)} entries")

        # Certificate
        if results.get("certificate"):
            console.print(f"\nDigital Certificate Present")

        # TLS
        if results.get("tls"):
            console.print(f"\nTLS Callbacks Present")

        logger.info("PEAnalyzer", f"Analyzed: {file_path}")

    def view_reports(self):
        """View existing reports"""
        self.clear_screen()
        console.print(Panel.fit("View Reports", border_style="cyan"))

        # Get list of report files
        reports = list(REPORTS_DIR.glob("*"))
        reports = [r for r in reports if r.suffix in [".txt", ".html", ".json", ".csv"]]
        reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)

        if not reports:
            console.print("No reports found in the reports directory")
            return

        console.print(f"\nFound {len(reports)} report(s):\n")

        # Display report list
        report_table = Table(title="Available Reports", box=box.ROUNDED)
        report_table.add_column("ID", style="cyan", no_wrap=True)
        report_table.add_column("Filename", style="white")
        report_table.add_column("Type", style="magenta")
        report_table.add_column("Size", style="yellow")
        report_table.add_column("Date", style="dim")

        for idx, report in enumerate(reports, 1):
            report_type = report.suffix.lstrip('.')
            size = report.stat().st_size
            mtime = datetime.fromtimestamp(report.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            report_table.add_row(str(idx), report.name, report_type.upper(), f"{size} bytes", mtime)

        console.print(report_table)

        # Ask user to select a report to view
        choice = Prompt.ask(f"\nEnter report ID to view (1-{len(reports)}) or press Enter to go back", default="")
        if not choice:
            return

        try:
            idx = int(choice) - 1
            if idx < 0 or idx >= len(reports):
                console.print("Invalid report ID!")
                return
            selected_report = reports[idx]
        except ValueError:
            console.print("Invalid input!")
            return

        # Read and display report content
        console.print(f"\nReading: {selected_report.name}\n")
        content = selected_report.read_text(encoding="utf-8")
        console.print(Panel(content[:5000] if len(content) > 5000 else content, 
                         title=f"Report Content ({len(content)} chars)", 
                         border_style="blue"))

        # Option to open in default application
        if selected_report.suffix == ".html":
            if Confirm.ask("Open in browser?"):
                import webbrowser
                webbrowser.open(selected_report.absolute())

        logger.info("ReportViewer", f"Viewed report: {selected_report}")

    def generate_report(self):
        """Generate Report"""
        self.clear_screen()
        console.print(Panel.fit("Generate Report", border_style="cyan"))

        console.print("Select action:")
        console.print("  1. File Analysis Report")
        console.print("  2. Scan History Report")
        console.print("  3. Custom Report")

        choice = Prompt.ask("Select option", choices=["1", "2", "3"])

        formats_str = Prompt.ask("Output formats (comma-separated: txt, json, csv, html)", default="txt")
        formats = [f.strip() for f in formats_str.split(",")]

        report_gen = ReportGenerator()

        if choice == "1":
            file_path = Prompt.ask("Enter file path to analyze")
            if not os.path.exists(file_path):
                console.print("File not found!")
                return

            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
                progress.add_task(description="Analyzing and generating report...", total=None)
                analyzer = FileAnalyzer()
                results = analyzer.analyze(file_path)
                report_files = report_gen.generate(results, "file_analysis", formats)

        elif choice == "2":
            history = db.get_scan_history(100)
            history_list = []
            for h in history:
                history_list.append({
                    "id": h[0],
                    "type": h[1],
                    "target": h[2],
                    "result": h[3],
                    "risk_score": h[4],
                    "timestamp": h[5],
                })
            report_files = report_gen.generate(history_list, "scan_history", formats)

        else:
            data = {"message": "Custom report data"}
            report_files = report_gen.generate(data, "custom", formats)

        console.print(f"\nReports generated:")
        for fmt, path in report_files.items():
            console.print(f"  {fmt.upper()}: {path}")

        logger.info("ReportGenerator", f"Generated reports: {formats}")

    def settings_menu(self):
        """Settings menu"""
        self.clear_screen()
        console.print(Panel.fit("Settings", border_style="cyan"))

        settings_table = Table(box=box.ROUNDED)
        settings_table.add_column("Setting", style="cyan")
        settings_table.add_column("Value", style="white")
        settings_table.add_column("Description", style="dim")

        settings_table.add_row("Theme", self.settings.get("theme", "dark"), "UI Theme")
        settings_table.add_row("Threads", str(self.settings.get("threads", 4)), "Parallel threads")
        settings_table.add_row("Timeout", str(self.settings.get("timeout", 30)) + "s", "Request timeout")

        console.print(settings_table)

        console.print("\nOptions:")
        console.print("  1. Change Threads")
        console.print("  2. Change Timeout")
        console.print("  3. Clear Cache")
        console.print("  4. Check for Updates")
        console.print("  5. Back to Main Menu")

        choice = Prompt.ask("Select option", choices=["1", "2", "3", "4", "5"])

        if choice == "1":
            threads = Prompt.ask("Threads count", default="4")
            self.settings["threads"] = int(threads)
            console.print("Updated!")

        elif choice == "2":
            timeout = Prompt.ask("Timeout in seconds", default="30")
            self.settings["timeout"] = int(timeout)
            console.print("Updated!")

        elif choice == "3":
            cache.clear()
            console.print("Cache cleared!")

        elif choice == "4":
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
                progress.add_task(description="Checking for updates...", total=None)
                updater = Updater()
                result = updater.check()
            if result.get("update_available"):
                console.print(f"Update available: v{result['latest_version']}")
            else:
                console.print(f"You're up to date (v{APP_VERSION})")

    def hash_checker_menu(self):
        """Hash Checker menu"""
        self.clear_screen()
        console.print(Panel.fit("Hash Checker", border_style="cyan"))
        file_path = Prompt.ask("Enter file path")
        if not os.path.exists(file_path):
            console.print("File not found!")
            return
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description="Calculating hashes...", total=None)
            checker = HashChecker()
            results = checker.check(file_path)
        if "error" in results:
            console.print(f"Error: {results['error']}")
            return
        table = Table(title="File Hashes & IOC Check", box=box.ROUNDED)
        table.add_column("Algorithm", style="cyan")
        table.add_column("Hash", style="white")
        table.add_column("IOC Match", style="red")
        for algo in ['md5', 'sha1', 'sha256', 'sha512']:
            h = results.get("hashes", {}).get(algo, "")
            match = "MALICIOUS" if algo in results.get("ioc_matches", {}) else "Clean"
            table.add_row(algo.upper(), h[:64], match)
        console.print(table)

    def virustotal_menu(self):
        """VirusTotal Integration"""
        self.clear_screen()
        console.print(Panel.fit("VirusTotal Integration", border_style="magenta"))
        vt = VirusTotal()
        api_key = self.settings.get("vt_api_key", "")
        if not api_key:
            console.print("Tip: If paste doesn't work, save key to a file and select option 2")
            console.print("1. Enter API key manually")
            console.print("2. Load API key from file")
            input_method = Prompt.ask("Select method", choices=["1", "2"])
            
            if input_method == "1":
                api_key = Prompt.ask("Enter VirusTotal API key (or leave empty to skip)")
            else:
                key_file = Prompt.ask("Enter path to file containing API key")
                try:
                    with open(key_file, 'r') as f:
                        api_key = f.read().strip()
                    console.print("Loaded API key from file")
                except Exception as e:
                    console.print(f"Error reading file: {e}")
                    api_key = ""
            
            if api_key:
                self.settings["vt_api_key"] = api_key
                vt.set_api_key(api_key)
            else:
                console.print("No API key - using local checks only")
        else:
            vt.set_api_key(api_key)
        console.print("1. Check File Hash")
        console.print("2. Check Domain")
        console.print("3. Check IP")
        choice = Prompt.ask("Select", choices=["1", "2", "3"])
        
        # Collect input BEFORE starting progress indicator
        if choice == "1":
            file_path = Prompt.ask("Enter file path or hash")
        elif choice == "2":
            domain = Prompt.ask("Enter domain")
        else:
            ip = Prompt.ask("Enter IP")
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description="Querying VirusTotal...", total=None)
            if choice == "1":
                if os.path.exists(file_path):
                    result = vt.get_file_report(file_path)
                else:
                    result = vt.check_hash(file_path.strip())
            elif choice == "2":
                result = vt.get_domain_report(domain)
            else:
                result = vt.get_ip_report(ip)
        if "error" in result:
            console.print(f"{result['error']}")
            return
        
        # Display risk assessment
        malicious = result.get("malicious", 0)
        suspicious = result.get("suspicious", 0)
        total = result.get("total_engines", 1)
        
        risk_score = int(((malicious + suspicious) / total * 100)) if total > 0 else 0
        
        if risk_score <= 10:
            risk_level = "LOW"
            risk_color = "green"
        elif risk_score <= 30:
            risk_level = "MEDIUM"
            risk_color = "yellow"
        elif risk_score <= 60:
            risk_level = "HIGH"
            risk_color = "red"
        else:
            risk_level = "CRITICAL"
            risk_color = "bold red"
        
        bar_length = 40
        filled = int(bar_length * risk_score / 100)
        bar = "#" * filled + "-" * (bar_length - filled)
        
        console.print(f"\nVT Risk Assessment:")
        console.print(f"Score: {risk_score}% | [{risk_color}]{bar}[/] | [{risk_color}]{risk_level}[/]")
        
        # Detailed stats
        table = Table(title="VirusTotal Results", box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        
        # Determine what type of result this is
        if "domain" in result:
            table.add_row("Domain", result.get("domain", "N/A"))
            table.add_row("Reputation", str(result.get("reputation", "N/A")))
        elif "ip" in result:
            table.add_row("IP Address", result.get("ip", "N/A"))
            table.add_row("Country", result.get("country", "N/A"))
            table.add_row("ASN", result.get("asn", "N/A"))
            table.add_row("AS Owner", result.get("as_owner", "N/A"))
            table.add_row("Reputation", str(result.get("reputation", "N/A")))
        else:
            table.add_row("Hash", result.get("hash", "N/A")[:64])
            if result.get("meaningful_name"):
                table.add_row("Name", result.get("meaningful_name", ""))
            if result.get("type_description"):
                table.add_row("Type", result.get("type_description", ""))
            if result.get("threat_label"):
                table.add_row("Threat Label", f"{result.get('threat_label', '')}")
            table.add_row("Times Submitted", str(result.get("times_submitted", 0)))
        
        table.add_row("Malicious", f"{malicious}")
        table.add_row("Suspicious", f"{suspicious}")
        table.add_row("Undetected", f"{result.get('undetected', 0)}")
        table.add_row("Harmless", f"{result.get('harmless', 0)}")
        table.add_row("Total Engines", str(total))
        if result.get("scan_date"):
            table.add_row("Scan Date", str(result.get("scan_date", ""))[:19])
        console.print(table)
        
        if result.get("detections"):
            console.print(f"\nDetections ({len(result['detections'])} engines):")
            det_table = Table(title="Detecting Engines", box=box.SIMPLE)
            det_table.add_column("Engine", style="red")
            det_table.add_column("Result", style="yellow")
            for d in result["detections"][:15]:
                det_table.add_row(d["engine"], d["result"])
            console.print(det_table)

    def batch_scanner_menu(self):
        """Batch Directory Scanner"""
        self.clear_screen()
        console.print(Panel.fit("Batch Directory Scanner", border_style="magenta"))
        console.print("1. Scan Directory for Suspicious Files")
        console.print("2. Find Duplicate Files")
        console.print("3. Scan by IOC Hashes")
        choice = Prompt.ask("Select", choices=["1", "2", "3"])
        directory = Prompt.ask("Enter directory path")
        scanner = BatchScanner(threads=self.settings.get("threads", 4))
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description="Scanning...", total=None)
            if choice == "1":
                results = scanner.scan_directory(directory)
            elif choice == "2":
                results = scanner.find_duplicates(directory)
            else:
                from core.database import db
                iocs = []
                results = scanner.scan_by_ioc(directory, iocs)
        if "error" in results:
            console.print(f"{results['error']}")
            return
        if choice == "1":
            summary = results.get("summary", {})
            console.print(f"\nTotal Files: {results['total_files']}")
            console.print(f"Suspicious: {len(results['suspicious_files'])}")
            console.print(f"High Entropy: {summary.get('high_entropy', 0)}")
            for f in results["suspicious_files"][:20]:
                risk = f.get("risk_score", 0)
                color = "red" if risk > 70 else "yellow"
                console.print(f"  [{color}] {f.get('name', '')} (Risk: {risk}%)[/]")
                for r in f.get("reasons", []):
                    console.print(f"    - {r}")
        elif choice == "2":
            console.print(f"\nDuplicates Found: {results.get('total_duplicates', 0)}")
            for d in results.get("duplicates", [])[:10]:
                console.print(f"  {d.get('duplicate', '')}")
                console.print(f"    - Original: {d.get('original', '')}")

    def watchdog_menu(self):
        """Watchdog Monitor"""
        self.clear_screen()
        console.print(Panel.fit("Watchdog - File System Monitor", border_style="magenta"))
        
        console.print("Enter directories to monitor (comma-separated):")
        console.print("Example: C:\\Users\\123\\Desktop,C:\\Users\\123\\Downloads")
        dirs_str = Prompt.ask("Directories", default="C:\\Users\\123\\Desktop,C:\\Users\\123\\Downloads")
        directories = [d.strip() for d in dirs_str.split(",") if d.strip()]
        
        # Validate directories
        valid_dirs = []
        for d in directories:
            path = Path(d)
            if not path.exists():
                console.print(f"Skipping non-existent: {d}")
            elif not path.is_dir():
                console.print(f"Skipping (not a directory): {d}")
            else:
                valid_dirs.append(d)
        
        if not valid_dirs:
            console.print("No valid directories found!")
            return
        
        # Get monitoring duration
        duration = Prompt.ask("Monitoring duration (seconds)", default="10")
        try:
            duration = int(duration)
            duration = max(5, min(duration, 60))  # Clamp between 5-60 seconds
        except ValueError:
            duration = 10
        
        console.print(f"Monitoring {len(valid_dirs)} directory(ies) for {duration} seconds...")
        console.print("This will detect file changes in real-time")
        
        watchdog = Watchdog()
        events_detected = []
        
        def capture_event(event):
            events_detected.append(event)
        
        # Start monitoring
        try:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
                progress.add_task(description="Starting monitor...", total=None)
                result = watchdog.start(valid_dirs, callback=capture_event, interval=2.0)
            
            if result.get("status") != "started":
                console.print("Failed to start monitoring")
                return
            
            # Monitor for specified duration
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=False) as progress:
                progress.add_task(description=f"Monitoring... (will stop in {duration}s)", total=None)
                import time
                time.sleep(duration)
            
            watchdog.stop()
            
        except KeyboardInterrupt:
            watchdog.stop()
        
        # Show results
        events = watchdog.get_events()
        console.print(f"\nMonitoring complete")
        console.print(f"Total Events Detected: {len(events)}")
        
        if events:
            table = Table(title=f"File System Events ({min(len(events), 50)} shown)", box=box.ROUNDED)
            table.add_column("Type", style="cyan")
            table.add_column("Path", style="white")
            table.add_column("Time", style="dim")
            
            for e in events[-50:]:
                table.add_row(
                    e["type"], 
                    e["path"][:70],
                    e.get("timestamp", "")[:19]
                )
            console.print(table)
            
            # Summary by type
            created = len([e for e in events if e["type"] == "CREATED"])
            modified = len([e for e in events if e["type"] == "MODIFIED"])
            deleted = len([e for e in events if e["type"] == "DELETED"])
            
            console.print(f"\nSummary:")
            console.print(f"  Created: {created}")
            console.print(f"  Modified: {modified}")
            console.print(f"  Deleted: {deleted}")
        else:
            console.print("No file changes detected during monitoring period")

    def dns_whois_menu(self):
        """DNS & WHOIS Lookup"""
        self.clear_screen()
        console.print(Panel.fit("DNS & WHOIS Tools", border_style="magenta"))
        console.print("1. DNS Lookup")
        console.print("2. WHOIS Lookup")
        console.print("3. Email Checker")
        choice = Prompt.ask("Select", choices=["1", "2", "3"])
        target = Prompt.ask("Enter domain")
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description="Looking up...", total=None)
            if choice == "1":
                dns = DNSLookup()
                results = dns.lookup(target)
            elif choice == "2":
                w = WhoisLookup()
                results = w.lookup(target)
            else:
                email = Prompt.ask("Enter email address")
                ec = EmailChecker()
                results = ec.check(email)
        if "error" in results:
            console.print(f"{results['error']}")
            return
        if choice == "1":
            for rtype, records in results.get("records", {}).items():
                if records:
                    console.print(f"\n{rtype}")
                    for r in records[:10]:
                        console.print(f"  {r}")
        elif choice == "2":
            table = Table(title=f"WHOIS: {target}", box=box.ROUNDED)
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="white")
            for k, v in results.items():
                if v and k != "domain":
                    table.add_row(k.replace("_", " ").title(), str(v)[:80])
            console.print(table)
        else:
            for check, value in results.get("checks", {}).items():
                status = "Yes" if value else "No" if isinstance(value, bool) else str(value)[:60]
                console.print(f"  {check.replace('_', ' ').title()}: {status}")

    def fuzzy_hash_menu(self):
        """SSDEEP Fuzzy Hashing"""
        self.clear_screen()
        console.print(Panel.fit("Fuzzy Hashing (SSDEEP)", border_style="magenta"))
        ssdeep = SSDEEP()
        console.print("1. Generate Fuzzy Hash for File")
        console.print("2. Compare Two Files")
        console.print("3. Scan Directory")
        choice = Prompt.ask("Select", choices=["1", "2", "3"])
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description="Processing...", total=None)
            if choice == "1":
                file_path = Prompt.ask("Enter file path")
                fhash = ssdeep.hash_file(file_path)
                console.print(f"\nFuzzy Hash:")
                console.print(f"{fhash}")
            elif choice == "2":
                f1 = Prompt.ask("File 1")
                f2 = Prompt.ask("File 2")
                h1 = ssdeep.hash_file(f1)
                h2 = ssdeep.hash_file(f2)
                score = ssdeep.compare(h1, h2)
                console.print(f"\nSimilarity Score: {score}%")
                color = "red" if score > 70 else "yellow" if score > 40 else "green"
                bar = "#" * (score // 2) + "-" * (50 - score // 2)
                console.print(f"[{color}]{bar}[/]")
            else:
                directory = Prompt.ask("Enter directory")
                results = ssdeep.scan_directory(directory)
                console.print(f"Hashed {results.get('files_hashed', 0)} files")

    def ioc_feed_menu(self):
        """IOC Feed Manager"""
        self.clear_screen()
        console.print(Panel.fit("IOC Feed Manager", border_style="magenta"))
        feed = IOCFeed()
        console.print("1. Import IOC File")
        console.print("2. Fetch Remote Feed")
        console.print("3. View Database Stats")
        choice = Prompt.ask("Select", choices=["1", "2", "3"])
        if choice == "1":
            file_path = Prompt.ask("Enter IOC file path")
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
                progress.add_task(description="Importing...", total=None)
                result = feed.import_from_file(file_path)
            console.print(f"Imported: {result.get('imported', 0)} IOCs")
            if result.get("skipped", 0):
                console.print(f"Skipped: {result['skipped']}")
            if result.get("errors"):
                for e in result["errors"]:
                    console.print(f"Error: {e}")
        elif choice == "2":
            url = Prompt.ask("Enter feed URL")
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
                progress.add_task(description="Fetching...", total=None)
                result = feed.fetch_remote_feed(url)
            console.print(f"Fetched: {result.get('imported', 0)} IOCs")
        else:
            from core.database import db
            console.print("IOC Database Statistics")
            console.print(f"  Local database active at: cybertool.db")

    def correlation_menu(self):
        """Correlation Engine"""
        self.clear_screen()
        console.print(Panel.fit("Correlation Engine", border_style="magenta"))
        engine = CorrelationEngine()
        console.print("1. Analyze File + Process Correlation")
        console.print("2. View Scan Timeline")
        console.print("3. Full Threat Analysis")
        choice = Prompt.ask("Select", choices=["1", "2", "3"])
        
        # Collect input BEFORE starting progress indicator
        if choice == "1":
            file_path = Prompt.ask("Enter file path to correlate")
        elif choice == "2":
            pass  # No input needed for timeline
        else:
            file_path = Prompt.ask("Enter file path")
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description="Correlating data...", total=None)
            if choice == "1":
                fa = FileAnalyzer()
                fr = fa.analyze(file_path)
                pm = ProcessMonitor()
                pr = pm.list_processes()
                results = engine.analyze(file_results=fr, process_results=pr)
            elif choice == "2":
                results = engine.get_timeline()
            else:
                fa = FileAnalyzer()
                fr = fa.analyze(file_path)
                pm = ProcessMonitor()
                pr = pm.list_processes()
                results = engine.analyze(file_results=fr, process_results=pr)
        if "error" in results:
            console.print(f"{results.get('error', 'Unknown error')}")
            return
        self.display_risk_score({"score": results.get("risk_score", 0), "reasons": []})
        if results['threat_level'] == 'CRITICAL':
            console.print(f"\nTHREAT LEVEL: {results['threat_level']}")
        elif results['threat_level'] == 'HIGH':
            console.print(f"\nTHREAT LEVEL: {results['threat_level']}")
        elif results['threat_level'] == 'MEDIUM':
            console.print(f"\nTHREAT LEVEL: {results['threat_level']}")
        else:
            console.print(f"\nTHREAT LEVEL: {results['threat_level']}")
        for finding in results.get("findings", []):
            weight = finding.get("weight", 0)
            color = "red" if weight > 25 else "yellow"
            console.print(f"  ! {finding['description']}")

    def browser_forensics_menu(self):
        """Browser Forensics"""
        self.clear_screen()
        console.print(Panel.fit("Browser Forensics", border_style="magenta"))
        bf = BrowserForensics()
        console.print("This will analyze Chrome, Edge, Brave, Firefox browser artifacts")
        if not Confirm.ask("Continue?"):
            return
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description="Analyzing browsers...", total=None)
            results = bf.analyze()
        console.print(f"\nBrowsers Found: {', '.join(results.get('browsers_found', ['None']))}")
        console.print(f"History Entries: {len(results.get('history', []))}")
        console.print(f"Downloads: {len(results.get('downloads', []))}")
        console.print(f"Bookmarks: {len(results.get('bookmarks', []))}")
        console.print(f"Extensions: {len(results.get('extensions', []))}")
        suspicious = results.get("suspicious_entries", [])
        if suspicious:
            console.print(f"\nSuspicious URLs Found: {len(suspicious)}")
            for s in suspicious[:10]:
                console.print(f"  ! {s['url']}")
                for r in s.get("reasons", []):
                    console.print(f"    - {r}")
        if results.get("extensions"):
            console.print(f"\nInstalled Extensions:")
            for ext in results["extensions"][:15]:
                perms = ext.get("permissions", [])
                has_suspicious = any(p in str(perms).lower() for p in ["tabs", "history", "cookies", "webrequest", "native"])
                color = "red" if has_suspicious else "green"
                console.print(f"  [+] {ext.get('name', 'Unknown')} v{ext.get('version', '?')}")

    def usb_forensics_menu(self):
        """USB Forensics"""
        self.clear_screen()
        console.print(Panel.fit("USB Forensics", border_style="magenta"))
        usb = USBForensics()
        console.print("Analyzing USB device history from registry...")
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description="Analyzing USB artifacts...", total=None)
            results = usb.analyze()
        summary = results.get("summary", {})
        console.print(f"\nUSB Analysis Complete:")
        console.print(f"  Currently Connected: {summary.get('current_devices', 0)}")
        console.print(f"  Historical Devices: {summary.get('historical_devices', 0)}")
        console.print(f"  Unique Devices: {summary.get('total_unique', 0)}")
        if results.get("current_devices"):
            table = Table(title="Current USB Devices", box=box.ROUNDED)
            table.add_column("Device", style="cyan")
            table.add_column("Mount", style="white")
            table.add_column("Size", style="green")
            for d in results["current_devices"]:
                table.add_row(d.get("device", ""), d.get("mount_point", ""), d.get("total_size", ""))
            console.print(table)
        if results.get("historical_devices"):
            table = Table(title="Recent USB Devices", box=box.ROUNDED)
            table.add_column("Model", style="cyan")
            table.add_column("Serial", style="white")
            table.add_column("First Install", style="yellow")
            for d in results["historical_devices"][-20:]:
                table.add_row(d.get("model", ""), d.get("serial", "")[-12:], d.get("first_install", ""))
            console.print(table)

    def memory_analysis_menu(self):
        """Memory Analysis"""
        self.clear_screen()
        console.print(Panel.fit("Memory Analysis", border_style="magenta"))
        ma = MemoryAnalyzer()
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description="Analyzing memory...", total=None)
            results = ma.analyze()
        if "error" in results:
            console.print(f"{results['error']}")
            return

        # Memory Health
        health = results.get("memory_health", {})
        if health:
            status = health.get("status", "OK")
            color = "green" if status == "OK" else "yellow" if status == "WARNING" else "red"
            console.print(Panel(
                f"Status: [{color}]{status}[/]",
                title="Memory Health",
                border_style=color
            ))
            for w in health.get("warnings", []):
                console.print(f"  [!] {w}")

        # Memory Usage
        mem = results.get("memory", {})
        if mem:
            table = Table(title="Memory Usage", box=box.ROUNDED)
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="white")
            table.add_row("Total", f"{mem.get('total', 0)} GB")
            table.add_row("Used", f"{mem.get('used', 0)} GB")
            table.add_row("Available", f"{mem.get('available', 0)} GB")
            table.add_row("Usage", f"{mem.get('percent', 0)}%")
            console.print(table)

        # Swap
        swap = results.get("swap", {})
        if swap:
            console.print(f"Swap: {swap.get('used', 0)}/{swap.get('total', 0)} GB ({swap.get('percent', 0)}%)")

        # Top Memory Processes
        top_procs = results.get("top_processes", [])
        if top_procs:
            proc_table = Table(title="Top Memory Processes", box=box.ROUNDED)
            proc_table.add_column("PID", style="cyan")
            proc_table.add_column("Name", style="white")
            proc_table.add_column("Memory %", style="yellow")
            proc_table.add_column("Memory MB", style="green")
            proc_table.add_column("CPU %", style="magenta")
            for p in top_procs[:15]:
                proc_table.add_row(
                    str(p.get("pid", "")),
                    p.get("name", "")[:30],
                    f"{p.get('memory_percent', 0):.1f}%",
                    f"{p.get('memory_mb', 0):.1f}",
                    f"{p.get('cpu_percent', 0):.1f}%"
                )
            console.print(proc_table)

        # Suspicious Processes
        suspicious = results.get("suspicious_processes", [])
        if suspicious:
            console.print(f"\nSuspicious Memory Processes ({len(suspicious)}):")
            for p in suspicious:
                console.print(f"  [!] PID {p['pid']} - {p['name']}")
                for r in p.get("suspicious_reasons", []):
                    console.print(f"      X {r}")

    def fraud_detection_menu(self):
        """Fraud Detection & Phishing Scanner"""
        self.clear_screen()
        console.print(Panel.fit("Fraud Detection & Phishing Scanner", border_style="red"))
        fd = FraudDetector()
        console.print("1. Analyze URL for Fraud")
        console.print("2. Analyze Email for Phishing")
        console.print("3. Analyze Text for Scams")
        console.print("4. Analyze Phone Number")
        console.print("5. Quick Phishing Scan URL")
        choice = Prompt.ask("Select", choices=["1", "2", "3", "4", "5"])
        
        # Collect input BEFORE starting progress indicator
        if choice in ["1", "5"]:
            url = Prompt.ask("Enter URL to analyze")
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
        elif choice == "2":
            email_content = Prompt.ask("Paste email content")
            sender = Prompt.ask("Sender (optional)", default="")
            subject = Prompt.ask("Subject (optional)", default="")
        elif choice == "3":
            text = Prompt.ask("Paste text to analyze")
        elif choice == "4":
            phone = Prompt.ask("Enter phone number")
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description="Analyzing for fraud...", total=None)
            if choice in ["1", "5"]:
                results = fd.analyze_url(url)
            elif choice == "2":
                results = fd.analyze_email(email_content, sender, subject)
            elif choice == "3":
                results = fd.analyze_text(text)
            else:
                results = fd.analyze_phone(phone)
        if "error" in results:
            console.print(f"{results['error']}")
            return
        self.display_risk_score({"score": results.get("risk_score", 0), "reasons": []})
        risk_level = results.get("risk_level", "LOW")
        if risk_level == "CRITICAL":
            console.print(f"\n{risk_level} - This appears to be FRAUDULENT!")
        elif risk_level == "HIGH":
            console.print(f"\n{risk_level} - Multiple fraud indicators detected")
        elif risk_level == "MEDIUM":
            console.print(f"\n{risk_level} - Exercise caution")
        else:
            console.print(f"\n{risk_level} - No significant fraud indicators")
        findings = results.get("findings", [])
        if findings:
            table = Table(title="Fraud Indicators", box=box.ROUNDED)
            table.add_column("Category", style="red")
            table.add_column("Description", style="white")
            table.add_column("Weight", style="yellow")
            categories = {}
            for f in findings:
                cat = f.get("category", "Other")
                if cat not in categories:
                    categories[cat] = {"count": 0, "weight": 0}
                categories[cat]["count"] += 1
                categories[cat]["weight"] += f.get("weight", 0)
            for cat, info in sorted(categories.items(), key=lambda x: x[1]["weight"], reverse=True):
                color = "red" if info["weight"] >= 50 else "yellow" if info["weight"] >= 25 else "green"
                table.add_row(f"[{color}]{cat}[/]", f"{info['count']} indicators", str(info["weight"]))
            console.print(table)
            console.print("\nDetailed Findings:")
            for f in findings[:10]:
                color = "red" if f["weight"] >= 30 else "yellow"
                console.print(f"  ! {f['description']}")
                if f.get("recommendation"):
                    console.print(f"    - Tip: {f['recommendation']}")
        warnings = results.get("warnings", [])
        if warnings:
            for w in warnings:
                console.print(f"\n{w}")

    def phishing_scan_menu(self):
        """Phishing Scan - dedicated phishing analysis"""
        self.clear_screen()
        console.print(Panel.fit("Phishing Scan", border_style="red"))
        fd = FraudDetector()
        url = Prompt.ask("Enter URL to scan for phishing")
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description="Scanning for phishing...", total=None)
            results = fd.analyze_url(url)

        if "error" in results:
            console.print(f"{results['error']}")
            return

        self.display_risk_score({"score": results.get("risk_score", 0), "reasons": []})
        if results.get("risk_level") == "CRITICAL":
            console.print("\n[bold red]This URL appears to be a PHISHING site![/]")
        elif results.get("risk_level") == "HIGH":
            console.print("\n[red]Multiple phishing indicators detected[/]")
        else:
            console.print("\n[green]No significant phishing indicators[/]")

        findings = results.get("findings", [])
        if findings:
            for f in findings[:5]:
                console.print(f"  ! {f['description']}")
        logger.info("PhishingScan", f"Scanned URL: {url}")

    def exit_app(self):
        """Exit application"""
        console.print("\nShutting down CyberTool...")
        db.close()
        self.running = False
        console.print("Goodbye!")


def main():
    """Entry point"""
    try:
        app = CyberTool()
        app.run()
    except KeyboardInterrupt:
        console.print("\nInterrupted. Exiting...")
    except Exception as e:
        console.print(f"Fatal error: {e}")
        logger.error("Main", f"Fatal error: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    main()