"""
CyberTool URL Analyzer Module - Enhanced
"""
import re
import ssl
import socket
import hashlib
import html
from urllib.parse import urlparse, urljoin, parse_qs
from datetime import datetime
from difflib import SequenceMatcher
import requests
from core.logger import logger
from core.cache import cache
from config import URL_SHORTENERS


class URLAnalyzer:
    """Analyze URLs for suspicious characteristics - Enhanced"""

    # Known phishing keywords
    PHISHING_KEYWORDS = [
        "login", "signin", "verify", "account", "secure", "update", "confirm",
        "password", "credential", "banking", "paypal", "ebay", "amazon",
        "apple", "microsoft", "google", "facebook", "instagram", "whatsapp",
        "netflix", "pay", "payment", "billing", "invoice", "refund",
        "support", "helpdesk", "security", "alert", "warning", "suspended",
        "unusual", "activity", "unlock", "restore", "recover", "reset",
        "authenticate", "authorize", "verification", "2fa", "mfa",
        "wallet", "crypto", "bitcoin", "blockchain", "metamask",
        "steamcommunity", "origin", "battle.net", "ubisoft",
    ]

    # Suspicious TLDs often used in phishing
    SUSPICIOUS_TLDS = [
        ".tk", ".ml", ".ga", ".cf", ".gq",  # Free TLDs
        ".xyz", ".top", ".club", ".win", ".bid", ".download",
        ".review", ".date", ".men", ".loan", ".click",
        ".link", ".site", ".online", ".website", ".space",
        ".press", ".rest", ".moe", ".work", ".party",
        ".trade", ".science", ".gdn", ".wang", ".ltd",
    ]

    # Security headers to check
    SECURITY_HEADERS = {
        "Strict-Transport-Security": "HSTS (HTTP Strict Transport Security)",
        "Content-Security-Policy": "CSP (Content Security Policy)",
        "X-Content-Type-Options": "X-Content-Type-Options (nosniff)",
        "X-Frame-Options": "X-Frame-Options (clickjacking protection)",
        "X-XSS-Protection": "X-XSS-Protection",
        "Referrer-Policy": "Referrer Policy",
        "Permissions-Policy": "Permissions Policy",
        "Set-Cookie": "Secure/HttpOnly Cookie Flags",
    }

    # Brands for typosquatting detection
    BRAND_DOMAINS = {
        "google": ["google.com", "gmail.com", "youtube.com", "drive.google.com"],
        "facebook": ["facebook.com", "fb.com", "messenger.com", "instagram.com"],
        "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com", "azure.com", "msn.com"],
        "apple": ["apple.com", "icloud.com"],
        "amazon": ["amazon.com", "aws.amazon.com", "primevideo.com"],
        "paypal": ["paypal.com", "paypal.me"],
        "netflix": ["netflix.com", "nflx.com"],
        "twitter": ["twitter.com", "x.com", "t.co"],
        "linkedin": ["linkedin.com"],
        "whatsapp": ["whatsapp.com", "wa.me"],
        "telegram": ["telegram.org", "t.me"],
        "discord": ["discord.com", "discord.gg", "discordapp.com"],
        "github": ["github.com", "github.io"],
        "stackoverflow": ["stackoverflow.com", "stackexchange.com"],
        "reddit": ["reddit.com", "redd.it"],
        "tiktok": ["tiktok.com", "tiktokv.com"],
        "snapchat": ["snapchat.com"],
        "spotify": ["spotify.com"],
        "adobe": ["adobe.com"],
        "cloudflare": ["cloudflare.com"],
        "dropbox": ["dropbox.com", "db.tt"],
        "steam": ["steampowered.com", "steamcommunity.com"],
        "roblox": ["roblox.com"],
        "aliexpress": ["aliexpress.com", "alibaba.com"],
        "ebay": ["ebay.com", "ebay.co.uk"],
    }

    def __init__(self):
        self.results = {}

    def analyze(self, url):
        """Perform comprehensive URL analysis"""
        self.results = {
            "url": url,
            "parsed": {},
            "checks": {},
            "security_headers": {},
            "content_analysis": {},
            "phishing": {},
            "typosquatting": {},
            "dns_info": {},
            "reputation": {},
        }

        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""

            # ===== 1. BASIC PARSING =====
            self.results["parsed"] = {
                "scheme": parsed.scheme,
                "netloc": parsed.netloc,
                "path": parsed.path,
                "params": parsed.params,
                "query": parsed.query,
                "fragment": parsed.fragment,
                "hostname": hostname,
                "port": parsed.port,
                "full_url": url,
            }

            # ===== 2. BASIC CHECKS =====
            checks = self.results["checks"]

            # HTTPS check
            checks["https"] = parsed.scheme == "https"

            # URL length
            checks["url_length"] = len(url)
            checks["suspicious_length"] = len(url) > 200

            # Suspicious characters
            suspicious_chars = re.findall(r'[<>{}|\\^~`@#$%]', url)
            checks["suspicious_characters"] = suspicious_chars[:20]

            # Punycode detection
            checks["punycode"] = "xn--" in hostname.lower()

            # IP instead of domain
            ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
            checks["ip_instead_domain"] = bool(ip_pattern.match(hostname))

            # URL shortener check
            checks["is_shortener"] = any(
                shortener in hostname.lower() for shortener in URL_SHORTENERS
            )

            # Multiple subdomains
            subdomains = hostname.split('.')
            checks["subdomain_count"] = len(subdomains) - 2 if len(subdomains) > 2 else 0
            checks["many_subdomains"] = len(subdomains) > 4

            # ===== 3. TLD ANALYSIS =====
            checks["tld_analysis"] = self._analyze_tld(hostname)

            # ===== 4. PHISHING DETECTION =====
            self.results["phishing"] = self._detect_phishing(url, hostname, parsed)

            # ===== 5. TYPOSQUATTING DETECTION =====
            self.results["typosquatting"] = self._detect_typosquatting(hostname)

            # ===== 6. QUERY PARAMETER ANALYSIS =====
            checks["query_params"] = self._analyze_query_params(parsed.query)

            # ===== 7. REDIRECT CHECK =====
            checks["redirects"] = self._check_redirects(url)

            # ===== 8. CERTIFICATE CHECK =====
            if parsed.scheme == "https":
                checks["certificate"] = self._check_certificate(hostname)

            # ===== 9. PORT SCAN =====
            checks["open_ports"] = self._check_common_ports(hostname)

            # ===== 10. SECURITY HEADERS =====
            self.results["security_headers"] = self._check_security_headers(url)

            # ===== 11. CONTENT ANALYSIS =====
            self.results["content_analysis"] = self._analyze_content(url)

            # ===== 12. DNS INFO =====
            self.results["dns_info"] = self._get_dns_info(hostname)

            # ===== 13. REPUTATION SCORE =====
            self.results["reputation"] = self._calculate_reputation()

            logger.info("URLAnalyzer", f"Enhanced analysis for URL: {url}")

        except Exception as e:
            self.results["error"] = str(e)

        return self.results

    def _analyze_tld(self, hostname):
        """Analyze TLD for suspicious patterns"""
        result = {"tld": "", "suspicious": False, "reasons": []}

        try:
            # Extract TLD
            parts = hostname.split('.')
            if len(parts) >= 2:
                tld = "." + parts[-1].lower()
                result["tld"] = tld

                # Check against suspicious TLDs
                if tld in self.SUSPICIOUS_TLDS:
                    result["suspicious"] = True
                    result["reasons"].append(f"Suspicious TLD: {tld} (commonly used in phishing)")

                # Check for uncommon TLDs
                common_tlds = {".com", ".org", ".net", ".edu", ".gov", ".mil", ".int",
                               ".uk", ".de", ".fr", ".jp", ".ru", ".cn", ".br", ".au",
                               ".ca", ".in", ".it", ".nl", ".es", ".se", ".no", ".fi",
                               ".dk", ".pl", ".be", ".at", ".ch", ".ie", ".nz", ".sg",
                               ".hk", ".kr", ".za", ".mx", ".ar", ".co", ".io", ".me",
                               ".info", ".biz", ".pro", ".name", ".mobi", ".asia"}
                if tld not in common_tlds and not result["suspicious"]:
                    result["reasons"].append(f"Uncommon TLD: {tld}")

        except Exception:
            pass

        return result

    def _detect_phishing(self, url, hostname, parsed):
        """Detect phishing indicators in URL"""
        result = {
            "is_phishing": False,
            "risk_score": 0,
            "indicators": [],
            "brand_impersonation": [],
        }

        url_lower = url.lower()
        path_lower = parsed.path.lower()
        query_lower = parsed.query.lower()

        # 1. Check for phishing keywords in path and query
        found_keywords = []
        for keyword in self.PHISHING_KEYWORDS:
            if keyword in path_lower or keyword in query_lower:
                found_keywords.append(keyword)

        if found_keywords:
            result["indicators"].append(f"Phishing keywords in URL: {', '.join(found_keywords[:8])}")
            result["risk_score"] += min(len(found_keywords) * 5, 30)

        # 2. Check for brand impersonation in hostname
        for brand, domains in self.BRAND_DOMAINS.items():
            if brand in hostname.lower():
                # Check if it's actually the legitimate domain
                is_legitimate = any(
                    legit_domain in hostname.lower() for legit_domain in domains
                )
                if not is_legitimate:
                    result["brand_impersonation"].append(brand)
                    result["indicators"].append(f"Possible {brand} brand impersonation")
                    result["risk_score"] += 25

        # 3. Check for @ symbol in URL (redirect trick)
        if "@" in url_lower and "@" not in hostname:
            result["indicators"].append("URL contains @ symbol (credential theft trick)")
            result["risk_score"] += 20

        # 4. Check for excessive path depth
        path_depth = len([p for p in parsed.path.split('/') if p])
        if path_depth > 5:
            result["indicators"].append(f"Deep path structure ({path_depth} levels)")
            result["risk_score"] += 5

        # 5. Check for hex encoding in hostname
        if re.search(r'%[0-9a-fA-F]{2}', hostname):
            result["indicators"].append("Hex encoding in hostname")
            result["risk_score"] += 15

        # 6. Check for multiple dots in hostname (subdomain trick)
        dot_count = hostname.count('.')
        if dot_count > 3:
            result["indicators"].append(f"Excessive subdomains ({dot_count} dots)")
            result["risk_score"] += 10

        # 7. Check for suspicious port usage
        if parsed.port and parsed.port not in [80, 443, 8080, 8443]:
            result["indicators"].append(f"Non-standard port: {parsed.port}")
            result["risk_score"] += 10

        # 8. Check for data URI scheme
        if parsed.scheme == "data":
            result["indicators"].append("Data URI scheme (possible obfuscation)")
            result["risk_score"] += 20

        # 9. Check for javascript scheme
        if parsed.scheme == "javascript":
            result["indicators"].append("JavaScript URI scheme")
            result["risk_score"] += 30

        # 10. Check for homograph attack (mixed scripts)
        if self._has_mixed_scripts(hostname):
            result["indicators"].append("Possible homograph attack (mixed character scripts)")
            result["risk_score"] += 30

        # Determine if phishing
        if result["risk_score"] >= 20:
            result["is_phishing"] = True

        return result

    def _has_mixed_scripts(self, hostname):
        """Detect homograph attacks using mixed Unicode scripts"""
        try:
            # Check if hostname contains non-ASCII characters
            if not all(ord(c) < 128 for c in hostname):
                # Check for Cyrillic, Greek, or other lookalike characters
                scripts = set()
                for c in hostname:
                    cp = ord(c)
                    if 0x0400 <= cp <= 0x04FF:  # Cyrillic
                        scripts.add("cyrillic")
                    elif 0x0370 <= cp <= 0x03FF:  # Greek
                        scripts.add("greek")
                    elif 0x1E00 <= cp <= 0x1EFF:  # Latin Extended
                        scripts.add("latin_ext")
                    elif 0x0100 <= cp <= 0x024F:  # Latin Extended-A/B
                        scripts.add("latin_ext")
                    elif cp > 0x00FF and cp < 0x0400:
                        scripts.add("other")
                return len(scripts) > 1
        except Exception:
            pass
        return False

    def _detect_typosquatting(self, hostname):
        """Detect typosquatting of popular domains"""
        result = {
            "is_typosquatting": False,
            "suspected_brands": [],
            "similarity_scores": [],
        }

        hostname_clean = hostname.lower()
        # Remove www. prefix for comparison
        if hostname_clean.startswith("www."):
            hostname_clean = hostname_clean[4:]

        for brand, domains in self.BRAND_DOMAINS.items():
            for legit_domain in domains:
                legit_clean = legit_domain.lower()
                if legit_clean == hostname_clean:
                    # Exact match - legitimate
                    continue

                # Calculate similarity
                similarity = SequenceMatcher(None, hostname_clean, legit_clean).ratio()

                if similarity > 0.7:
                    result["is_typosquatting"] = True
                    result["suspected_brands"].append(brand)
                    result["similarity_scores"].append({
                        "brand": brand,
                        "legitimate_domain": legit_domain,
                        "similarity": round(similarity * 100, 1),
                    })

                # Check for common typosquatting techniques
                # 1. Missing character
                if len(hostname_clean) == len(legit_clean) - 1:
                    for i in range(len(legit_clean)):
                        modified = legit_clean[:i] + legit_clean[i+1:]
                        if modified == hostname_clean:
                            result["is_typosquatting"] = True
                            result["suspected_brands"].append(brand)
                            result["similarity_scores"].append({
                                "brand": brand,
                                "legitimate_domain": legit_domain,
                                "technique": "missing_character",
                            })
                            break

                # 2. Extra character
                if len(hostname_clean) == len(legit_clean) + 1:
                    for i in range(len(hostname_clean)):
                        modified = hostname_clean[:i] + hostname_clean[i+1:]
                        if modified == legit_clean:
                            result["is_typosquatting"] = True
                            result["suspected_brands"].append(brand)
                            result["similarity_scores"].append({
                                "brand": brand,
                                "legitimate_domain": legit_domain,
                                "technique": "extra_character",
                            })
                            break

                # 3. Character substitution (e.g., rn -> m)
                if len(hostname_clean) == len(legit_clean):
                    substitutions = sum(1 for a, b in zip(hostname_clean, legit_clean) if a != b)
                    if 1 <= substitutions <= 2:
                        result["is_typosquatting"] = True
                        result["suspected_brands"].append(brand)
                        result["similarity_scores"].append({
                            "brand": brand,
                            "legitimate_domain": legit_domain,
                            "technique": "character_substitution",
                            "changes": substitutions,
                        })

        # Deduplicate brands
        result["suspected_brands"] = list(set(result["suspected_brands"]))

        return result

    def _analyze_query_params(self, query):
        """Analyze URL query parameters for suspicious patterns"""
        result = {
            "param_count": 0,
            "suspicious_params": [],
            "has_redirect_param": False,
            "has_base64": False,
        }

        if not query:
            return result

        params = parse_qs(query)
        result["param_count"] = len(params)

        # Check for redirect parameters
        redirect_params = ["redirect", "redirect_uri", "return", "return_to",
                          "return_url", "next", "url", "link", "goto", "target",
                          "destination", "continue", "continue_to", "follow"]
        for param in params:
            if param.lower() in redirect_params:
                result["has_redirect_param"] = True
                result["suspicious_params"].append(f"Open redirect parameter: {param}")

        # Check for base64 encoded values
        for param, values in params.items():
            for value in values:
                if re.match(r'^[A-Za-z0-9+/=]{20,}$', value):
                    try:
                        decoded = base64_decode(value)
                        if decoded and b'http' in decoded.lower():
                            result["has_base64"] = True
                            result["suspicious_params"].append(f"Base64 encoded URL in parameter: {param}")
                    except Exception:
                        pass

        return result

    def _check_redirects(self, url):
        """Check URL redirects"""
        try:
            response = requests.get(url, timeout=10, allow_redirects=True,
                                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                                    verify=False)
            redirects = []
            if response.history:
                for resp in response.history:
                    redirects.append({
                        "from": resp.url,
                        "status": resp.status_code,
                    })
            return {
                "final_url": response.url,
                "redirect_count": len(redirects),
                "redirects": redirects,
                "status_code": response.status_code,
            }
        except requests.exceptions.SSLError:
            return {"error": "SSL certificate error"}
        except requests.exceptions.ConnectionError:
            return {"error": "Connection failed"}
        except requests.exceptions.Timeout:
            return {"error": "Request timeout"}
        except Exception as e:
            return {"error": str(e)}

    def _check_certificate(self, hostname):
        """Check SSL certificate with detailed info"""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        # Parse issuer
                        issuer = {}
                        for item in cert.get("issuer", []):
                            for key, value in item:
                                issuer[key] = value

                        # Parse subject
                        subject = {}
                        for item in cert.get("subject", []):
                            for key, value in item:
                                subject[key] = value

                        # Check expiration
                        valid_from = cert.get("notBefore", "")
                        valid_to = cert.get("notAfter", "")
                        is_expired = False
                        days_remaining = 0
                        try:
                            if valid_to:
                                expiry_date = datetime.strptime(valid_to, "%b %d %H:%M:%S %Y %Z")
                                days_remaining = (expiry_date - datetime.now()).days
                                is_expired = days_remaining < 0
                        except Exception:
                            pass

                        # Get SAN (Subject Alternative Names)
                        san = []
                        for ext in cert.get("subjectAltName", []):
                            san.append(ext[1])

                        return {
                            "issuer": issuer,
                            "subject": subject,
                            "valid_from": valid_from,
                            "valid_to": valid_to,
                            "serial": cert.get("serialNumber"),
                            "version": cert.get("version"),
                            "san": san[:20],
                            "is_expired": is_expired,
                            "days_remaining": days_remaining,
                            "fingerprint_sha256": ssock.shared_ciphers()[0][0] if ssock.shared_ciphers() else "N/A",
                        }
            return None
        except ssl.SSLCertVerificationError as e:
            return {"error": f"SSL verification failed: {str(e)}"}
        except ssl.SSLError as e:
            return {"error": f"SSL error: {str(e)}"}
        except socket.timeout:
            return {"error": "Connection timeout"}
        except Exception as e:
            return {"error": str(e)}

    def _check_common_ports(self, hostname):
        """Check common open ports"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443]
        open_ports = []
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((hostname, port))
                if result == 0:
                    # Try to get service banner
                    try:
                        sock.settimeout(1)
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()[:50]
                    except Exception:
                        banner = ""
                    open_ports.append({"port": port, "banner": banner})
                sock.close()
            except Exception:
                continue
        return open_ports

    def _check_security_headers(self, url):
        """Check HTTP security headers"""
        result = {
            "headers": {},
            "missing_headers": [],
            "present_headers": [],
            "security_score": 0,
        }

        try:
            response = requests.get(url, timeout=10, allow_redirects=True,
                                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                                    verify=False)

            response_headers = {k.lower(): v for k, v in response.headers.items()}

            for header, description in self.SECURITY_HEADERS.items():
                header_lower = header.lower()
                if header_lower in response_headers:
                    value = response_headers[header_lower]
                    result["present_headers"].append(header)
                    result["headers"][header] = {
                        "present": True,
                        "value": value[:200],
                        "description": description,
                    }
                    result["security_score"] += 15
                else:
                    result["missing_headers"].append(header)
                    result["headers"][header] = {
                        "present": False,
                        "description": description,
                    }

            # Check for secure cookie flags
            if "set-cookie" in response_headers:
                cookie_header = response_headers["set-cookie"]
                result["headers"]["Set-Cookie"] = {
                    "present": True,
                    "has_secure": "secure" in cookie_header.lower(),
                    "has_httponly": "httponly" in cookie_header.lower(),
                    "has_samesite": "samesite" in cookie_header.lower(),
                    "value": cookie_header[:200],
                }
                if "secure" in cookie_header.lower():
                    result["security_score"] += 10
                if "httponly" in cookie_header.lower():
                    result["security_score"] += 10
                if "samesite" in cookie_header.lower():
                    result["security_score"] += 10

            # Check server header (information disclosure)
            if "server" in response_headers:
                result["headers"]["Server"] = {
                    "present": True,
                    "value": response_headers["server"][:100],
                    "info_disclosure": True,
                }

            # Check for X-Powered-By (information disclosure)
            if "x-powered-by" in response_headers:
                result["headers"]["X-Powered-By"] = {
                    "present": True,
                    "value": response_headers["x-powered-by"][:100],
                    "info_disclosure": True,
                }

        except requests.exceptions.SSLError:
            result["error"] = "SSL certificate error"
        except requests.exceptions.ConnectionError:
            result["error"] = "Connection failed"
        except Exception as e:
            result["error"] = str(e)

        return result

    def _analyze_content(self, url):
        """Analyze page content for suspicious elements"""
        result = {
            "has_content": False,
            "title": "",
            "has_login_form": False,
            "has_iframe": False,
            "has_external_scripts": False,
            "has_trackers": False,
            "form_action_external": False,
            "suspicious_elements": [],
            "content_length": 0,
        }

        try:
            response = requests.get(url, timeout=10, allow_redirects=True,
                                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                                    verify=False)

            content = response.text
            result["has_content"] = True
            result["content_length"] = len(content)

            # Extract title
            title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
            if title_match:
                result["title"] = html.unescape(title_match.group(1).strip())[:200]

            # Check for login forms
            login_patterns = [
                r'<input[^>]*type=["\']password["\']',
                r'<input[^>]*name=["\'](?:login|password|passwd|pwd|signin|username)["\']',
                r'<form[^>]*action=["\'].*(?:login|signin|auth|verify)["\']',
            ]
            for pattern in login_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    result["has_login_form"] = True
                    result["suspicious_elements"].append("Login form detected")
                    break

            # Check for iframes
            if re.search(r'<iframe[^>]*>', content, re.IGNORECASE):
                result["has_iframe"] = True
                result["suspicious_elements"].append("Iframe detected (possible clickjacking)")

            # Check for external scripts
            external_scripts = re.findall(r'<script[^>]*src=["\'](https?://[^"\']+)["\']', content, re.IGNORECASE)
            if external_scripts:
                result["has_external_scripts"] = True
                # Check if scripts are from different domain
                parsed = urlparse(url)
                base_domain = parsed.hostname or ""
                external_domains = set()
                for script_url in external_scripts:
                    script_parsed = urlparse(script_url)
                    if script_parsed.hostname and script_parsed.hostname != base_domain:
                        external_domains.add(script_parsed.hostname)
                if external_domains:
                    result["suspicious_elements"].append(f"External scripts from: {', '.join(list(external_domains)[:5])}")

            # Check for form actions pointing to external domains
            form_actions = re.findall(r'<form[^>]*action=["\'](https?://[^"\']+)["\']', content, re.IGNORECASE)
            for form_action in form_actions:
                action_parsed = urlparse(form_action)
                if action_parsed.hostname and action_parsed.hostname != base_domain:
                    result["form_action_external"] = True
                    result["suspicious_elements"].append(f"Form submits to external domain: {action_parsed.hostname}")

            # Check for common trackers
            tracker_patterns = [
                r'google-analytics\.com', r'googletagmanager\.com',
                r'facebook\.com/tr', r'analytics\.twitter\.com',
                r'hotjar\.com', r'newrelic\.com', r'fullstory\.com',
                r'mixpanel\.com', r'amplitude\.com', r'segment\.com',
                r'linkedin\.com/analytics', r'pinterest\.com/analytics',
                r'reddit\.com/analytics', r'tiktok\.com/analytics',
                r'snapchat\.com/analytics', r'quantserve\.com',
                r'criteo\.com', r'outbrain\.com', r'taboola\.com',
            ]
            for pattern in tracker_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    result["has_trackers"] = True
                    break

            # Check for obfuscated JavaScript
            obfuscation_patterns = [
                r'eval\s*\(', r'unescape\s*\(', r'String\.fromCharCode',
                r'atob\s*\(', r'btoa\s*\(', r'\\x[0-9a-fA-F]{2}',
                r'document\.write\s*\(', r'innerHTML\s*=',
            ]
            for pattern in obfuscation_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    result["suspicious_elements"].append(f"Obfuscated JavaScript detected: {pattern}")
                    break

        except requests.exceptions.SSLError:
            pass
        except requests.exceptions.ConnectionError:
            pass
        except Exception:
            pass

        return result

    def _get_dns_info(self, hostname):
        """Get DNS information for the hostname"""
        result = {
            "ip_addresses": [],
            "has_dns": False,
            "dns_error": None,
        }

        try:
            # Get IP addresses
            ips = socket.getaddrinfo(hostname, 80)
            ip_set = set()
            for ip_info in ips:
                ip_set.add(ip_info[4][0])
            result["ip_addresses"] = list(ip_set)
            result["has_dns"] = True
        except socket.gaierror as e:
            result["dns_error"] = f"DNS resolution failed: {str(e)}"
        except Exception as e:
            result["dns_error"] = str(e)

        return result

    def _calculate_reputation(self):
        """Calculate overall URL reputation score"""
        score = 50  # Start neutral
        reasons = []
        severity = "unknown"

        checks = self.results.get("checks", {})
        phishing = self.results.get("phishing", {})
        typosquatting = self.results.get("typosquatting", {})
        security = self.results.get("security_headers", {})
        content = self.results.get("content_analysis", {})

        # 1. No HTTPS
        if not checks.get("https"):
            score -= 15
            reasons.append("No HTTPS (insecure connection)")

        # 2. Suspicious length
        if checks.get("suspicious_length"):
            score -= 5
            reasons.append("Suspicious URL length")

        # 3. Punycode
        if checks.get("punycode"):
            score -= 15
            reasons.append("Punycode domain (possible homograph attack)")

        # 4. IP instead of domain
        if checks.get("ip_instead_domain"):
            score -= 20
            reasons.append("IP address used instead of domain name")

        # 5. URL shortener
        if checks.get("is_shortener"):
            score -= 10
            reasons.append("URL shortener (obscures final destination)")

        # 6. Many subdomains
        if checks.get("many_subdomains"):
            score -= 5
            reasons.append("Excessive subdomains")

        # 7. Suspicious TLD
        tld = checks.get("tld_analysis", {})
        if tld.get("suspicious"):
            score -= 15
            reasons.append(f"Suspicious TLD: {tld.get('tld', '')}")

        # 8. Phishing indicators
        if phishing.get("is_phishing"):
            score -= phishing.get("risk_score", 0)
            for indicator in phishing.get("indicators", [])[:3]:
                reasons.append(indicator)

        # 9. Typosquatting
        if typosquatting.get("is_typosquatting"):
            score -= 20
            brands = typosquatting.get("suspected_brands", [])
            reasons.append(f"Typosquatting of: {', '.join(brands)}")

        # 10. Missing security headers
        missing = security.get("missing_headers", [])
        if len(missing) >= 5:
            score -= 10
            reasons.append(f"Missing {len(missing)} security headers")
        elif len(missing) >= 3:
            score -= 5
            reasons.append(f"Missing {len(missing)} security headers")

        # 11. Content analysis
        if content.get("has_login_form") and not checks.get("https"):
            score -= 15
            reasons.append("Login form on non-HTTPS page")
        if content.get("form_action_external"):
            score -= 15
            reasons.append("Form submits credentials to external domain")
        if content.get("has_iframe"):
            score -= 5
            reasons.append("Page contains iframe (possible clickjacking)")

        # 12. Redirects
        redirects = checks.get("redirects", {})
        if redirects and "error" not in redirects:
            if redirects.get("redirect_count", 0) > 2:
                score -= 10
                reasons.append(f"Multiple redirects ({redirects['redirect_count']})")

        # Clamp score
        score = max(0, min(100, score))

        # Determine severity
        if score <= 20:
            severity = "malicious"
        elif score <= 40:
            severity = "suspicious"
        elif score <= 60:
            severity = "neutral"
        elif score <= 80:
            severity = "likely_safe"
        else:
            severity = "safe"

        return {
            "score": score,
            "severity": severity,
            "reasons": reasons,
        }


def base64_decode(s):
    """Safely decode base64 string"""
    import base64
    # Add padding if needed
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)