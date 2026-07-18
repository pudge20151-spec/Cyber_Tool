"""
CyberTool Fraud Detection Module
Detects phishing, scams, fake websites, social engineering
"""
import re
import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime
from pathlib import Path
from core.logger import logger
from core.cache import cache


class FraudDetector:
    """Detect various types of fraud and scams"""

    def __init__(self):
        self.results = {}
        self.risk_score = 0
        self.findings = []

    def analyze_url(self, url):
        """Analyze URL for fraud indicators"""
        self.results = {
            "target": url,
            "type": "url",
            "risk_score": 0,
            "risk_level": "LOW",
            "checks": {},
            "findings": [],
            "warnings": []
        }
        self.findings = []
        self.risk_score = 0

        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""

            # Phishing checks
            self._check_phishing_indicators(url, hostname, parsed)
            self._check_impersonation(hostname)
            self._check_suspicious_tld(hostname)
            self._check_url_obfuscation(url, hostname)
            self._check_fake_https(url, hostname)
            self._check_scam_keywords(url, hostname)
            self._check_redirect_loops(url)
            self._check_fake_shopping(url, hostname)
            self._check_tech_support_scam(url, hostname)
            self._check_crypto_scam(url, hostname)
            self._check_phishing_form(url)

            # Calculate final score
            self.risk_score = min(sum(f.get("weight", 0) for f in self.findings), 100)
            self.results["risk_score"] = self.risk_score
            self.results["findings"] = self.findings

            if self.risk_score >= 75:
                self.results["risk_level"] = "CRITICAL"
            elif self.risk_score >= 50:
                self.results["risk_level"] = "HIGH"
            elif self.risk_score >= 25:
                self.results["risk_level"] = "MEDIUM"
            else:
                self.results["risk_level"] = "LOW"

            # Generate warnings
            self._generate_warnings()

            logger.info("FraudDetector", f"Analyzed URL: {url} - Risk: {self.results['risk_level']}")

        except Exception as e:
            self.results["error"] = str(e)

        return self.results

    def analyze_email(self, email_content, sender="", subject=""):
        """Analyze email for fraud indicators"""
        self.results = {
            "type": "email",
            "risk_score": 0,
            "risk_level": "LOW",
            "findings": [],
            "warnings": []
        }
        self.findings = []
        self.risk_score = 0

        # Phishing email checks
        self._check_email_urgency(email_content, subject)
        self._check_email_requests(email_content)
        self._check_fake_links_in_text(email_content)
        self._check_spoofed_sender(sender)
        self._check_grammar_mistakes(email_content)
        self._check_threat_intimidation(email_content)
        self._check_attachment_warning(email_content)
        self._check_prize_scam(email_content, subject)
        self._check_invoice_scam(email_content, subject)
        self._check_ceo_fraud(email_content, sender, subject)

        self.risk_score = min(sum(f.get("weight", 0) for f in self.findings), 100)
        self.results["risk_score"] = self.risk_score
        self.results["findings"] = self.findings

        if self.risk_score >= 75:
            self.results["risk_level"] = "CRITICAL"
        elif self.risk_score >= 50:
            self.results["risk_level"] = "HIGH"
        elif self.risk_score >= 25:
            self.results["risk_level"] = "MEDIUM"
        else:
            self.results["risk_level"] = "LOW"

        self._generate_warnings()
        return self.results

    def analyze_phone(self, phone_number):
        """Analyze phone number for scam indicators"""
        self.results = {
            "type": "phone",
            "target": phone_number,
            "risk_score": 0,
            "risk_level": "LOW",
            "findings": [],
            "warnings": []
        }
        self.findings = []
        self.risk_score = 0

        # Clean number
        cleaned = re.sub(r'[\s\-\(\)\+]', '', phone_number)

        # Check for premium rate numbers
        if cleaned.startswith('809') or cleaned.startswith('900') or cleaned.startswith('901'):
            self._add_finding("Premium rate number", 30, "Scam", "Premium rate numbers are often used for fraud")

        # Check for international scam patterns
        if cleaned.startswith('44') and len(cleaned) > 11:
            self._add_finding("International premium risk", 15, "Warning", "UK premium numbers used in scams")

        # Check for known scam area codes
        scam_codes = ['876', '649', '758', '784', '473', '268', '664', '767', '809']
        for code in scam_codes:
            if cleaned.startswith('1' + code) or cleaned.startswith(code):
                self._add_finding(f"Caribbean scam risk (area {code})", 20, "Scam", "Known scam region")

        # Check for spoofed caller ID patterns
        if len(cleaned) == 11 and cleaned.startswith('1'):
            self._add_finding("US number with international prefix", 5, "Info", "Could be spoofed")

        self.risk_score = min(sum(f.get("weight", 0) for f in self.findings), 100)
        self.results["risk_score"] = self.risk_score
        self.results["findings"] = self.findings

        if self.risk_score >= 50:
            self.results["risk_level"] = "HIGH"
        elif self.risk_score >= 20:
            self.results["risk_level"] = "MEDIUM"
        else:
            self.results["risk_level"] = "LOW"

        return self.results

    def analyze_text(self, text):
        """Analyze any text for fraud patterns"""
        self.results = {
            "type": "text",
            "risk_score": 0,
            "risk_level": "LOW",
            "findings": [],
            "warnings": []
        }
        self.findings = []
        self.risk_score = 0

        text_lower = text.lower()

        # Check for scam patterns
        scam_patterns = {
            "Nigerian Prince / Advance Fee": [
                r'nigerian\s+prince', r'advance\s+fee', r'western\s+union',
                r'money\s+transfer', r' inheritance ', r'next\s+of\s+kin',
                r'bank\s+account\s+needed', r'fund\s+release', r'commission\s+payment'
            ],
            "Lottery / Prize Scam": [
                r'you\s+won', r'lucky\s+winner', r'lottery', r'prize\s+money',
                r'claim\s+your\s+prize', r'congratulations.*won', r'final\s+notice.*prize',
                r'you\s+have\s+been\s+selected', r'winning\s+number'
            ],
            "Romance Scam": [
                r'love\s+you', r'marry\s+me', r'soulmate', r'true\s+love',
                r'beautiful\s+woman', r'single\s+man', r'looking\s+for\s+love',
                r'foreign\s+woman', r'mail\s+order', r' dating\s+site'
            ],
            "Investment Scam": [
                r'guaranteed\s+return', r'risk\s+free', r'double\s+your\s+money',
                r'get\s+rich', r'work\s+from\s+home.*\$', r'make\s+money\s+fast',
                r'cryptocurrency.*guaranteed', r'forex.*guaranteed', r'pyramid',
                r'ponzi', r'multi.level', r'passive\s+income.*\$'
            ],
            "Tech Support Scam": [
                r'virus\s+detected', r'your\s+computer.*infected', r'windows\s+support',
                r'microsoft\s+certified', r'tech\s+support.*number', r'call\s+immediately',
                r'security\s+alert.*call', r'your\s+ip.*compromised', r'remote\s+access'
            ],
            "Phishing / Account Theft": [
                r'verify\s+your\s+account', r'confirm\s+your\s+details',
                r'account.*suspended', r'login.*verify', r'update\s+payment',
                r'banking\s+details.*confirm', r'password.*expired',
                r'security.*verify.*account', r'unusual\s+activity.*account'
            ],
            "Fake Job Scam": [
                r'work\s+from\s+home.*no\s+experience', r'earn\s+\$.*day',
                r'payment\s+processing.*job', r'money\s+transfer.*job',
                r'package\s+forwarding', r'reshipping', r'mystery\s+shopper'
            ],
            "Ransom / Extortion": [
                r'we\s+have\s+your\s+password', r'we\s+recorded\s+you',
                r'pay\s+or\s+we\s+will', r'bitcoin.*or\s+else', r'your\s+files.*encrypted',
                r'ransom', r'sextortion', r'webcam.*recorded'
            ]
        }

        for scam_type, patterns in scam_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    weight = 25 if scam_type in ["Phishing / Account Theft", "Ransom / Extortion"] else 20
                    self._add_finding(f"{scam_type}: {pattern}", weight, "Scam Pattern", f"Text matches {scam_type.lower()} pattern")

        # Check for urgency
        urgency_words = ['urgent', 'immediately', 'asap', 'act now', 'limited time',
                        'expires', 'deadline', 'hurry', 'don\'t miss', 'last chance']
        for word in urgency_words:
            if word in text_lower:
                self._add_finding(f"Urgency pressure: '{word}'", 10, "Social Engineering", "Urgency is a common scam tactic")

        # Check for requests for personal info
        info_requests = ['ssn', 'social security', 'credit card', 'bank account',
                        'routing number', 'passport', 'driver\'s license', 'mother\'s maiden']
        for req in info_requests:
            if req in text_lower:
                self._add_finding(f"Requests sensitive info: '{req}'", 30, "Phishing", "Legitimate entities don't ask for this via email/text")

        self.risk_score = min(sum(f.get("weight", 0) for f in self.findings), 100)
        self.results["risk_score"] = self.risk_score
        self.results["findings"] = self.findings

        if self.risk_score >= 75:
            self.results["risk_level"] = "CRITICAL"
        elif self.risk_score >= 50:
            self.results["risk_level"] = "HIGH"
        elif self.risk_score >= 25:
            self.results["risk_level"] = "MEDIUM"
        else:
            self.results["risk_level"] = "LOW"

        return self.results

    def _check_phishing_indicators(self, url, hostname, parsed):
        """Check for phishing indicators in URL"""
        # IP address in URL (phishing)
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        if ip_pattern.match(hostname):
            self._add_finding("IP address used instead of domain name", 35, "Phishing", "Legitimate sites use domain names")

        # Excessive subdomains
        subdomains = hostname.split('.')
        if len(subdomains) > 4:
            self._add_finding(f"Excessive subdomains ({len(subdomains)})", 20, "Obfuscation", "Phishing sites often use many subdomains")

        # URL has @ symbol (browser ignores everything before @)
        if '@' in url:
            self._add_finding("URL contains @ symbol", 40, "Phishing", "Used to hide real domain from casual viewers")

        # Double slash in path
        if '//' in parsed.path and parsed.path.index('//') > 1:
            self._add_finding("Double slash in URL path", 15, "Obfuscation", "Attempts to confuse URL structure")

        # Unusual port
        if parsed.port and parsed.port not in [80, 443, 8080, 8443]:
            self._add_finding(f"Unusual port ({parsed.port})", 15, "Suspicious", "Phishing sites may use non-standard ports")

        # Very long URL
        if len(url) > 200:
            self._add_finding(f"Very long URL ({len(url)} chars)", 10, "Obfuscation", "Long URLs hide malicious parameters")

    def _check_impersonation(self, hostname):
        """Check for brand impersonation"""
        hostname_lower = hostname.lower()

        # Known brands and their legitimate domains
        brands = {
            'paypal': ['paypal.com', 'paypalobjects.com'],
            'google': ['google.com', 'gmail.com', 'youtube.com', 'googlemail.com'],
            'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com'],
            'apple': ['apple.com', 'icloud.com'],
            'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr'],
            'netflix': ['netflix.com'],
            'facebook': ['facebook.com', 'fb.com', 'messenger.com'],
            'instagram': ['instagram.com'],
            'twitter': ['twitter.com', 'x.com'],
            'linkedin': ['linkedin.com'],
            'whatsapp': ['whatsapp.com'],
            'telegram': ['telegram.org'],
            'binance': ['binance.com'],
            'coinbase': ['coinbase.com'],
            'bank': ['bankofamerica.com', 'wellsfargo.com', 'chase.com', 'citibank.com'],
            'payoneer': ['payoneer.com'],
            'skrill': ['skrill.com'],
            'wise': ['wise.com'],
            'revolut': ['revolut.com'],
        }

        for brand, legit_domains in brands.items():
            if brand in hostname_lower:
                # Check if it's actually the legitimate domain
                is_legitimate = any(legit in hostname_lower for legit in legit_domains)
                if not is_legitimate:
                    # Check for typosquatting
                    for legit_domain in legit_domains:
                        legit_base = legit_domain.split('.')[0]
                        if self._is_typosquatting(hostname_lower, legit_base):
                            self._add_finding(
                                f"Typosquatting: '{hostname}' impersonates '{legit_domain}'",
                                45, "Impersonation",
                                f"Domain attempts to impersonate {brand}"
                            )
                            break
                    else:
                        self._add_finding(
                            f"Suspicious brand mention: '{hostname}' contains '{brand}'",
                            25, "Brand Impersonation",
                            f"May attempt to impersonate {brand}"
                        )

    def _is_typosquatting(self, domain, brand):
        """Detect typosquatting attempts"""
        # Character substitution
        substitutions = {
            '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
            '6': 'g', '7': 't', '8': 'b', '9': 'g', '@': 'a',
        }

        # Check for brand name with extra characters
        if brand in domain:
            # Check if there are extra chars before/after
            idx = domain.index(brand)
            before = domain[:idx]
            after = domain[idx + len(brand):]
            # Legitimate would be brand.com or brand.something
            if before or (after and not after.startswith('.')):
                return True

        # Check for character substitutions
        domain_clean = domain
        for char, replacement in substitutions.items():
            domain_clean = domain_clean.replace(char, replacement)

        if brand in domain_clean and domain != domain_clean:
            return True

        # Check for doubled letters
        for i in range(len(brand)):
            doubled = brand[:i] + brand[i] + brand[i:]
            if doubled in domain:
                return True

        # Check for missing letters
        for i in range(len(brand)):
            missing = brand[:i] + brand[i+1:]
            if missing in domain:
                return True

        return False

    def _check_suspicious_tld(self, hostname):
        """Check for suspicious TLDs"""
        suspicious_tlds = {
            '.tk': 'Free domain, commonly used for phishing',
            '.ml': 'Free domain, commonly used for phishing',
            '.ga': 'Free domain, commonly used for phishing',
            '.cf': 'Free domain, commonly used for phishing',
            '.gq': 'Free domain, commonly used for phishing',
            '.xyz': 'Cheap domain, used for scams',
            '.top': 'Cheap domain, used for scams',
            '.loan': 'Common in financial scams',
            '.work': 'Common in job scams',
            '.date': 'Common in romance scams',
            '.men': 'Common in adult site scams',
            '.click': 'Common in phishing',
            '.download': 'Common in malware distribution',
            '.review': 'Common in fake review scams',
            '.trade': 'Common in investment scams',
            '.webcam': 'Common in sextortion',
            '.bid': 'Common in auction scams',
            '.win': 'Common in lottery scams',
            '.party': 'Common in social scams',
            '.science': 'Common in fake tech support',
        }

        for tld, description in suspicious_tlds.items():
            if hostname.endswith(tld):
                self._add_finding(f"Suspicious TLD: {tld}", 25, "Suspicious TLD", description)

    def _check_url_obfuscation(self, url, hostname):
        """Check for URL obfuscation techniques"""
        # Punycode/IDN homograph attack
        if 'xn--' in hostname:
            self._add_finding("Punycode/IDN homograph attack detected", 50, "Homograph Attack",
                            "Uses lookalike characters from different alphabets")

        # Hex encoding in URL
        if '%' in url:
            hex_chars = re.findall(r'%[0-9a-fA-F]{2}', url)
            if len(hex_chars) > 5:
                self._add_finding(f"Excessive URL encoding ({len(hex_chars)} encoded chars)", 15, "Obfuscation",
                                "Used to hide malicious URLs from filters")

        # Base64 in URL
        if re.search(r'[A-Za-z0-9+/]{40,}={0,2}', url):
            self._add_finding("Possible Base64 encoded content in URL", 20, "Obfuscation",
                            "Base64 used to hide malicious payloads")

    def _check_fake_https(self, url, hostname):
        """Check for fake HTTPS indicators"""
        if url.startswith('https://'):
            # Check certificate
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        if cert:
                            # Check if certificate is recently issued
                            not_before = cert.get('notBefore', '')
                            if not_before:
                                try:
                                    from datetime import datetime
                                    cert_date = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
                                    days_old = (datetime.now() - cert_date).days
                                    if days_old < 7:
                                        self._add_finding(f"Certificate is very new ({days_old} days old)", 15,
                                                        "Suspicious", "Phishing sites often use newly issued certificates")
                                except Exception:
                                    pass
            except Exception:
                self._add_finding("Failed to verify SSL certificate", 20, "No SSL", "Could not validate certificate")

    def _check_scam_keywords(self, url, hostname):
        """Check for scam-related keywords"""
        scam_keywords = {
            'login': 'Fake login page',
            'signin': 'Fake sign-in page',
            'verify': 'Account verification scam',
            'secure': 'False sense of security',
            'account': 'Account-related scam',
            'update': 'Fake update page',
            'confirm': 'Confirmation scam',
            'banking': 'Banking phishing',
            'password': 'Password harvesting',
            'wallet': 'Cryptocurrency wallet scam',
            'bitcoin': 'Cryptocurrency scam',
            'free': 'Free offer scam',
            'bonus': 'Bonus scam',
            'prize': 'Prize scam',
            'winner': 'Lottery scam',
            'refund': 'Refund scam',
            'invoice': 'Fake invoice',
            'payment': 'Payment scam',
            'shipping': 'Shipping scam',
            'tracking': 'Tracking scam',
            'support': 'Fake support',
            'helpdesk': 'Fake helpdesk',
            'recovery': 'Account recovery scam',
            'unlock': 'Account unlock scam',
            'suspended': 'Account suspended scam',
            'limited': 'Limited access scam',
            'unusual': 'Unusual activity scam',
        }

        url_lower = url.lower()
        for keyword, description in scam_keywords.items():
            if keyword in url_lower:
                self._add_finding(f"Scam keyword in URL: '{keyword}'", 15, "Scam Keyword", description)

    def _check_redirect_loops(self, url):
        """Check for redirect chains"""
        try:
            import requests
            response = requests.get(url, timeout=10, allow_redirects=True)
            if len(response.history) > 3:
                self._add_finding(f"Multiple redirects ({len(response.history)})", 20, "Redirect Chain",
                                "Phishing sites often use redirect chains to hide final destination")
            if len(response.history) > 0:
                for i, resp in enumerate(response.history):
                    if 'login' in resp.url.lower() or 'verify' in resp.url.lower():
                        self._add_finding(f"Redirect passes through login page", 25, "Phishing Redirect",
                                        "Redirect chain includes credential harvesting page")
                        break
        except Exception:
            pass

    def _check_fake_shopping(self, url, hostname):
        """Check for fake shopping site indicators"""
        shopping_indicators = ['shop', 'store', 'buy', 'sale', 'discount', 'cheap', 'deal']
        url_lower = url.lower()

        has_shopping = any(ind in url_lower for ind in shopping_indicators)
        if has_shopping:
            # Check for unrealistic discounts
            if re.search(r'90%|95%|99%|free|only\s*\$\d{1,2}', url_lower):
                self._add_finding("Unrealistic discount indicators", 30, "Fake Shopping",
                                "Scam shopping sites use extreme discounts to lure victims")

            # Check domain age for shopping sites
            try:
                import whois
                w = whois.whois(hostname)
                if w.creation_date:
                    if isinstance(w.creation_date, list):
                        creation = w.creation_date[0]
                    else:
                        creation = w.creation_date
                    age_days = (datetime.now() - creation).days
                    if age_days < 30:
                        self._add_finding(f"Shopping site domain is very new ({age_days} days)", 35,
                                        "Fake Shopping", "Fake shops use recently registered domains")
                    elif age_days < 90:
                        self._add_finding(f"Shopping site domain is relatively new ({age_days} days)", 20,
                                        "Suspicious", "New shopping sites should be verified")
            except Exception:
                self._add_finding("Could not verify domain age for shopping site", 10, "Unverifiable",
                                "Unable to determine if this is an established store")

    def _check_tech_support_scam(self, url, hostname):
        """Check for tech support scam indicators"""
        tech_keywords = ['support', 'help', 'fix', 'repair', 'virus', 'malware',
                        'error', 'problem', 'crash', 'blue screen', 'microsoft',
                        'windows', 'antivirus', 'security', 'alert', 'warning']

        url_lower = url.lower()
        if any(kw in url_lower for kw in tech_keywords):
            # Check for call-to-action
            if 'call' in url_lower or 'number' in url_lower or 'contact' in url_lower:
                self._add_finding("Tech support scam: prompts to call a number", 40, "Tech Support Scam",
                                "Legitimate tech support doesn't use popup warnings with phone numbers")

            # Check for fake alert language
            if re.search(r'(infected|compromised|blocked|locked|alert|warning|critical)', url_lower):
                self._add_finding("Tech support scam: fake security alert", 35, "Tech Support Scam",
                                "Uses fear tactics to get you to call")

    def _check_crypto_scam(self, url, hostname):
        """Check for cryptocurrency scam indicators"""
        crypto_keywords = ['bitcoin', 'crypto', 'eth', 'wallet', 'mining', 'investment',
                          'trading', 'forex', 'signal', 'profit', 'return']

        url_lower = url.lower()
        if any(kw in url_lower for kw in crypto_keywords):
            # Check for guaranteed returns
            if re.search(r'guaranteed|risk.?free|double|100%.*profit|passive.*income', url_lower):
                self._add_finding("Crypto scam: guaranteed returns promised", 45, "Investment Scam",
                                "No legitimate investment guarantees returns")

            # Check for celebrity endorsement claims
            if re.search(r'(elon|musk|bezos|buffett|trump|cook).*(bitcoin|crypto|giveaway)', url_lower):
                self._add_finding("Crypto scam: fake celebrity endorsement", 50, "Celebrity Scam",
                                "Scammers impersonate celebrities to promote fake crypto giveaways")

    def _check_phishing_form(self, url):
        """Check for phishing form indicators"""
        try:
            import requests
            response = requests.get(url, timeout=10)
            html = response.text.lower()

            # Check for password fields
            password_fields = re.findall(r'<input[^>]*type=["\']password["\']', html)
            if password_fields:
                # Check if it's a known login page
                known_login_pages = ['login', 'signin', 'auth', 'account']
                if not any(p in url.lower() for p in known_login_pages):
                    self._add_finding(f"Password field on non-login page ({len(password_fields)} fields)", 30,
                                "Phishing Form", "Password fields outside normal login pages are suspicious")

            # Check for credit card fields
            if re.search(r'credit.?card|card.?number|cvv|cvc|expiry', html):
                self._add_finding("Credit card information fields detected", 35, "Phishing Form",
                                "Verify this is a legitimate payment page")

            # Check for form submission to external domain
            form_actions = re.findall(r'<form[^>]*action=["\'](https?://[^"\']+)["\']', html)
            for action in form_actions:
                action_domain = urlparse(action).hostname
                original_domain = urlparse(url).hostname
                if action_domain and original_domain and action_domain != original_domain:
                    self._add_finding(f"Form submits to different domain: {action_domain}", 45,
                                "Phishing Form", "Credentials are being sent to a different domain")

        except Exception:
            pass

    def _check_email_urgency(self, content, subject):
        """Check for urgency tactics in email"""
        urgency_patterns = [
            r'urgent', r'immediately', r'asap', r'act\s+now', r'limited\s+time',
            r'expires?\s+(today|soon)', r'deadline', r'hurry', r'don\'t\s+miss',
            r'last\s+(chance|warning|notice)', r'final\s+notice', r'response\s+required',
            r'within\s+\d+\s+(hours?|days?)', r'immediate\s+action', r'time\s+sensitive'
        ]

        text = (content + " " + (subject or "")).lower()
        urgency_count = 0
        for pattern in urgency_patterns:
            if re.search(pattern, text):
                urgency_count += 1

        if urgency_count >= 3:
            self._add_finding(f"High urgency pressure ({urgency_count} urgency indicators)", 30,
                        "Urgency Tactic", "Scammers create false urgency to bypass critical thinking")
        elif urgency_count >= 1:
            self._add_finding(f"Urgency indicator detected", 15, "Urgency Tactic",
                        "Urgency is a common social engineering technique")

    def _check_email_requests(self, content):
        """Check for suspicious requests in email"""
        request_patterns = [
            (r'click\s+(the\s+)?link', 'Click link request'),
            (r'open\s+(the\s+)?attachment', 'Open attachment request'),
            (r'download\s+(the\s+)?file', 'Download file request'),
            (r'send\s+(us\s+)?(your\s+)?(personal|banking|credit)', 'Request for personal info'),
            (r'confirm\s+(your\s+)?(account|details|information)', 'Confirm account details'),
            (r'update\s+(your\s+)?(account|payment|billing)', 'Update account request'),
            (r'verify\s+(your\s+)?(identity|account|login)', 'Verify identity request'),
            (r'provide\s+(your\s+)?(password|username|pin)', 'Request for credentials'),
            (r'transfer\s+(the\s+)?(money|funds|payment)', 'Money transfer request'),
            (r'wire\s+(the\s+)?(money|funds)', 'Wire transfer request'),
            (r'gift\s+(cards?|certificates?)', 'Gift card request'),
            (r'western\s+union', 'Western Union request'),
            (r'money\s+gram', 'MoneyGram request'),
        ]

        content_lower = content.lower()
        for pattern, description in request_patterns:
            if re.search(pattern, content_lower):
                self._add_finding(f"Suspicious request: {description}", 25, "Suspicious Request",
                                "Legitimate entities don't make these requests via email")

    def _check_fake_links_in_text(self, content):
        """Check for misleading links in text"""
        # Find all links
        links = re.findall(r'https?://[^\s<>"\']+', content)
        for link in links:
            # Check for display text mismatch
            link_lower = link.lower()
            # Check if link text says one thing but links to another
            text_before = content[:content.find(link)][-50:]
            if any(brand in text_before.lower() for brand in
                   ['paypal', 'google', 'microsoft', 'apple', 'amazon', 'netflix']):
                if not any(legit in link_lower for legit in
                           ['.paypal.', '.google.', '.microsoft.', '.apple.',
                            '.amazon.', '.netflix.']):
                    self._add_finding(f"Deceptive link: text says one brand, links to {link}", 40,
                                "Deceptive Link", "Classic phishing technique")

    def _check_spoofed_sender(self, sender):
        """Check for spoofed sender address"""
        if not sender:
            return

        sender_lower = sender.lower()
        # Check for display name mismatch
        display_match = re.match(r'"?([^"<]+)"?\s*<([^>]+)>', sender)
        if display_match:
            display_name = display_match.group(1).lower()
            email_addr = display_match.group(2).lower()

            # Check if display name contains a brand but email doesn't match
            brands = ['paypal', 'google', 'microsoft', 'apple', 'amazon', 'netflix',
                     'facebook', 'instagram', 'twitter', 'linkedin', 'bank', 'chase',
                     'wells fargo', 'bank of america', 'citibank', 'amex']

            for brand in brands:
                if brand in display_name:
                    email_domain = email_addr.split('@')[1] if '@' in email_addr else ''
                    if brand.replace(' ', '') not in email_domain:
                        self._add_finding(f"Spoofed sender: display name '{display_name}' but email from '{email_addr}'",
                                        45, "Spoofed Sender", "Classic CEO fraud / brand impersonation technique")

    def _check_grammar_mistakes(self, content):
        """Check for poor grammar (common in scams)"""
        # Simple heuristic checks
        content_lower = content.lower()

        # Check for excessive capitalization
        caps_words = re.findall(r'\b[A-Z]{4,}\b', content)
        if len(caps_words) > 3:
            self._add_finding(f"Excessive capitalization ({len(caps_words)} words in ALL CAPS)", 10,
                        "Poor Grammar", "Scams often use excessive capitalization")

        # Check for missing punctuation
        sentences = re.split(r'[.!?]+', content)
        if len(sentences) > 3:
            proper_endings = sum(1 for s in sentences if s.strip() and s.strip()[-1] in '.!?')
            if proper_endings < len(sentences) * 0.5:
                self._add_finding("Poor sentence structure (missing punctuation)", 10,
                                "Poor Grammar", "Scams often have grammatical errors")

    def _check_threat_intimidation(self, content):
        """Check for threatening language"""
        threat_patterns = [
            r'legal\s+action', r'lawsuit', r'sue\s+you', r'court',
            r'police\s+report', r'fbi', r'cia', r'government\s+agency',
            r'your\s+credit\s+(score|rating).*(damage|ruin)',
            r'debt\s+collection', r'warrant', r'arrest',
            r'deport', r'immigration', r'ice',
            r'social\s+security.*suspend', r'benefits.*suspend',
            r'tax.*(evasion|fraud|audit)', r'irs',
        ]

        content_lower = content.lower()
        for pattern in threat_patterns:
            if re.search(pattern, content_lower):
                self._add_finding(f"Intimidation tactic: '{pattern}'", 30, "Intimidation",
                                "Scammers use threats to pressure victims into compliance")

    def _check_attachment_warning(self, content):
        """Check for dangerous attachment indicators"""
        attachment_patterns = [
            r'invoice\.(exe|zip|rar|7z|js|vbs|ps1|bat|scr|msi)',
            r'payment\.(exe|zip|rar|7z|js|vbs|ps1|bat|scr|msi)',
            r'document\.(exe|zip|rar|7z|js|vbs|ps1|bat|scr|msi)',
            r'fax\.(exe|zip|rar|7z|js|vbs|ps1|bat|scr|msi)',
            r' scanned\.(exe|zip|rar|7z|js|vbs|ps1|bat|scr|msi)',
            r'copy\.(exe|zip|rar|7z|js|vbs|ps1|bat|scr|msi)',
        ]

        content_lower = content.lower()
        for pattern in attachment_patterns:
            if re.search(pattern, content_lower):
                self._add_finding(f"Suspicious attachment pattern: {pattern}", 40, "Malicious Attachment",
                                "Executable files disguised as documents are common malware delivery")

    def _check_prize_scam(self, content, subject):
        """Check for lottery/prize scam patterns"""
        text = (content + " " + (subject or "")).lower()
        prize_indicators = [
            (r'you\s+(have\s+)?won', 'Claims you won'),
            (r'lottery', 'Lottery mention'),
            (r'prize.*\$\d+', 'Large prize amount'),
            (r'claim.*prize', 'Prize claim request'),
            (r'processing\s+fee', 'Processing fee request'),
            (r'release\s+(funds|money|prize)', 'Fund release request'),
            (r'tax.*prize', 'Tax on prize'),
            (r'customs.*(fee|charge|duty)', 'Customs fee request'),
        ]

        for pattern, description in prize_indicators:
            if re.search(pattern, text):
                self._add_finding(f"Prize scam: {description}", 30, "Prize Scam",
                                "You cannot win a contest you didn't enter")

    def _check_invoice_scam(self, content, subject):
        """Check for fake invoice scams"""
        text = (content + " " + (subject or "")).lower()
        invoice_indicators = [
            (r'overdue\s+(invoice|payment)', 'Overdue payment claim'),
            (r'past\s+due', 'Past due claim'),
            (r'outstanding\s+balance', 'Outstanding balance claim'),
            (r'final\s+notice.*payment', 'Final payment notice'),
            (r'subscription.*(renew|expire)', 'Subscription renewal scam'),
            (r'cancellation.*(order|subscription)', 'Cancellation scam'),
            (r'payment.*(failed|declined|rejected)', 'Payment failed scam'),
            (r'update.*(billing|payment).*info', 'Billing update scam'),
        ]

        for pattern, description in invoice_indicators:
            if re.search(pattern, text):
                self._add_finding(f"Invoice scam: {description}", 25, "Fake Invoice",
                                "Verify invoices independently before payment")

    def _check_ceo_fraud(self, content, sender, subject):
        """Check for CEO fraud / business email compromise"""
        text = (content + " " + (subject or "")).lower()
        ceo_indicators = [
            r'wire\s+transfer', r'urgent\s+payment', r'confidential',
            r'authorize\s+payment', r'ach\s+transfer', r'bank\s+transfer',
            r'vendor\s+payment', r'invoice\s+payment', r'pay\s+immediately',
            r'wiring\s+instructions', r'banking\s+details.*change',
            r'payment.*update.*account', r'direct.*deposit.*change',
        ]

        for pattern in ceo_indicators:
            if re.search(pattern, text):
                self._add_finding(f"CEO fraud indicator: '{pattern}'", 35, "CEO Fraud",
                                "Business Email Compromise (BEC) - verify payment requests via phone")

    def _add_finding(self, description, weight, category, recommendation=""):
        """Add a finding"""
        self.findings.append({
            "description": description,
            "weight": weight,
            "category": category,
            "recommendation": recommendation
        })

    def _generate_warnings(self):
        """Generate human-readable warnings"""
        warnings = []
        high_risk = [f for f in self.findings if f["weight"] >= 30]
        medium_risk = [f for f in self.findings if 15 <= f["weight"] < 30]

        if self.results["risk_level"] == "CRITICAL":
            warnings.append("CRITICAL: This appears to be a fraudulent/scam attempt!")
        elif self.results["risk_level"] == "HIGH":
            warnings.append("HIGH: Multiple fraud indicators detected. Exercise extreme caution.")

        if high_risk:
            categories = set(f["category"] for f in high_risk)
            warnings.append(f"Detected: {', '.join(categories)}")

        if medium_risk:
            warnings.append("Additional suspicious indicators present")

        self.results["warnings"] = warnings