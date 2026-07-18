"""
CyberTool Email Checker Module
"""
import re
import socket
from datetime import datetime
from core.logger import logger


class EmailChecker:
    """Check email addresses for security issues"""

    def __init__(self):
        self.results = {}

    def check(self, email):
        """Perform comprehensive email check"""
        self.results = {
            "email": email,
            "checks": {}
        }

        # Syntax check
        self.results["checks"]["valid_syntax"] = self._check_syntax(email)

        # Extract domain
        domain = email.split('@')[1] if '@' in email else ""

        # Disposable email check
        self.results["checks"]["disposable"] = self._check_disposable(domain)

        # MX records
        self.results["checks"]["mx_records"] = self._check_mx(domain)

        # SPF record
        self.results["checks"]["spf"] = self._check_spf(domain)

        # DKIM
        self.results["checks"]["dkim"] = self._check_dkim(domain)

        # DMARC
        self.results["checks"]["dmarc"] = self._check_dmarc(domain)

        # Domain age
        self.results["checks"]["domain_age"] = self._check_domain_age(domain)

        logger.info("EmailChecker", f"Checked email: {email}")
        return self.results

    def _check_syntax(self, email):
        """Validate email syntax"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    def _check_disposable(self, domain):
        """Check if domain is a disposable email provider"""
        disposable_domains = [
            "mailinator.com", "guerrillamail.com", "10minutemail.com",
            "tempmail.com", "throwaway.email", "yopmail.com",
            "sharklasers.com", "trashmail.com", "mailnator.com",
            "temp-mail.org", "fakeinbox.com", "dispostable.com",
            "getnada.com", "maildrop.cc", "tempemail.net",
        ]
        return domain.lower() in disposable_domains

    def _check_mx(self, domain):
        """Check MX records"""
        try:
            import dns.resolver
            mx_records = dns.resolver.resolve(domain, 'MX')
            return [f"{r.preference} {str(r.exchange)}" for r in mx_records]
        except Exception:
            return []

    def _check_spf(self, domain):
        """Check SPF record"""
        try:
            import dns.resolver
            txt_records = dns.resolver.resolve(domain, 'TXT')
            for r in txt_records:
                text = str(r)
                if 'v=spf1' in text:
                    return text
            return "No SPF record found"
        except Exception:
            return "Unable to check"

    def _check_dkim(self, domain):
        """Check DKIM record (default selector)"""
        try:
            import dns.resolver
            dkim_domain = f"default._domainkey.{domain}"
            dkim_records = dns.resolver.resolve(dkim_domain, 'TXT')
            return [str(r) for r in dkim_records]
        except Exception:
            return "No DKIM record found"

    def _check_dmarc(self, domain):
        """Check DMARC record"""
        try:
            import dns.resolver
            dmarc_domain = f"_dmarc.{domain}"
            dmarc_records = dns.resolver.resolve(dmarc_domain, 'TXT')
            return [str(r) for r in dmarc_records]
        except Exception:
            return "No DMARC record found"

    def _check_domain_age(self, domain):
        """Check domain age"""
        try:
            import whois
            w = whois.whois(domain)
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation = w.creation_date[0]
                else:
                    creation = w.creation_date
                age_days = (datetime.now() - creation).days
                return {
                    "created": str(creation),
                    "age_days": age_days,
                    "is_new": age_days < 30,
                }
            return {"error": "Could not determine domain age"}
        except Exception as e:
            return {"error": str(e)}