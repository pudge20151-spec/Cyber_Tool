"""
CyberTool WHOIS Module
"""
from core.logger import logger


class WhoisLookup:
    """WHOIS domain lookup"""

    def __init__(self):
        self.results = {}

    def lookup(self, domain):
        """Perform WHOIS lookup"""
        self.results = {"domain": domain}

        try:
            import whois
            w = whois.whois(domain)
            self.results = {
                "domain": domain,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date) if w.creation_date else "N/A",
                "expiration_date": str(w.expiration_date) if w.expiration_date else "N/A",
                "updated_date": str(w.updated_date) if w.updated_date else "N/A",
                "name_servers": w.name_servers if w.name_servers else [],
                "status": w.status if w.status else [],
                "emails": w.emails if w.emails else [],
                "org": w.org if w.org else "N/A",
                "country": w.country if w.country else "N/A",
                "dnssec": w.dnssec if hasattr(w, 'dnssec') else "N/A",
            }
            logger.info("WhoisLookup", f"WHOIS lookup for: {domain}")
        except ImportError:
            self.results["error"] = "python-whois library not installed"
        except Exception as e:
            self.results["error"] = str(e)

        return self.results