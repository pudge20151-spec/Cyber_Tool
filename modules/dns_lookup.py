"""
CyberTool DNS Lookup Module
"""
import socket
from core.logger import logger


class DNSLookup:
    """Perform DNS lookups"""

    def __init__(self):
        self.results = {}

    def lookup(self, domain):
        """Perform comprehensive DNS lookup"""
        self.results = {
            "domain": domain,
            "records": {}
        }

        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 10
            resolver.lifetime = 10

            # A records
            try:
                a_records = [str(r) for r in resolver.resolve(domain, 'A')]
                self.results["records"]["A"] = a_records
            except Exception:
                self.results["records"]["A"] = []

            # AAAA records
            try:
                aaaa_records = [str(r) for r in resolver.resolve(domain, 'AAAA')]
                self.results["records"]["AAAA"] = aaaa_records
            except Exception:
                self.results["records"]["AAAA"] = []

            # MX records
            try:
                mx_records = [f"{r.preference} {str(r.exchange)}" for r in resolver.resolve(domain, 'MX')]
                self.results["records"]["MX"] = mx_records
            except Exception:
                self.results["records"]["MX"] = []

            # TXT records
            try:
                txt_records = [str(r) for r in resolver.resolve(domain, 'TXT')]
                self.results["records"]["TXT"] = txt_records
            except Exception:
                self.results["records"]["TXT"] = []

            # NS records
            try:
                ns_records = [str(r) for r in resolver.resolve(domain, 'NS')]
                self.results["records"]["NS"] = ns_records
            except Exception:
                self.results["records"]["NS"] = []

            # SOA record
            try:
                soa = resolver.resolve(domain, 'SOA')
                self.results["records"]["SOA"] = str(soa[0])
            except Exception:
                self.results["records"]["SOA"] = "N/A"

            # PTR records (reverse DNS)
            try:
                for ip in self.results["records"]["A"]:
                    try:
                        ptr = resolver.resolve_address(ip)
                        self.results["records"]["PTR"] = str(ptr[0])
                        break
                    except Exception:
                        continue
            except Exception:
                pass

            # CAA records
            try:
                caa_records = [str(r) for r in resolver.resolve(domain, 'CAA')]
                self.results["records"]["CAA"] = caa_records
            except Exception:
                self.results["records"]["CAA"] = []

            logger.info("DNSLookup", f"Looked up DNS for: {domain}")

        except ImportError:
            self.results["error"] = "dnspython library not installed"
            # Fallback to socket
            try:
                ip = socket.gethostbyname(domain)
                self.results["records"]["A"] = [ip]
            except Exception:
                self.results["records"]["A"] = []
        except Exception as e:
            self.results["error"] = str(e)

        return self.results