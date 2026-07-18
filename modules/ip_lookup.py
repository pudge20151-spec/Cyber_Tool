"""
CyberTool IP Intelligence Module - Enhanced
"""
import socket
import struct
import ipaddress
import requests
import time
from core.logger import logger
from core.cache import cache


class IPLookup:
    """IP address intelligence lookup with enhanced data sources"""

    # DNSBL (DNS-based Blackhole Lists)
    DNSBL_LIST = [
        "zen.spamhaus.org",
        "b.barracudacentral.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net",
        "cbl.abuseat.org",
        "dnsbl-1.uceprotect.net",
        "psbl.surriel.com",
        "ix.dnsbl.manitu.net",
    ]

    # Common proxy/VPN detection ports
    PROXY_PORTS = [80, 8080, 3128, 1080, 8118, 9050, 9051, 9150]

    # Suspicious hosting/datacenter ASN keywords
    HOSTING_ASN_KEYWORDS = [
        "amazon", "aws", "azure", "google cloud", "gcp", "digitalocean",
        "linode", "vultr", "ovh", "hetzner", "scaleway", "upcloud",
        "contabo", "ionos", "leaseweb", "psychz", "cogent", "gtt",
        "nforce", "netcup", "netcologne", "mythic", "datapacket",
        "choopa", "voxility", "dacentec", "buyvm", "ramnode",
    ]

    # Popular domains for typosquatting detection
    POPULAR_DOMAINS = [
        "google.com", "youtube.com", "facebook.com", "twitter.com", "x.com",
        "instagram.com", "linkedin.com", "whatsapp.com", "tiktok.com",
        "reddit.com", "telegram.org", "discord.com", "github.com",
        "stackoverflow.com", "amazon.com", "ebay.com", "aliexpress.com",
        "paypal.com", "apple.com", "microsoft.com", "cloudflare.com",
        "dropbox.com", "drive.google.com", "docs.google.com",
    ]

    # Special IP ranges for classification
    SPECIAL_RANGES = {
        "loopback": [ipaddress.IPv4Network("127.0.0.0/8")],
        "link_local": [ipaddress.IPv4Network("169.254.0.0/16"), ipaddress.IPv6Network("fe80::/10")],
        "multicast": [ipaddress.IPv4Network("224.0.0.0/4"), ipaddress.IPv6Network("ff00::/8")],
        "broadcast": [ipaddress.IPv4Network("255.255.255.255/32")],
        "cgnat": [ipaddress.IPv4Network("100.64.0.0/10")],  # RFC 6598
        "documentation": [
            ipaddress.IPv4Network("192.0.2.0/24"),    # RFC 5737
            ipaddress.IPv4Network("198.51.100.0/24"),  # RFC 5737
            ipaddress.IPv4Network("203.0.113.0/24"),   # RFC 5737
        ],
        "benchmark": [ipaddress.IPv4Network("168.192.0.0/16")],  # RFC 5737 (also used)
        "future_use": [ipaddress.IPv4Network("240.0.0.0/4")],  # RFC 1112
    }

    def __init__(self):
        self.results = {}

    def lookup(self, ip):
        """Perform comprehensive IP intelligence lookup"""
        start_time = time.time()
        self.results = {
            "ip": ip,
            "basic": {},
            "geo": {},
            "network": {},
            "reputation": {},
            "threat": {},
            "dnsbl": {},
            "proxy_vpn": {},
            "rdap": {},
            "timing": {},
        }

        # 1. Basic info - classify IP first
        self.results["basic"]["classifications"] = self.get_ip_classification(ip)
        self.results["basic"]["is_private"] = self._is_private_ip(ip)
        self.results["basic"]["is_reserved"] = self._is_reserved_ip(ip)
        self.results["basic"]["ip_version"] = self._get_ip_version(ip)
        self.results["basic"]["ip_type"] = self._classify_ip_type(ip)
        self.results["basic"]["range_description"] = self._get_range_description(ip)
        self.results["basic"]["rir"] = self._get_rir(ip)

        # 2. Check if special address - skip geolocation for special IPs
        is_special = self._is_special_address(ip)
        
        if not is_special:
            # 3. Geolocation from ip-api.com
            geo_info = self._get_geo_info(ip)
            if geo_info:
                self.results["geo"] = geo_info

            # 4. Geolocation from ipinfo.io (fallback/enrichment)
            ipinfo_info = self._get_ipinfo_info(ip)
            if ipinfo_info:
                # Merge missing fields from ipinfo
                for k, v in ipinfo_info.items():
                    if k not in self.results["geo"] or not self.results["geo"].get(k):
                        self.results["geo"][k] = v

            # 5. DNSBL checks
            self.results["dnsbl"] = self._check_dnsbl(ip)

            # 6. Proxy/VPN/Tor detection
            self.results["proxy_vpn"] = self._detect_proxy_vpn(ip)

            # 7. RDAP/WHOIS lookup
            rdap_info = self._get_rdap_info(ip)
            if rdap_info:
                self.results["rdap"] = rdap_info

            # 8. Reputation scoring (enhanced)
            self.results["reputation"] = self._calculate_reputation(ip)
        else:
            # Special address - set N/A geolocation
            self.results["geo"] = {
                "country": "N/A",
                "country_code": "N/A",
                "region": "N/A",
                "region_code": "N/A",
                "city": "N/A",
                "zip": "N/A",
                "lat": "N/A",
                "lon": "N/A",
                "timezone": "N/A",
                "isp": "N/A",
                "org": "N/A",
                "as": "N/A",
                "asn": "N/A",
                "as_name": "N/A",
                "reason": "Special Address Range",
            }
            self.results["dnsbl"] = {"listed": False, "lists": [], "count": 0}
            self.results["proxy_vpn"] = {
                "is_tor": False,
                "is_proxy": False,
                "is_vpn": False,
                "is_datacenter": False,
                "details": ["Special address - skipped"],
            }
            self.results["rdap"] = {"handle": "N/A"}
            self.results["reputation"] = {
                "score": 100,
                "severity": "safe",
                "reasons": ["Special address range - not routable"],
            }

        # 9. Local IOC database check
        from core.database import db
        ioc_match = db.check_ip(ip)
        if ioc_match:
            self.results["threat"]["local_ioc"] = {
                "threat_type": ioc_match[3],
                "description": ioc_match[4],
                "source": ioc_match[5],
            }

        # 10. AbuseIPDB check (if configured)
        abuse_info = self._check_abuseipdb(ip)
        if abuse_info:
            self.results["threat"]["abuseipdb"] = abuse_info

        # Calculate timing
        elapsed_ms = int((time.time() - start_time) * 1000)
        self.results["timing"]["lookup_time_ms"] = elapsed_ms

        logger.info("IPLookup", f"Enhanced lookup for IP: {ip}")
        return self.results

    def _is_special_address(self, ip):
        """Check if IP is in a special/reserved range that should skip external checks"""
        try:
            addr = ipaddress.ip_address(ip)
            
            # Check loopback (127.0.0.0/8)
            if addr.is_loopback:
                return True
            
            # Check private (RFC 1918)
            if addr.is_private:
                return True
            
            # Check CGNAT (RFC 6598) - 100.64.0.0/10
            if isinstance(addr, ipaddress.IPv4Address):
                cgnat_range = ipaddress.IPv4Network('100.64.0.0/10')
                if addr in cgnat_range:
                    return True
            
            # Check link-local (169.254.0.0/16)
            if addr.is_link_local:
                return True
            
            return False
        except Exception:
            return False

    def _reverse_dns(self, ip):
        """Reverse DNS lookup"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except Exception:
            return "PTR Missing"

    def _reverse_dns_validated(self, ip):
        """Check reverse DNS and validate if present"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            # Try forward-confirmed reverse DNS
            try:
                resolved_ip = socket.gethostbyname(hostname)
                if resolved_ip == ip:
                    return {"hostname": hostname, "validated": True}
            except Exception:
                pass
            return {"hostname": hostname, "validated": False}
        except Exception:
            return {"hostname": "PTR Missing", "validated": False}

    def _is_private_ip(self, ip):
        """Check if IP is private (RFC 1918)"""
        try:
            return ipaddress.ip_address(ip).is_private
        except Exception:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            first = int(parts[0])
            second = int(parts[1])
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:
                return True
            if first == 169 and second == 254:
                return True
            return False

    def _is_reserved_ip(self, ip):
        """Check if IP is reserved/special purpose"""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_multicast or addr.is_loopback or addr.is_link_local or addr.is_unspecified
        except Exception:
            return False

    def _get_ip_version(self, ip):
        """Get IP version (IPv4/IPv6)"""
        try:
            return ipaddress.ip_address(ip).version
        except Exception:
            return "Unknown"

    def _classify_ip_type(self, ip):
        """Classify IP type - return primary classification"""
        try:
            addr = ipaddress.ip_address(ip)
            
            # Check in order of specificity
            if addr.is_loopback:
                return "Loopback"
            if addr.is_unspecified:
                return "Unspecified"
            if addr.is_multicast:
                return "Multicast"
            if addr.is_link_local:
                return "Link Local"
            if isinstance(addr, ipaddress.IPv4Address):
                # CGNAT (100.64.0.0/10)
                cgnat_range = ipaddress.IPv4Network('100.64.0.0/10')
                if addr in cgnat_range:
                    return "Carrier Grade NAT"
                # Documentation ranges (RFC 5737)
                doc_ranges = [
                    ipaddress.IPv4Network('192.0.2.0/24'),
                    ipaddress.IPv4Network('198.51.100.0/24'),
                    ipaddress.IPv4Network('203.0.113.0/24'),
                ]
                for net in doc_ranges:
                    if addr in net:
                        return "Documentation"
                # Benchmark testing (RFC 5737)
                if isinstance(addr, ipaddress.IPv4Address):
                    if addr in ipaddress.IPv4Network('168.192.0.0/16'):
                        return "Benchmarking"
                # Future use (RFC 1112)
                if addr in ipaddress.IPv4Network('240.0.0.0/4'):
                    return "Future Use"
            if addr.is_private:
                return "Private"
            if addr.is_reserved:
                return "Reserved"
            return "Public"
        except Exception:
            return "Unknown"

    def _get_range_description(self, ip):
        """Get human-readable description of the IP range"""
        try:
            addr = ipaddress.ip_address(ip)
            
            # Check specific ranges
            if addr.is_loopback:
                return "RFC127 Loopback"
            if addr.is_unspecified:
                return "RFC11 Unspecified (0.0.0.0)"
            if addr.is_multicast:
                return "RFC11 Multicast"
            if addr.is_link_local:
                return "RFC3927 Link Local"
            
            if isinstance(addr, ipaddress.IPv4Address):
                # CGNAT
                cgnat_range = ipaddress.IPv4Network('100.64.0.0/10')
                if addr in cgnat_range:
                    return "RFC6598 Carrier Grade NAT"
                # Private ranges
                if addr in ipaddress.IPv4Network('10.0.0.0/8'):
                    return "RFC1918 Private Network (10.x.x.x)"
                if addr in ipaddress.IPv4Network('172.16.0.0/12'):
                    return "RFC1918 Private Network (172.16-31.x.x)"
                if addr in ipaddress.IPv4Network('192.168.0.0/16'):
                    return "RFC1918 Private Network (192.168.x.x)"
                # Documentation
                doc_ranges = [
                    ("192.0.2.0/24", "RFC5737 Documentation Network"),
                    ("198.51.100.0/24", "RFC5737 Documentation Network"),
                    ("203.0.113.0/24", "RFC5737 Documentation Network"),
                ]
                for net, desc in doc_ranges:
                    if addr in ipaddress.IPv4Network(net):
                        return desc
            
            return "Global Public Network"
        except Exception:
            return "Unknown"

    def _get_rir(self, ip):
        """Get RIR (Regional Internet Registry) for IP"""
        try:
            addr = ipaddress.ip_address(ip)
            
            # Special addresses don't have RIR
            if addr.is_loopback or addr.is_multicast or addr.is_link_local or addr.is_unspecified:
                return "N/A"
            if isinstance(addr, ipaddress.IPv4Address):
                if addr in ipaddress.IPv4Network('10.0.0.0/8'):
                    return "RFC1918 (Private)"
                if addr in ipaddress.IPv4Network('172.16.0.0/12'):
                    return "RFC1918 (Private)"
                if addr in ipaddress.IPv4Network('192.168.0.0/16'):
                    return "RFC1918 (Private)"
                if addr in ipaddress.IPv4Network('100.64.0.0/10'):
                    return "RFC6598 (CGNAT)"
            
            # RIR ranges (approximate)
            rir_ranges = [
                (ipaddress.IPv4Network('0.0.0.0/8'), "RESERVED"),
                (ipaddress.IPv4Network('1.0.0.0/8'), "IANA"),
                (ipaddress.IPv4Network('2.0.0.0/8'), "IANA"),
                (ipaddress.IPv4Network('5.0.0.0/8'), "RIPE"),
                (ipaddress.IPv4Network('3.0.0.0/8'), "General"),
                (ipaddress.IPv4Network('4.0.0.0/8'), "General"),
                (ipaddress.IPv4Network('6.0.0.0/8'), "General"),
                (ipaddress.IPv4Network('7.0.0.0/8'), "General"),
                (ipaddress.IPv4Network('8.0.0.0/8'), "RIPE"),
                (ipaddress.IPv4Network('9.0.0.0/8'), "ARIN"),
                (ipaddress.IPv4Network('11.0.0.0/8'), "US DoD"),
                (ipaddress.IPv4Network('12.0.0.0/8'), "AT&T"),
                (ipaddress.IPv4Network('13.0.0.0/8'), "Xerox"),
                (ipaddress.IPv4Network('14.0.0.0/8'), "ICM"),
                (ipaddress.IPv4Network('15.0.0.0/8'), "Hewlett-Packard"),
                (ipaddress.IPv4Network('16.0.0.0/8'), "DEC"),
                (ipaddress.IPv4Network('17.0.0.0/8'), "Apple"),
                (ipaddress.IPv4Network('18.0.0.0/8'), "Ford"),
                (ipaddress.IPv4Network('19.0.0.0/8'), "IBM"),
                (ipaddress.IPv4Network('20.0.0.0/8'), "AT&T"),
                (ipaddress.IPv4Network('21.0.0.0/8'), "Sun"),
                (ipaddress.IPv4Network('22.0.0.0/8'), "Bbn"),
                (ipaddress.IPv4Network('23.0.0.0/8'), "IBM"),
                (ipaddress.IPv4Network('24.0.0.0/8'), "Csc"),
                (ipaddress.IPv4Network('25.0.0.0/8'), "UK DfE"),
                (ipaddress.IPv4Network('26.0.0.0/8'), "UK DfE"),
                (ipaddress.IPv4Network('27.0.0.0/8'), "Bellcore"),
                (ipaddress.IPv4Network('28.0.0.0/8'), "Bbn"),
                (ipaddress.IPv4Network('29.0.0.0/8'), "IBM"),
                (ipaddress.IPv4Network('30.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('31.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('32.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('33.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('34.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('35.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('36.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('37.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('38.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('39.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('40.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('41.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('42.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('43.0.0.0/8'), "Nasa"),
                (ipaddress.IPv4Network('44.0.0.0/8'), "Amateur Radio"),
                (ipaddress.IPv4Network('45.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('46.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('47.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('48.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('49.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('50.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('51.0.0.0/8'), "UK MoD"),
                (ipaddress.IPv4Network('52.0.0.0/8'), "UK MoD"),
                (ipaddress.IPv4Network('53.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('54.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('55.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('56.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('57.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('58.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('59.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('60.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('61.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('62.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('63.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('64.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('65.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('66.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('67.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('68.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('69.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('70.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('71.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('72.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('73.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('74.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('75.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('76.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('77.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('78.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('79.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('80.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('81.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('82.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('83.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('84.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('85.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('86.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('87.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('88.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('89.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('90.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('91.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('92.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('93.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('94.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('95.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('96.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('97.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('98.0.0.0/8'), "Nextlevel"),
                (ipaddress.IPv4Network('99.0.0.0/8'), "Nextlevel"),
            ]
            
            # More accurate RIR detection based on IP
            first_octet = int(str(addr).split('.')[0]) if isinstance(addr, ipaddress.IPv4Address) else 0
            
            # Major RIR ranges
            if first_octet in range(1, 126):  # General use + early allocations
                # Check against known RIRs
                if first_octet in range(1, 100):  # Early IANA/ARIN
                    return "ARIN/RIR"
            if first_octet in range(128, 167):
                return "ARIN"
            if first_octet in range(168, 191):
                return "RIPE"
            if first_octet in range(192, 223):
                return "RIPE/APNIC"
            if first_octet in range(224, 239):
                return "Multicast"
            if first_octet in range(240, 255):
                return "Future Use"
                
            return "Global"
        except Exception:
            return "N/A"

    def get_ip_classification(self, ip):
        """Get detailed IP address classification - returns all applicable types"""
        try:
            addr = ipaddress.ip_address(ip)
            classifications = []

            # IP Version
            if addr.version == 4:
                classifications.append("IPv4")
            else:
                classifications.append("IPv6")

            # Loopback (127.0.0.0/8)
            if addr.is_loopback:
                classifications.append("Loopback")

            # Unspecified (0.0.0.0 or ::)
            if addr.is_unspecified:
                classifications.append("Unspecified")

            # Private (RFC 1918)
            if addr.is_private:
                classifications.append("Private")
                # Check if it's Carrier Grade NAT (100.64.0.0/10 - RFC 6598)
                if isinstance(addr, ipaddress.IPv4Address):
                    cgnat_range = ipaddress.IPv4Network('100.64.0.0/10')
                    if addr in cgnat_range:
                        classifications.append("Carrier Grade NAT")

            # Link Local (169.254.0.0/16, fe80::/10)
            if addr.is_link_local:
                classifications.append("Link Local")

            # Multicast (224.0.0.0/4, ff00::/8)
            if addr.is_multicast:
                classifications.append("Multicast")

            # Documentation (RFC 5737)
            if isinstance(addr, ipaddress.IPv4Address):
                doc_ranges = [
                    ipaddress.IPv4Network('192.0.2.0/24'),
                    ipaddress.IPv4Network('198.51.100.0/24'),
                    ipaddress.IPv4Network('203.0.113.0/24'),
                ]
                for net in doc_ranges:
                    if addr in net:
                        classifications.append("Documentation")
                        break

            # Benchmarking (RFC 5737)
            if isinstance(addr, ipaddress.IPv4Address):
                if addr in ipaddress.IPv4Network('168.192.0.0/16'):
                    classifications.append("Benchmarking")

            # Future Use (RFC 1112)
            if isinstance(addr, ipaddress.IPv4Address):
                if addr in ipaddress.IPv4Network('240.0.0.0/4'):
                    classifications.append("Future Use")

            # Reserved (other reserved addresses)
            if addr.is_reserved and not any(c in classifications for c in ["Loopback", "Link Local", "Multicast", "Unspecified"]):
                classifications.append("Reserved")

            # Global/Public - if no special classification
            if not classifications or classifications == ["IPv4"] or classifications == ["IPv6"]:
                if not addr.is_private and not addr.is_loopback and not addr.is_link_local and not addr.is_multicast and not addr.is_reserved and not addr.is_unspecified:
                    classifications.append("Global")

            # Default to Public if nothing matches
            if not classifications:
                classifications.append("Public")

            return classifications
        except Exception:
            return ["Unknown"]

    def _get_geo_info(self, ip):
        """Get geolocation info from ip-api.com"""
        cache_key = f"geo_{ip}"
        cached = cache.get(cache_key)
        if cached:
            return cached

        try:
            response = requests.get(f"https://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query,mobile,proxy,hosting", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    info = {
                        "country": data.get("country", "N/A"),
                        "country_code": data.get("countryCode", "N/A"),
                        "region": data.get("regionName", "N/A"),
                        "region_code": data.get("region", "N/A"),
                        "city": data.get("city", "N/A"),
                        "zip": data.get("zip", "N/A"),
                        "lat": data.get("lat", 0),
                        "lon": data.get("lon", 0),
                        "timezone": data.get("timezone", "N/A"),
                        "isp": data.get("isp", "N/A"),
                        "org": data.get("org", "N/A"),
                        "as": data.get("as", "N/A"),
                        "asn": data.get("as", "N/A").split()[0] if data.get("as") else "N/A",
                        "as_name": data.get("asname", "N/A"),
                        "mobile": data.get("mobile", False),
                        "proxy": data.get("proxy", False),
                        "hosting": data.get("hosting", False),
                    }
                    cache.set(cache_key, info, ttl=86400)  # Cache for 24 hours
                    return info
        except Exception:
            pass
        return None

    def _get_ipinfo_info(self, ip):
        """Get additional info from ipinfo.io"""
        cache_key = f"ipinfo_{ip}"
        cached = cache.get(cache_key)
        if cached:
            return cached

        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
            if response.status_code == 200:
                data = response.json()
                info = {
                    "hostname": data.get("hostname", ""),
                    "loc": data.get("loc", ""),
                    "org": data.get("org", ""),
                    "postal": data.get("postal", ""),
                    "timezone": data.get("timezone", ""),
                    "country": data.get("country", ""),
                    "region": data.get("region", ""),
                    "city": data.get("city", ""),
                }
                # Parse loc into lat/lon if not already set
                if info["loc"] and "lat" not in self.results.get("geo", {}):
                    parts = info["loc"].split(",")
                    if len(parts) == 2:
                        info["lat"] = float(parts[0])
                        info["lon"] = float(parts[1])
                cache.set(cache_key, info, ttl=86400)
                return info
        except Exception:
            pass
        return None

    def _get_network_info(self, ip):
        """Get network information (CIDR, ASN path)"""
        info = {}
        try:
            # Try to get CIDR from ip-api.com (already cached)
            geo = self.results.get("geo", {})
            if geo.get("as"):
                info["asn"] = geo.get("asn", "N/A")
                info["as_name"] = geo.get("as_name", "N/A")
                info["org"] = geo.get("org", "N/A")
                info["isp"] = geo.get("isp", "N/A")

            # Check if it's a known hosting/datacenter
            org_lower = (geo.get("org", "") + " " + geo.get("isp", "")).lower()
            hosting_keywords_found = []
            for kw in self.HOSTING_ASN_KEYWORDS:
                if kw in org_lower:
                    hosting_keywords_found.append(kw)
            if hosting_keywords_found:
                info["is_hosting"] = True
                info["hosting_indicators"] = hosting_keywords_found
            else:
                info["is_hosting"] = False

            # Mobile network detection
            info["is_mobile"] = geo.get("mobile", False)

            # Proxy detection from ip-api
            info["is_proxy"] = geo.get("proxy", False)

            # Hosting detection from ip-api
            info["is_hosting_api"] = geo.get("hosting", False)

        except Exception:
            pass
        return info

    def _check_dnsbl(self, ip):
        """Check IP against multiple DNSBLs"""
        results = {"listed": False, "lists": []}

        try:
            # Convert IP to reverse octet format for DNSBL query
            parts = ip.split('.')
            if len(parts) != 4:
                return results
            reversed_ip = f"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}"

            for dnsbl in self.DNSBL_LIST:
                try:
                    query = f"{reversed_ip}.{dnsbl}"
                    hostname, _, _ = socket.gethostbyaddr(query)
                    # If we get here, IP is listed
                    results["listed"] = True
                    results["lists"].append({
                        "dnsbl": dnsbl,
                        "response": hostname,
                    })
                except socket.herror:
                    # Not listed on this DNSBL
                    pass
                except Exception:
                    # DNSBL may be unreachable
                    pass

            results["count"] = len(results["lists"])
        except Exception:
            pass

        return results

    def _detect_proxy_vpn(self, ip, check_ports=False):
        """Detect if IP is a proxy, VPN, or Tor exit node

        Args:
            ip: IP address to check
            check_ports: If True, check common proxy ports (may trigger IDS/firewall alerts)
        """
        result = {
            "is_tor": False,
            "is_proxy": False,
            "is_vpn": False,
            "is_datacenter": False,
            "details": [],
        }

        # 1. Check Tor exit nodes via DNS
        try:
            parts = ip.split('.')
            if len(parts) == 4:
                reversed_ip = f"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}"
                query = f"{reversed_ip}.dnsel.torproject.org"
                try:
                    socket.gethostbyaddr(query)
                    result["is_tor"] = True
                    result["details"].append("Tor exit node (confirmed via Tor DNSEL)")
                except socket.herror:
                    pass
        except Exception:
            pass

        # 2. Check common proxy ports (only if explicitly requested)
        if check_ports:
            logger.warning("IPLookup", f"Port check requested for {ip} - this may trigger IDS/firewall alerts")
            try:
                open_proxy_ports = []
                for port in self.PROXY_PORTS:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1.5)
                        if sock.connect_ex((ip, port)) == 0:
                            open_proxy_ports.append(port)
                        sock.close()
                    except Exception:
                        pass
                if open_proxy_ports:
                    result["is_proxy"] = True
                    result["details"].append(f"Open proxy/VPN ports: {open_proxy_ports}")
            except Exception:
                pass

        # 3. Check geo proxy/hosting flags
        geo = self.results.get("geo", {})
        if geo.get("proxy"):
            result["is_proxy"] = True
            result["details"].append("Flagged as proxy by ip-api.com")
        if geo.get("hosting"):
            result["is_datacenter"] = True
            result["details"].append("Hosted in datacenter (ip-api.com)")

        # 4. Check network info for hosting
        net = self.results.get("network", {})
        if net.get("is_hosting"):
            result["is_datacenter"] = True
            result["details"].append(f"Hosting indicators: {', '.join(net.get('hosting_indicators', []))}")

        # 5. Check if mobile
        if net.get("is_mobile"):
            result["details"].append("Mobile network (3G/4G/5G)")

        return result

    def _get_rdap_info(self, ip):
        """Get RDAP registration info for IP"""
        cache_key = f"rdap_{ip}"
        cached = cache.get(cache_key)
        if cached:
            return cached

        try:
            # Try RIPE RDAP first, then fallback
            rdap_urls = [
                f"https://rdap.db.ripe.net/ip/{ip}",
                f"https://rdap.arin.net/registry/ip/{ip}",
                f"https://rdap.apnic.net/ip/{ip}",
                f"https://rdap.lacnic.net/rdap/ip/{ip}",
                f"https://rdap.afrinic.net/rdap/ip/{ip}",
            ]

            for url in rdap_urls:
                try:
                    response = requests.get(url, timeout=10, headers={"Accept": "application/json"})
                    if response.status_code == 200:
                        data = response.json()
                        info = {}

                        # Extract handle
                        info["handle"] = data.get("handle", "N/A")

                        # Extract name and type
                        if data.get("name"):
                            info["name"] = data["name"]
                        if data.get("type"):
                            info["type"] = data["type"]

                        # Extract parent CIDR
                        if data.get("cidr0_cidrs"):
                            cidrs = data["cidr0_cidrs"]
                            if cidrs:
                                info["cidr"] = f"{cidrs[0].get('v4prefix', '')}/{cidrs[0].get('length', '')}"
                        else:
                            # Alternative CIDR extraction from 'cidr' field
                            if data.get("cidr"):
                                info["cidr"] = data["cidr"]
                            elif data.get("startAddress") and data.get("endAddress"):
                                # Calculate CIDR from range if available
                                info["prefix_range"] = f"{data.get('startAddress')} - {data.get('endAddress')}"

                        # Extract entities (organization)
                        entities = data.get("entities", [])
                        org_info = []
                        for entity in entities:
                            vcard = entity.get("vcardArray", [[], []])
                            if len(vcard) > 1:
                                for item in vcard[1]:
                                    if len(item) >= 3 and item[0] == "fn":
                                        org_info.append(item[3])
                            roles = entity.get("roles", [])
                            if roles:
                                org_info.append(f"({', '.join(roles)})")
                        if org_info:
                            info["organization"] = " ".join(org_info)

                        # Extract events (creation, last changed)
                        events = data.get("events", [])
                        for event in events:
                            if event.get("eventAction") == "registration":
                                info["registration_date"] = event.get("eventDate", "")
                            if event.get("eventAction") == "last changed":
                                info["last_changed"] = event.get("eventDate", "")

                        # Extract abuse contact
                        abuse_contacts = []
                        for entity in entities:
                            for link in entity.get("links", []):
                                if "abuse" in link.get("rel", "").lower() or "abuse" in link.get("value", "").lower():
                                    abuse_contacts.append(link.get("value", ""))
                        if abuse_contacts:
                            info["abuse_contact"] = abuse_contacts[0]

                        # Extract country
                        if data.get("country"):
                            info["country"] = data["country"]

                        cache.set(cache_key, info, ttl=86400)
                        return info
                except Exception:
                    continue

        except Exception:
            pass
        return None

    def _check_abuseipdb(self, ip):
        """Check IP against AbuseIPDB (requires API key)"""
        try:
            from config import DEFAULT_SETTINGS
            api_key = DEFAULT_SETTINGS.get("api_keys", {}).get("abuseipdb", "")
        except (ImportError, KeyError):
            api_key = ""
            return None

        if not api_key:
            return None

        cache_key = f"abuseipdb_{ip}"
        cached = cache.get(cache_key)
        if cached:
            return cached

        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": 90,
                    "verbose": True,
                },
                headers={
                    "Key": api_key,
                    "Accept": "application/json",
                },
                timeout=10
            )
            if response.status_code == 200:
                data = response.json().get("data", {})
                info = {
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "last_reported_at": data.get("lastReportedAt", ""),
                    "is_public": data.get("isPublic", False),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "country_code": data.get("countryCode", ""),
                    "domain": data.get("domain", ""),
                    "hostnames": data.get("hostnames", []),
                    "usage_type": data.get("usageType", ""),
                    "isp": data.get("isp", ""),
                }
                cache.set(cache_key, info, ttl=3600)
                return info
        except Exception:
            pass
        return None

    def _calculate_reputation(self, ip):
        """Calculate overall reputation score for the IP"""
        score = 50  # Start neutral
        reasons = []
        severity = "unknown"

        basic = self.results.get("basic", {})
        classifications = basic.get("classifications", [])

        # Check if special address - don't penalize
        if any(c in ["Private", "Loopback", "Link Local", "Carrier Grade NAT", "Documentation", "Unspecified", "Future Use"] for c in classifications):
            return {
                "score": 100,
                "severity": "safe",
                "reasons": ["Special address range - not routable"],
            }

        # 1. VirusTotal check (positive signal)
        # Check if there's VT data for this IP
        vt_clean = True
        if self.results.get("threat", {}).get("vt_data"):
            vt_clean = False
            reasons.append("VirusTotal data available")
        else:
            reasons.append("Clean VirusTotal")

        # 2. DNSBL listings (strong negative)
        dnsbl = self.results.get("dnsbl", {})
        if dnsbl.get("listed"):
            listed_count = dnsbl.get("count", 0)
            score -= listed_count * 15
            reasons.append(f"Listed in {listed_count} DNSBL(s)")
            if listed_count >= 3:
                score -= 15
                reasons.append("Multiple DNSBL listings (highly suspicious)")
        else:
            reasons.append("Not listed in DNSBL")

        # 3. Tor exit node
        proxy = self.results.get("proxy_vpn", {})
        if proxy.get("is_tor"):
            score -= 20
            reasons.append("Tor exit node")
        else:
            reasons.append("Not a Tor exit node")

        # 4. Proxy/VPN detection
        if proxy.get("is_proxy"):
            score -= 15
            reasons.append("Proxy detected")

        # 5. Datacenter/hosting
        if proxy.get("is_datacenter"):
            score -= 10
            reasons.append("Hosting Provider")
        else:
            reasons.append("Residential or Business network")

        # 6. Reverse DNS check - minimal weight only
        reverse_dns = basic.get("reverse_dns", "")
        if reverse_dns == "PTR Missing":
            score -= 2  # Very small weight - not a threat indicator
            reasons.append("No PTR record (minor)")

        # 7. AbuseIPDB data
        threat = self.results.get("threat", {})
        if threat.get("abuseipdb"):
            abuse = threat["abuseipdb"]
            confidence = abuse.get("abuse_confidence_score", 0)
            if confidence > 50:
                score -= 25
                reasons.append(f"High AbuseIPDB confidence ({confidence}%)")
            elif confidence > 0:
                score -= confidence // 10
                reasons.append(f"AbuseIPDB confidence: {confidence}%")

        # 8. Local IOC match
        if threat.get("local_ioc"):
            score -= 40
            reasons.append("Local IOC database match")

        # Clamp score
        score = max(0, min(100, score))

        # Determine severity
        if score <= 20:
            severity = "dangerous"
        elif score <= 40:
            severity = "suspicious"
        elif score <= 60:
            severity = "warning"
        elif score <= 80:
            severity = "likely_safe"
        else:
            severity = "safe"

        return {
            "score": score,
            "severity": severity,
            "reasons": reasons,
        }