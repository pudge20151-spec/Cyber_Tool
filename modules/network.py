"""
CyberTool Network Scanner Module
"""
import socket
import subprocess
from core.logger import logger


class NetworkScanner:
    """Network scanning and diagnostics"""

    def __init__(self):
        self.results = {}

    def ping(self, host):
        """Ping a host"""
        self.results = {"host": host, "alive": False, "response_time": 0}
        try:
            import platform
            param = "-n" if platform.system().lower() == "windows" else "-c"
            result = subprocess.run(
                ["ping", param, "1", host],
                capture_output=True, text=True, timeout=10
            )
            self.results["alive"] = result.returncode == 0
            if result.returncode == 0:
                # Extract response time
                for line in result.stdout.split('\n'):
                    if 'time=' in line.lower() or 'time<' in line.lower():
                        try:
                            time_part = line.split('time=')[1].split('ms')[0].strip()
                            if time_part == '<1':
                                time_part = '0.5'
                            self.results["response_time"] = float(time_part)
                        except Exception:
                            self.results["response_time"] = 0
                        break
        except Exception:
            pass
        return self.results

    def ping_sweep(self, subnet):
        """Ping sweep a subnet (e.g., 192.168.1)"""
        self.results = {"subnet": subnet, "alive_hosts": []}
        for i in range(1, 255):
            ip = f"{subnet}.{i}"
            result = self.ping(ip)
            if result["alive"]:
                self.results["alive_hosts"].append(ip)
        return self.results

    def port_scan(self, host, ports=None):
        """Scan common ports on a host"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                     993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985,
                     5986, 6379, 8080, 8443, 9000, 27017]
        self.results = {"host": host, "open_ports": []}
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    service = self._get_service_name(port)
                    self.results["open_ports"].append({
                        "port": port,
                        "service": service,
                        "banner": self._grab_banner(host, port)
                    })
                sock.close()
            except Exception:
                continue
        return self.results

    def _grab_banner(self, host, port):
        """Grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:200] if banner else ""
        except Exception:
            return ""

    def _get_service_name(self, port):
        """Get service name by port"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM-HTTP",
            5986: "WinRM-HTTPS", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
            9000: "HTTP-Alt2", 27017: "MongoDB",
        }
        return services.get(port, "Unknown")

    def traceroute(self, host):
        """Perform traceroute"""
        self.results = {"host": host, "hops": []}
        try:
            import platform
            cmd = ["tracert" if platform.system().lower() == "windows" else "traceroute"]
            result = subprocess.run(
                cmd + [host], capture_output=True, text=True, timeout=60
            )
            for line in result.stdout.split('\n'):
                if 'ms' in line:
                    self.results["hops"].append(line.strip())
        except Exception:
            pass
        return self.results

    def os_detect(self, host):
        """Basic OS detection via TTL"""
        try:
            import platform
            param = "-n" if platform.system().lower() == "windows" else "-c"
            result = subprocess.run(
                ["ping", param, "1", host],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split('\n'):
                if 'TTL=' in line:
                    ttl = int(line.split('TTL=')[1].split()[0])
                    if ttl <= 64:
                        return "Linux/Unix"
                    elif ttl <= 128:
                        return "Windows"
                    elif ttl <= 255:
                        return "Cisco/Network"
            return "Unknown"
        except Exception:
            return "Unknown"