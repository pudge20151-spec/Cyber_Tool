"""
CyberTool Memory Analysis Module
"""
from core.logger import logger


class MemoryAnalyzer:
    """Analyze system memory usage and detect suspicious memory patterns"""

    def __init__(self):
        self.results = {}

    def analyze(self):
        """Analyze system memory"""
        self.results = {
            "memory": {},
            "swap": {},
            "top_processes": [],
            "suspicious_processes": [],
            "memory_health": {},
        }

        try:
            import psutil

            # Memory info
            mem = psutil.virtual_memory()
            self.results["memory"] = {
                "total": self._bytes_to_gb(mem.total),
                "available": self._bytes_to_gb(mem.available),
                "used": self._bytes_to_gb(mem.used),
                "percent": mem.percent,
            }

            # Swap info
            swap = psutil.swap_memory()
            self.results["swap"] = {
                "total": self._bytes_to_gb(swap.total),
                "used": self._bytes_to_gb(swap.used),
                "free": self._bytes_to_gb(swap.free),
                "percent": swap.percent,
            }

            # Memory health assessment
            health = {"status": "OK", "warnings": []}
            if mem.percent > 90:
                health["status"] = "CRITICAL"
                health["warnings"].append("Memory usage above 90% - system may be unstable")
            elif mem.percent > 80:
                health["status"] = "WARNING"
                health["warnings"].append("Memory usage above 80% - consider closing applications")
            if swap.percent > 50:
                health["warnings"].append(f"High swap usage ({swap.percent}%) - possible memory pressure")
            self.results["memory_health"] = health

            # Top memory processes
            processes = []
            suspicious = []
            for proc in psutil.process_iter(['pid', 'name', 'memory_percent', 'memory_info', 'cpu_percent', 'exe', 'ppid']):
                try:
                    pinfo = proc.info
                    if pinfo['memory_info']:
                        proc_data = {
                            "pid": pinfo['pid'],
                            "name": pinfo['name'],
                            "memory_percent": round(pinfo['memory_percent'] or 0, 2),
                            "memory_mb": round(pinfo['memory_info'].rss / (1024 * 1024), 2),
                            "cpu_percent": round(pinfo['cpu_percent'] or 0, 1),
                            "exe": pinfo['exe'] or "",
                        }
                        processes.append(proc_data)

                        # Detect suspicious memory patterns
                        reasons = []
                        if pinfo['memory_percent'] and pinfo['memory_percent'] > 30:
                            reasons.append(f"Extremely high memory usage ({pinfo['memory_percent']:.1f}%)")
                        if pinfo['memory_info'] and pinfo['memory_info'].rss > 500 * 1024 * 1024:
                            reasons.append(f"Process using >500MB RAM")
                        if pinfo['exe'] and ('temp' in pinfo['exe'].lower() or 'appdata' in pinfo['exe'].lower()):
                            reasons.append("Running from temp/appdata location")
                        if pinfo['name'] and pinfo['name'].lower() in ['miner.exe', 'xmrig.exe', 'ethminer.exe']:
                            reasons.append("Known mining software")
                        if reasons:
                            proc_data["suspicious_reasons"] = reasons
                            suspicious.append(proc_data)
                except Exception:
                    continue

            # Sort by memory usage
            processes.sort(key=lambda x: x['memory_percent'], reverse=True)
            self.results["top_processes"] = processes[:20]
            self.results["suspicious_processes"] = suspicious

            logger.info("MemoryAnalyzer", f"Analyzed system memory: {len(processes)} processes, {len(suspicious)} suspicious")

        except ImportError:
            self.results["error"] = "psutil library not installed"
        except Exception as e:
            self.results["error"] = str(e)

        return self.results

    def _bytes_to_gb(self, bytes_val):
        """Convert bytes to GB"""
        return round(bytes_val / (1024 ** 3), 2)