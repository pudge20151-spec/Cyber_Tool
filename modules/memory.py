"""
CyberTool Memory Analysis Module
"""
from core.logger import logger


class MemoryAnalyzer:
    """Analyze system memory usage"""

    def __init__(self):
        self.results = {}

    def analyze(self):
        """Analyze system memory"""
        self.results = {
            "memory": {},
            "swap": {},
            "top_processes": [],
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

            # Top memory processes
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'memory_percent', 'memory_info']):
                try:
                    pinfo = proc.info
                    if pinfo['memory_info']:
                        processes.append({
                            "pid": pinfo['pid'],
                            "name": pinfo['name'],
                            "memory_percent": round(pinfo['memory_percent'] or 0, 2),
                            "memory_mb": round(pinfo['memory_info'].rss / (1024 * 1024), 2),
                        })
                except Exception:
                    continue

            # Sort by memory usage
            processes.sort(key=lambda x: x['memory_percent'], reverse=True)
            self.results["top_processes"] = processes[:20]

            logger.info("MemoryAnalyzer", "Analyzed system memory")

        except ImportError:
            self.results["error"] = "psutil library not installed"
        except Exception as e:
            self.results["error"] = str(e)

        return self.results

    def _bytes_to_gb(self, bytes_val):
        """Convert bytes to GB"""
        return round(bytes_val / (1024 ** 3), 2)