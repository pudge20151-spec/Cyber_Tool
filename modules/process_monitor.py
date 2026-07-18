"""
CyberTool Process Monitor Module
"""
import os
from datetime import datetime
from pathlib import Path
from core.logger import logger
from core.utils import calculate_file_entropy, is_random_name


class ProcessMonitor:
    """Monitor and analyze running processes"""

    def __init__(self):
        self.results = {}

    def list_processes(self):
        """List all running processes with details"""
        self.results = {"processes": []}
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'ppid', 'exe', 'cpu_percent', 'memory_percent', 'create_time']):
                try:
                    pinfo = proc.info
                    process = {
                        "pid": pinfo['pid'],
                        "name": pinfo['name'],
                        "parent_pid": pinfo['ppid'],
                        "path": pinfo['exe'] or "N/A",
                        "cpu": pinfo['cpu_percent'] or 0,
                        "memory": round(pinfo['memory_percent'] or 0, 2),
                        "created": pinfo['create_time'],
                    }

                    # Check digital signature
                    if pinfo['exe']:
                        process["signed"] = self._check_signed(pinfo['exe'])
                        process["suspicious_path"] = self._check_suspicious_path(pinfo['exe'])
                        process["random_name"] = is_random_name(Path(pinfo['exe']).name)

                    # Check connections
                    try:
                        conns = proc.connections()
                        process["connections"] = len(conns)
                        if conns:
                            process["remote_addresses"] = list(set(
                                f"{c.raddr.ip}:{c.raddr.port}" for c in conns if c.raddr
                            ))
                    except Exception:
                        process["connections"] = 0
                        process["remote_addresses"] = []

                    # Get parent name
                    try:
                        parent = psutil.Process(pinfo['ppid'])
                        process["parent_name"] = parent.name()
                    except Exception:
                        process["parent_name"] = "N/A"

                    # Calculate hash
                    if pinfo['exe'] and os.path.exists(pinfo['exe']):
                        from core.utils import calculate_hashes
                        hashes = calculate_hashes(pinfo['exe'])
                        process["hash"] = hashes.get('sha256', 'N/A')
                    else:
                        process["hash"] = "N/A"

                    self.results["processes"].append(process)

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            logger.info("ProcessMonitor", f"Listed {len(self.results['processes'])} processes")

        except ImportError:
            self.results["error"] = "psutil library not installed"

        return self.results

    def _check_signed(self, file_path):
        """Check if file is digitally signed"""
        try:
            import subprocess
            result = subprocess.run(
                ["powershell", "-Command", 
                 f"Get-AuthenticodeSignature '{file_path}' | Select-Object -ExpandProperty Status"],
                capture_output=True, text=True, timeout=5
            )
            status = result.stdout.strip()
            return status == "Valid"
        except Exception:
            return False

    def _check_suspicious_path(self, file_path):
        """Check if process runs from suspicious location"""
        suspicious_paths = [
            "\\AppData\\", "\\Temp\\", "\\Users\\", "\\Downloads\\",
            "\\Desktop\\", "\\Roaming\\", "\\Local\\Temp\\",
        ]
        path_lower = file_path.lower() if file_path else ""
        for sp in suspicious_paths:
            if sp.lower() in path_lower:
                return True
        return False

    def get_suspicious_processes(self):
        """Get only suspicious processes"""
        self.list_processes()
        suspicious = []
        for proc in self.results.get("processes", []):
            reasons = []
            if not proc.get("signed", True):
                reasons.append("Unsigned")
            if proc.get("suspicious_path"):
                reasons.append("Suspicious path")
            if proc.get("random_name"):
                reasons.append("Random name")
            if proc.get("connections", 0) > 10:
                reasons.append("Many connections")
            if reasons:
                proc["suspicious_reasons"] = reasons
                suspicious.append(proc)
        return suspicious

    def analyze_cpu_usage(self, cpu_threshold=5.0):
        """
        Analyze processes consuming CPU resources
        
        Args:
            cpu_threshold: Minimum CPU percentage to include in results
            
        Returns:
            dict: Analysis of CPU-consuming processes
        """
        self.list_processes()
        
        analysis = {
            "timestamp": datetime.now().isoformat(),
            "total_processes": len(self.results.get("processes", [])),
            "high_cpu_processes": [],
            "top_cpu_consumers": [],
            "suspicious_cpu_processes": [],
            "summary": {}
        }
        
        processes = self.results.get("processes", [])
        
        # Filter processes above threshold
        high_cpu = [p for p in processes if p.get("cpu", 0) >= cpu_threshold]
        analysis["high_cpu_processes"] = high_cpu
        
        # Sort by CPU usage (descending)
        sorted_by_cpu = sorted(processes, key=lambda x: x.get("cpu", 0), reverse=True)
        analysis["top_cpu_consumers"] = sorted_by_cpu[:20]  # Top 20
        
        # Find suspicious processes with high CPU
        for proc in high_cpu:
            suspicious_reasons = []
            if not proc.get("signed", True):
                suspicious_reasons.append("Unsigned executable")
            if proc.get("suspicious_path"):
                suspicious_reasons.append("Running from suspicious location")
            if proc.get("random_name"):
                suspicious_reasons.append("Random/generated name")
            if proc.get("connections", 0) > 20:
                suspicious_reasons.append("Excessive network connections")
            
            if suspicious_reasons:
                proc_copy = proc.copy()
                proc_copy["cpu_risk_reasons"] = suspicious_reasons
                analysis["suspicious_cpu_processes"].append(proc_copy)
        
        # Generate summary statistics
        total_cpu = sum(p.get("cpu", 0) for p in processes)
        avg_cpu = total_cpu / len(processes) if processes else 0
        
        analysis["summary"] = {
            "total_cpu_usage": round(total_cpu, 2),
            "average_cpu_per_process": round(avg_cpu, 2),
            "processes_above_threshold": len(high_cpu),
            "threshold_used": cpu_threshold,
            "suspicious_high_cpu_count": len(analysis["suspicious_cpu_processes"])
        }
        
        logger.info("ProcessMonitor", f"CPU analysis: {len(high_cpu)} processes above {cpu_threshold}% CPU")
        
        return analysis
