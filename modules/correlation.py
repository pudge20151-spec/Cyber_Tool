"""
CyberTool Correlation Engine Module
"""
from datetime import datetime, timedelta
from core.logger import logger
from core.database import db


class CorrelationEngine:
    """Correlate analysis results for threat detection"""

    def __init__(self):
        self.results = {}

    def analyze(self, **kwargs):
        """Correlate multiple analysis results"""
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "findings": [],
            "risk_score": 0,
            "threat_level": "LOW",
        }

        total_weight = 0
        findings = []

        # File + Process correlation
        if "file_results" in kwargs and "process_results" in kwargs:
            corr = self._correlate_file_process(
                kwargs["file_results"], kwargs["process_results"]
            )
            if corr:
                findings.extend(corr)
                total_weight += sum(f.get("weight", 0) for f in corr)

        # Network + Process correlation
        if "network_results" in kwargs and "process_results" in kwargs:
            corr = self._correlate_network_process(
                kwargs["network_results"], kwargs["process_results"]
            )
            if corr:
                findings.extend(corr)
                total_weight += sum(f.get("weight", 0) for f in corr)

        # URL + DNS correlation
        if "url_results" in kwargs and "dns_results" in kwargs:
            corr = self._correlate_url_dns(
                kwargs["url_results"], kwargs["dns_results"]
            )
            if corr:
                findings.extend(corr)
                total_weight += sum(f.get("weight", 0) for f in corr)

        # Hash + VirusTotal correlation
        if "hash_results" in kwargs and "vt_results" in kwargs:
            corr = self._correlate_hash_vt(
                kwargs["hash_results"], kwargs["vt_results"]
            )
            if corr:
                findings.extend(corr)
                total_weight += sum(f.get("weight", 0) for f in corr)

        # IOA (Indicators of Attack) pattern matching
        if "file_results" in kwargs:
            ioa = self._detect_attack_patterns(kwargs["file_results"])
            if ioa:
                findings.extend(ioa)
                total_weight += sum(f.get("weight", 0) for f in ioa)

        self.results["findings"] = findings
        self.results["risk_score"] = min(total_weight, 100)

        # Determine threat level
        if self.results["risk_score"] >= 75:
            self.results["threat_level"] = "CRITICAL"
        elif self.results["risk_score"] >= 50:
            self.results["threat_level"] = "HIGH"
        elif self.results["risk_score"] >= 25:
            self.results["threat_level"] = "MEDIUM"
        else:
            self.results["threat_level"] = "LOW"

        # Log if significant findings
        if findings:
            logger.info("CorrelationEngine",
                       f"Found {len(findings)} correlations, risk: {self.results['risk_score']}")

        return self.results

    def _correlate_file_process(self, file_results, process_results):
        """Correlate file analysis with process list"""
        findings = []
        file_name = file_results.get("filename", "").lower()
        processes = process_results.get("processes", [])

        for proc in processes:
            proc_name = proc.get("name", "").lower()
            proc_path = proc.get("path", "").lower()

            # Running from suspicious file
            if file_name and file_name in proc_name:
                findings.append({
                    "type": "FILE_PROCESS_MATCH",
                    "description": f"Analyzed file is running as process: {proc['name']} (PID: {proc['pid']})",
                    "weight": 25,
                    "indicators": [file_name, proc["name"]],
                })

            # Unsigned process with connections
            if not proc.get("signed") and proc.get("connections", 0) > 0:
                findings.append({
                    "type": "UNSIGNED_NETWORK_PROCESS",
                    "description": f"Unsigned process with network connections: {proc['name']}",
                    "weight": 20,
                    "indicators": [proc["name"], str(proc["pid"])],
                })

        return findings

    def _correlate_network_process(self, network_results, process_results):
        """Correlate network activity with processes"""
        findings = []
        processes = process_results.get("processes", [])

        for proc in processes:
            if proc.get("connections", 0) > 5 and not proc.get("signed"):
                findings.append({
                    "type": "SUSPICIOUS_NETWORK_ACTIVITY",
                    "description": f"Unsigned process with high network activity: {proc['name']}",
                    "weight": 30,
                    "indicators": [proc["name"], f"{proc['connections']} connections"],
                })

        return findings

    def _correlate_url_dns(self, url_results, dns_results):
        """Correlate URL analysis with DNS data"""
        findings = []

        if "error" not in dns_results:
            records = dns_results.get("records", {})

            # Check for missing security records
            if not records.get("MX"):
                findings.append({
                    "type": "NO_MAIL_RECORDS",
                    "description": "Domain has no mail exchange records",
                    "weight": 5,
                    "indicators": [dns_results.get("domain", "")],
                })

        # Check URL redirects
        redirects = url_results.get("checks", {}).get("redirects", {})
        if redirects and redirects.get("redirect_count", 0) > 2:
            findings.append({
                "type": "MULTIPLE_REDIRECTS",
                "description": f"URL has {redirects['redirect_count']} redirects - potential tracking",
                "weight": 15,
                "indicators": [url_results.get("url", "")],
            })

        return findings

    def _correlate_hash_vt(self, hash_results, vt_results):
        """Correlate hash check with VirusTotal"""
        findings = []

        if "error" not in vt_results:
            malicious = vt_results.get("malicious", 0)
            total = vt_results.get("total_engines", 0)

            if malicious > 0:
                ratio = (malicious / total) * 100 if total > 0 else 0
                threat_label = vt_results.get("threat_label", "Unknown")

                findings.append({
                    "type": "VT_MALICIOUS",
                    "description": f"VirusTotal: {malicious}/{total} engines detected ({ratio:.0f}%) - {threat_label}",
                    "weight": min(int(ratio), 40),
                    "indicators": [threat_label, f"{malicious}/{total}"],
                })

        return findings

    def _detect_attack_patterns(self, file_results):
        """Detect attack patterns from file analysis"""
        findings = []
        score = 0

        apis = file_results.get("suspicious_apis", [])
        api_set = set(api.lower() for api in apis)

        # Process injection pattern
        injection_apis = {"createremotethread", "virtualallocex", "writeprocessmemory"}
        if injection_apis.intersection(api_set):
            findings.append({
                "type": "PROCESS_INJECTION",
                "description": "Process injection API calls detected (CreateRemoteThread, VirtualAllocEx, WriteProcessMemory)",
                "weight": 35,
                "indicators": list(injection_apis.intersection(api_set)),
            })

        # Keylogging pattern
        keylogging_apis = {"getasynckeystate", "getkeystate", "setwindowshookex"}
        if keylogging_apis.intersection(api_set):
            findings.append({
                "type": "KEYLOGGING",
                "description": "Keylogging API calls detected",
                "weight": 30,
                "indicators": list(keylogging_apis.intersection(api_set)),
            })

        # Persistence pattern
        persistence_apis = {"regsetvalue", "createservice", "openscmanager"}
        if persistence_apis.intersection(api_set):
            findings.append({
                "type": "PERSISTENCE",
                "description": "Persistence mechanism API calls detected",
                "weight": 25,
                "indicators": list(persistence_apis.intersection(api_set)),
            })

        # Downloader pattern
        download_apis = {"urldownloadtofile", "internetopen", "urlmonitor"}
        if download_apis.intersection(api_set):
            findings.append({
                "type": "DOWNLOADER",
                "description": "File download capability detected",
                "weight": 20,
                "indicators": list(download_apis.intersection(api_set)),
            })

        # Packed + unsigned
        if file_results.get("packed") and "Unsigned" in str(file_results.get("digital_signature", "")):
            findings.append({
                "type": "PACKED_UNSIGNED",
                "description": "Packed and unsigned executable",
                "weight": 25,
                "indicators": ["packed", "unsigned"],
            })

        return findings

    def get_timeline(self, hours=24):
        """Get correlation timeline from recent scans"""
        try:
            history = db.get_scan_history(100)
            timeline = []
            for h in history:
                timeline.append({
                    "id": h[0],
                    "type": h[1],
                    "target": h[2],
                    "risk_score": h[4],
                    "timestamp": h[5],
                })

            # Group by time
            from collections import Counter
            time_groups = Counter()
            for item in timeline:
                if item["timestamp"]:
                    hour = str(item["timestamp"])[:13]  # Group by hour
                    time_groups[hour] += 1

            return {
                "total_scans": len(timeline),
                "timeline": timeline[:50],
                "activity_by_hour": dict(time_groups.most_common(24)),
            }
        except Exception:
            return {"error": "Could not generate timeline"}