"""
CyberTool YARA Scanner Module
"""
from pathlib import Path
from core.logger import logger
from config import SIGNATURES_DIR


class YaraScanner:
    """Scan files using YARA rules"""

    def __init__(self):
        self.results = {}
        self.rules = None

    def load_rules(self, rules_path=None):
        """Load YARA rules from file or directory"""
        try:
            import yara
            if rules_path:
                if Path(rules_path).is_file():
                    self.rules = yara.compile(filepath=rules_path)
                    return True
                elif Path(rules_path).is_dir():
                    rule_files = list(Path(rules_path).glob("*.yar")) + list(Path(rules_path).glob("*.yara"))
                    if rule_files:
                        # Compile all rules
                        namespaces = {}
                        for rf in rule_files:
                            namespaces[rf.stem] = str(rf)
                        self.rules = yara.compile(filepaths=namespaces)
                        return True
            return False
        except ImportError:
            return False
        except Exception as e:
            logger.error("YaraScanner", f"Failed to load rules: {e}")
            return False

    def scan(self, file_path):
        """Scan a file with loaded YARA rules"""
        self.results = {
            "file": file_path,
            "matches": [],
            "error": None
        }

        if not self.rules:
            # Try to load default rules
            if not self.load_rules(str(SIGNATURES_DIR)):
                self.results["error"] = "No YARA rules loaded"
                return self.results

        try:
            matches = self.rules.match(file_path)
            for match in matches:
                match_info = {
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "tags": list(match.tags),
                    "meta": dict(match.meta),
                    "strings": []
                }
                for s in match.strings:
                    match_info["strings"].append({
                        "identifier": s[1],
                        "data": s[2].decode('utf-8', errors='ignore')[:100] if isinstance(s[2], bytes) else str(s[2])[:100],
                    })
                self.results["matches"].append(match_info)

            logger.info("YaraScanner", f"Scanned {file_path}: {len(matches)} matches")

        except Exception as e:
            self.results["error"] = str(e)

        return self.results

    def create_sample_rule(self):
        """Create a sample YARA rule file"""
        sample_rule = """
rule SuspiciousStrings
{
    meta:
        description = "Detects files with suspicious strings"
        author = "CyberTool"
        date = "2026-07-17"
    strings:
        $s1 = "CreateRemoteThread" nocase
        $s2 = "VirtualAllocEx" nocase
        $s3 = "WriteProcessMemory" nocase
        $s4 = "NtOpenProcess" nocase
        $s5 = "LoadLibraryA" nocase
        $s6 = "WinExec" nocase
        $s7 = "powershell" nocase
        $s8 = "cmd.exe" nocase
    condition:
        any of them
}

rule PotentialMalware
{
    meta:
        description = "Detects potential malware indicators"
        author = "CyberTool"
    strings:
        $s1 = "AppData\\\\Roaming" nocase
        $s2 = "\\\\Temp\\\\" nocase
        $s3 = "\\\\Startup\\\\" nocase
        $s4 = "CurrentVersion\\\\Run" nocase
    condition:
        2 of them
}

rule HighEntropy
{
    meta:
        description = "Detects high entropy sections (potential packing)"
        author = "CyberTool"
    condition:
        pe and pe.sections[0].entropy > 7.0
}
"""
        rule_path = SIGNATURES_DIR / "sample_rules.yar"
        rule_path.write_text(sample_rule)
        logger.info("YaraScanner", f"Created sample rule: {rule_path}")
        return str(rule_path)