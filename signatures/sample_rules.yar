
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
        $s1 = "AppData\\Roaming" nocase
        $s2 = "\\Temp\\" nocase
        $s3 = "\\Startup\\" nocase
        $s4 = "CurrentVersion\\Run" nocase
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
