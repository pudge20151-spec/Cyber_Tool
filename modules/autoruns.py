"""
CyberTool Autoruns Module
"""
import os
import winreg
from pathlib import Path
from core.logger import logger


class Autoruns:
    """Check all autorun locations"""

    def __init__(self):
        self.results = {}

    def check(self):
        """Check all autorun locations"""
        self.results = {
            "autoruns": []
        }

        self._check_registry_autoruns()
        self._check_startup_folders()
        self._check_scheduled_tasks()
        self._check_services_autoruns()
        self._check_drivers()

        logger.info("Autoruns", f"Found {len(self.results['autoruns'])} autorun entries")
        return self.results

    def _check_registry_autoruns(self):
        """Check all registry autorun locations"""
        autorun_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Active Setup\Installed Components"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\Windows\load"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\Windows\run"),
        ]

        for hkey, key_path in autorun_keys:
            try:
                key = winreg.OpenKey(hkey, key_path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        self.results["autoruns"].append({
                            "type": "Registry",
                            "location": key_path,
                            "name": name,
                            "value": value,
                            "hive": "HKLM" if "LOCAL_MACHINE" in str(hkey) else "HKCU",
                        })
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except Exception:
                continue

    def _check_startup_folders(self):
        """Check startup folders"""
        startup_paths = [
            Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
            Path(os.environ.get("PROGRAMDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
            Path(os.environ.get("ALLUSERSPROFILE", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
        ]

        for path in startup_paths:
            if path.exists():
                for item in path.iterdir():
                    self.results["autoruns"].append({
                        "type": "Startup Folder",
                        "location": str(path),
                        "name": item.name,
                        "value": str(item),
                    })

    def _check_scheduled_tasks(self):
        """Check scheduled tasks"""
        try:
            import subprocess
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "CSV", "/v"],
                capture_output=True, text=True, timeout=30
            )
            lines = result.stdout.split('\n')
            if len(lines) > 2:
                for line in lines[2:]:
                    if line.strip():
                        parts = line.split(',')
                        if len(parts) > 8:
                            task_name = parts[0].strip('"')
                            task_to_run = parts[8].strip('"') if len(parts) > 8 else ""
                            if task_to_run and task_to_run != "N/A":
                                self.results["autoruns"].append({
                                    "type": "Scheduled Task",
                                    "location": "Task Scheduler",
                                    "name": task_name,
                                    "value": task_to_run,
                                })
        except Exception:
            pass

    def _check_services_autoruns(self):
        """Check services that auto-start"""
        try:
            import subprocess
            result = subprocess.run(
                ["sc", "query", "type=", "service", "state=", "all"],
                capture_output=True, text=True, timeout=30
            )
            current_service = {}
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith("SERVICE_NAME"):
                    if current_service and current_service.get("start_type") == "AUTO":
                        self.results["autoruns"].append({
                            "type": "Service",
                            "location": "Services",
                            "name": current_service.get("name", ""),
                            "value": current_service.get("display_name", ""),
                        })
                    current_service = {"name": line.split(":")[1].strip()}
                elif line.startswith("DISPLAY_NAME"):
                    current_service["display_name"] = line.split(":")[1].strip()
                elif line.startswith("START_TYPE"):
                    parts = line.split(":")
                    if len(parts) > 1:
                        start_parts = parts[1].strip().split()
                        current_service["start_type"] = start_parts[1] if len(start_parts) > 1 else ""
            if current_service and current_service.get("start_type") == "AUTO":
                self.results["autoruns"].append({
                    "type": "Service",
                    "location": "Services",
                    "name": current_service.get("name", ""),
                    "value": current_service.get("display_name", ""),
                })
        except Exception:
            pass

    def _check_drivers(self):
        """Check loaded drivers"""
        try:
            import subprocess
            result = subprocess.run(
                ["sc", "query", "type=", "driver", "state=", "all"],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith("SERVICE_NAME"):
                    driver_name = line.split(":")[1].strip()
                    self.results["autoruns"].append({
                        "type": "Driver",
                        "location": "Drivers",
                        "name": driver_name,
                        "value": "",
                    })
        except Exception:
            pass