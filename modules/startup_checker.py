"""
CyberTool Startup Checker Module
"""
import os
import winreg
from pathlib import Path
from core.logger import logger


class StartupChecker:
    """Check startup locations for persistence"""

    def __init__(self):
        self.results = {}

    def check(self):
        """Check all startup locations"""
        self.results = {
            "registry_run": [],
            "startup_folder": [],
            "services": [],
            "scheduled_tasks": [],
        }

        self._check_registry_run()
        self._check_startup_folder()
        self._check_services()
        self._check_scheduled_tasks()

        logger.info("StartupChecker", "Checked startup locations")
        return self.results

    def _check_registry_run(self):
        """Check Registry Run keys"""
        run_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        ]

        for hkey, key_path in run_keys:
            try:
                key = winreg.OpenKey(hkey, key_path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        self.results["registry_run"].append({
                            "key": key_path,
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

    def _check_startup_folder(self):
        """Check Startup folders"""
        startup_paths = [
            Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
            Path(os.environ.get("PROGRAMDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
        ]

        for path in startup_paths:
            if path.exists():
                for item in path.iterdir():
                    self.results["startup_folder"].append({
                        "path": str(item),
                        "name": item.name,
                        "type": "Directory" if item.is_dir() else "File",
                    })

    def _check_services(self):
        """Check Windows services"""
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
                    if current_service:
                        self.results["services"].append(current_service)
                    current_service = {"name": line.split(":")[1].strip()}
                elif line.startswith("DISPLAY_NAME"):
                    current_service["display_name"] = line.split(":")[1].strip()
                elif line.startswith("STATE"):
                    parts = line.split(":")
                    if len(parts) > 1:
                        state_parts = parts[1].strip().split()
                        current_service["state"] = state_parts[1] if len(state_parts) > 1 else parts[1].strip()
                elif line.startswith("START_TYPE"):
                    parts = line.split(":")
                    if len(parts) > 1:
                        current_service["start_type"] = parts[1].strip().split()[1] if len(parts[1].strip().split()) > 1 else parts[1].strip()
            if current_service:
                self.results["services"].append(current_service)
        except Exception:
            pass

    def _check_scheduled_tasks(self):
        """Check scheduled tasks"""
        try:
            import subprocess
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "LIST", "/v"],
                capture_output=True, text=True, timeout=30
            )
            current_task = {}
            for line in result.stdout.split('\n'):
                line = line.strip()
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip()
                    value = value.strip()
                    if key == "TaskName":
                        if current_task:
                            self.results["scheduled_tasks"].append(current_task)
                        current_task = {"task_name": value}
                    elif key == "Status":
                        current_task["status"] = value
                    elif key == "Next Run Time":
                        current_task["next_run"] = value
                    elif key == "Task To Run":
                        current_task["task_to_run"] = value
            if current_task:
                self.results["scheduled_tasks"].append(current_task)
        except Exception:
            pass