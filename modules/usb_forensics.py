"""
CyberTool USB Forensics Module
"""
import os
import json
import winreg
from pathlib import Path
from datetime import datetime
from core.logger import logger


class USBForensics:
    """Analyze USB device history and artifacts"""

    def __init__(self):
        self.results = {}

    def analyze(self):
        """Analyze USB device history"""
        self.results = {
            "current_devices": [],
            "historical_devices": [],
            "mount_points": [],
            "suspicious_devices": [],
            "summary": {},
        }

        self._check_current_drives()
        self._check_registry_history()
        self._check_mount_points()
        self._check_usb_stor()

        self.results["summary"] = {
            "current_devices": len(self.results["current_devices"]),
            "historical_devices": len(self.results["historical_devices"]),
            "suspicious": len(self.results["suspicious_devices"]),
            "total_unique": len(set(
                d.get("serial", "") for d in self.results["historical_devices"]
                if d.get("serial")
            )),
        }

        logger.info("USBForensics", f"Found {self.results['summary']['historical_devices']} USB devices")
        return self.results

    def _check_current_drives(self):
        """Check currently connected drives"""
        try:
            import psutil
            for partition in psutil.disk_partitions():
                if 'removable' in partition.opts.lower():
                    try:
                        usage = psutil.disk_usage(partition.mountpoint)
                        device_info = {
                            "device": partition.device,
                            "mount_point": partition.mountpoint,
                            "fstype": partition.fstype,
                            "total_size": self._format_size(usage.total),
                            "used": self._format_size(usage.used),
                            "free": self._format_size(usage.free),
                            "percent_used": usage.percent,
                        }
                        self.results["current_devices"].append(device_info)
                    except Exception:
                        self.results["current_devices"].append({
                            "device": partition.device,
                            "mount_point": partition.mountpoint,
                            "fstype": partition.fstype,
                        })
        except ImportError:
            pass

    def _check_registry_history(self):
        """Check registry for USB device history"""
        usb_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USB"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USBSTOR"),
        ]

        for hkey, key_path in usb_keys:
            try:
                key = winreg.OpenKey(hkey, key_path, 0, winreg.KEY_READ)
                self._enum_usb_key(key, key_path)
                winreg.CloseKey(key)
            except Exception:
                continue

        # Check USB device classes
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\DeviceClasses\{a5dcbf10-6530-11d2-901f-00c04fb951ed}",
                0, winreg.KEY_READ
            )
            self._enum_device_classes(key)
            winreg.CloseKey(key)
        except Exception:
            pass

    def _enum_usb_key(self, key, key_path):
        """Enumerate USB registry key"""
        i = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(key, i)
                subkey_path = f"{key_path}\\{subkey_name}"

                try:
                    subkey = winreg.OpenKey(key, subkey_name, 0, winreg.KEY_READ)
                    self._enum_usb_devices(subkey, subkey_path)
                    winreg.CloseKey(subkey)
                except Exception:
                    pass

                i += 1
            except OSError:
                break

    def _enum_usb_devices(self, key, key_path):
        """Enumerate USB devices under a key"""
        j = 0
        while True:
            try:
                device_key_name = winreg.EnumKey(key, j)
                device_path = f"{key_path}\\{device_key_name}"

                try:
                    device_key = winreg.OpenKey(key, device_key_name, 0, winreg.KEY_READ)
                    device_info = self._get_device_info(device_key, device_path)
                    if device_info:
                        self.results["historical_devices"].append(device_info)
                    winreg.CloseKey(device_key)
                except Exception:
                    pass

                j += 1
            except OSError:
                break

    def _get_device_info(self, key, device_path):
        """Get detailed device information"""
        info = {
            "path": device_path,
            "serial": "",
            "friendly_name": "",
            "class": "",
            "first_install": "",
            "last_connected": "",
        }

        try:
            # Try to get FriendlyName
            try:
                info["friendly_name"] = winreg.QueryValueEx(key, "FriendlyName")[0]
            except Exception:
                pass

            # Try to get DeviceDesc
            try:
                info["description"] = winreg.QueryValueEx(key, "DeviceDesc")[0]
            except Exception:
                pass

            # Get Class
            try:
                info["class"] = winreg.QueryValueEx(key, "Class")[0]
            except Exception:
                pass

            # Get serial from path
            parts = device_path.split("\\")
            if len(parts) > 2:
                info["serial"] = parts[-1]

            # Check Properties subkey for timestamps
            try:
                props_key = winreg.OpenKey(key, "Properties", 0, winreg.KEY_READ)
                info["first_install"] = self._get_property_date(props_key, "{83da6326-97a6-4088-9453-a1923f573b29} 5")
                info["last_connected"] = self._get_property_date(props_key, "{83da6326-97a6-4088-9453-a1923f573b29} 6")
                winreg.CloseKey(props_key)
            except Exception:
                pass

            return info

        except Exception:
            return None

    def _get_property_date(self, key, property_name):
        """Get date from registry property"""
        try:
            from datetime import timedelta
            value, _ = winreg.QueryValueEx(key, property_name)
            if value:
                # FILETIME format
                try:
                    epoch = datetime(1601, 1, 1)
                    dt = epoch + timedelta(microseconds=value // 10)
                    return dt.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    return str(value)
        except Exception:
            return ""

    def _enum_device_classes(self, key):
        """Enumerate device classes"""
        i = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(key, i)
                # Parse the symbolic link to get device info
                try:
                    subkey = winreg.OpenKey(key, subkey_name, 0, winreg.KEY_READ)
                    try:
                        symlink = winreg.QueryValueEx(subkey, "SymbolicLink")[0]
                        if symlink:
                            self.results["mount_points"].append(symlink)
                    except Exception:
                        pass
                    winreg.CloseKey(subkey)
                except Exception:
                    pass
                i += 1
            except OSError:
                break

    def _check_mount_points(self):
        """Check mount points"""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\MountedDevices",
                0, winreg.KEY_READ
            )
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    name_str = name if isinstance(name, str) else name.decode('utf-8', errors='ignore')
                    if 'DosDevices' in name_str or name_str.startswith('\\??\\'):
                        self.results["mount_points"].append(name_str)
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass

    def _check_usb_stor(self):
        """Check USBSTOR for device identifiers"""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Enum\USBSTOR",
                0, winreg.KEY_READ
            )
            self._enum_usb_stor(key)
            winreg.CloseKey(key)
        except Exception:
            pass

    def _enum_usb_stor(self, key):
        """Enumerate USBSTOR devices"""
        i = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(key, i)
                subkey = winreg.OpenKey(key, subkey_name, 0, winreg.KEY_READ)

                j = 0
                while True:
                    try:
                        serial_key_name = winreg.EnumKey(subkey, j)
                        serial_key = winreg.OpenKey(subkey, serial_key_name, 0, winreg.KEY_READ)

                        device_info = {
                            "serial": serial_key_name,
                            "model": subkey_name,
                        }

                        # Check for Properties
                        try:
                            props_key = winreg.OpenKey(serial_key, "Properties", 0, winreg.KEY_READ)
                            try:
                                device_info["first_installed"] = self._get_property_date(
                                    props_key, "{83da6326-97a6-4088-9453-a1923f573b29} 5"
                                )
                            except Exception:
                                pass
                            winreg.CloseKey(props_key)
                        except Exception:
                            pass

                        self.results["historical_devices"].append(device_info)
                        winreg.CloseKey(serial_key)
                        j += 1
                    except OSError:
                        break

                winreg.CloseKey(subkey)
                i += 1
            except OSError:
                break

    def _format_size(self, bytes_val):
        """Format size to human readable"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} PB"