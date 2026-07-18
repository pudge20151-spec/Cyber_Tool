"""
CyberTool PE Analyzer Module
"""
from pathlib import Path
from core.logger import logger


class PEAnalyzer:
    """Analyze PE (Portable Executable) files"""

    def __init__(self):
        self.results = {}

    def analyze(self, file_path):
        """Analyze PE file structure"""
        path = Path(file_path)
        if not path.exists():
            return {"error": "File not found"}

        self.results = {
            "filename": path.name,
            "file_path": str(path.absolute()),
        }

        try:
            import pefile
            pe = pefile.PE(str(file_path))

            try:
                # DOS Header
                self.results["dos_header"] = {
                    "e_magic": hex(pe.DOS_HEADER.e_magic),
                    "e_lfanew": hex(pe.DOS_HEADER.e_lfanew),
                }

                # PE Header
                if hasattr(pe, 'FILE_HEADER'):
                    fh = pe.FILE_HEADER
                    self.results["pe_header"] = {
                        "machine": self._get_machine_type(fh.Machine),
                        "machine_hex": hex(fh.Machine),
                        "number_of_sections": fh.NumberOfSections,
                        "timestamp": fh.TimeDateStamp,
                        "timestamp_str": self._timestamp_to_str(fh.TimeDateStamp),
                        "characteristics": hex(fh.Characteristics),
                        "size_of_optional_header": fh.SizeOfOptionalHeader,
                    }

                # Optional Header
                if hasattr(pe, 'OPTIONAL_HEADER'):
                    oh = pe.OPTIONAL_HEADER
                    self.results["optional_header"] = {
                        "magic": hex(oh.Magic),
                        "entry_point": hex(oh.AddressOfEntryPoint),
                        "image_base": hex(oh.ImageBase),
                        "subsystem": self._get_subsystem(oh.Subsystem),
                        "subsystem_hex": hex(oh.Subsystem),
                        "major_os_version": f"{oh.MajorOperatingSystemVersion}.{oh.MinorOperatingSystemVersion}",
                        "major_image_version": f"{oh.MajorImageVersion}.{oh.MinorImageVersion}",
                        "major_subsystem_version": f"{oh.MajorSubsystemVersion}.{oh.MinorSubsystemVersion}",
                        "size_of_code": hex(oh.SizeOfCode),
                        "size_of_image": hex(oh.SizeOfImage),
                        "size_of_headers": hex(oh.SizeOfHeaders),
                        "checksum": hex(oh.CheckSum),
                        "dll_characteristics": hex(oh.DllCharacteristics),
                    }

                # Sections
                self.results["sections"] = []
                if hasattr(pe, 'SECTIONS'):
                    for section in pe.sections:
                        section_info = {
                            "name": section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                            "virtual_address": hex(section.VirtualAddress),
                            "virtual_size": hex(section.Misc_VirtualSize),
                            "raw_size": section.SizeOfRawData,
                            "entropy": section.get_entropy(),
                            "characteristics": hex(section.Characteristics),
                        }
                        self.results["sections"].append(section_info)

                # Imports
                self.results["imports"] = []
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode('utf-8', errors='ignore')
                        imports_list = []
                        for imp in entry.imports:
                            if imp.name:
                                imports_list.append(imp.name.decode('utf-8', errors='ignore'))
                            else:
                                imports_list.append(f"ordinal_{imp.ordinal}")
                        self.results["imports"].append({
                            "dll": dll_name,
                            "functions": imports_list[:100]  # Limit per DLL
                        })

                # Exports
                self.results["exports"] = []
                if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        if exp.name:
                            self.results["exports"].append(exp.name.decode('utf-8', errors='ignore'))

                # Resources
                self.results["resources"] = []
                if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                    self._parse_resources(pe.DIRECTORY_ENTRY_RESOURCE.entries)

                # Relocations
                self.results["relocations"] = []
                if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
                    for reloc in pe.DIRECTORY_ENTRY_BASERELOC:
                        self.results["relocations"].append({
                            "virtual_address": hex(reloc.struct.VirtualAddress),
                            "size_of_block": reloc.struct.SizeOfBlock,
                            "entries_count": len(reloc.entries),
                        })

                # Debug info
                self.results["debug"] = []
                if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
                    for debug in pe.DIRECTORY_ENTRY_DEBUG:
                        self.results["debug"].append({
                            "type": debug.struct.Type,
                            "size": debug.struct.SizeOfData,
                            "timestamp": debug.struct.TimeDateStamp,
                        })

                # Certificate
                self.results["certificate"] = None
                if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                    self.results["certificate"] = "Present"

                # TLS
                self.results["tls"] = hasattr(pe, 'DIRECTORY_ENTRY_TLS')

                logger.info("PEAnalyzer", f"Analyzed PE file: {path.name}")
            finally:
                pe.close()
        except ImportError:
            self.results["error"] = "pefile library not installed"
        except Exception as e:
            self.results["error"] = f"PE analysis failed: {str(e)}"

        return self.results

    def _parse_resources(self, entries, depth=0):
        """Parse resource directory entries"""
        if depth > 3:
            return
        for entry in entries:
            if hasattr(entry, 'directory'):
                self._parse_resources(entry.directory.entries, depth + 1)
            elif hasattr(entry, 'data'):
                self.results["resources"].append({
                    "name": str(entry.name) if entry.name else f"ID: {entry.id}",
                    "size": entry.data.struct.Size,
                    "code_page": entry.data.struct.CodePage,
                })

    def _get_machine_type(self, machine):
        """Get machine type string"""
        types = {
            0x14c: "I386",
            0x8664: "AMD64",
            0x1c0: "ARM",
            0xaa64: "ARM64",
            0x200: "IA64",
            0x4: "MIPS",
        }
        return types.get(machine, f"Unknown ({hex(machine)})")

    def _get_subsystem(self, subsystem):
        """Get subsystem string"""
        subsystems = {
            1: "NATIVE",
            2: "WINDOWS_GUI",
            3: "WINDOWS_CUI",
            5: "OS2_CUI",
            7: "POSIX_CUI",
            9: "WINDOWS_CE_GUI",
            10: "EFI_APPLICATION",
            11: "EFI_BOOT_SERVICE_DRIVER",
            12: "EFI_RUNTIME_DRIVER",
            13: "EFI_ROM",
            14: "XBOX",
        }
        return subsystems.get(subsystem, f"Unknown ({subsystem})")

    def _timestamp_to_str(self, timestamp):
        """Convert PE timestamp to string"""
        from datetime import datetime
        try:
            return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return str(timestamp)