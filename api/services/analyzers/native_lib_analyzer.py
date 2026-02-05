"""Native library analyzer for Android .so files."""

import logging
import struct
import tempfile
import zipfile
from pathlib import Path

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)


# ELF constants
ELF_MAGIC = b"\x7fELF"
PT_GNU_RELRO = 0x6474E552
PT_GNU_STACK = 0x6474E551
DT_BIND_NOW = 24
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW = 0x00000008
DF_1_NOW = 0x00000001

# ELF header offsets
EI_CLASS = 4
ELFCLASS32 = 1
ELFCLASS64 = 2


class NativeLibAnalyzer(BaseAnalyzer):
    """Analyzes native libraries (.so files) for security features."""

    name = "native_lib_analyzer"
    platform = "android"

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze native libraries in the APK."""
        findings: list[Finding] = []

        if not app.file_path:
            return findings

        try:
            # Extract and analyze .so files
            so_files = await self._extract_native_libs(Path(app.file_path))

            for lib_path, lib_name, arch in so_files:
                lib_findings = await self._analyze_library(app, lib_path, lib_name, arch)
                findings.extend(lib_findings)

        except Exception as e:
            logger.error(f"Native library analysis failed: {e}")

        return findings

    async def _extract_native_libs(
        self, apk_path: Path
    ) -> list[tuple[Path, str, str]]:
        """Extract .so files from APK."""
        libs = []

        try:
            with zipfile.ZipFile(apk_path, "r") as apk:
                for name in apk.namelist():
                    if name.startswith("lib/") and name.endswith(".so"):
                        # Parse architecture from path: lib/<arch>/<name>.so
                        parts = name.split("/")
                        if len(parts) >= 3:
                            arch = parts[1]
                            lib_name = parts[-1]

                            # Extract to temp file
                            with tempfile.NamedTemporaryFile(
                                suffix=".so", delete=False
                            ) as tmp:
                                tmp.write(apk.read(name))
                                libs.append((Path(tmp.name), lib_name, arch))

        except Exception as e:
            logger.error(f"Failed to extract native libraries: {e}")

        return libs

    async def _analyze_library(
        self,
        app: MobileApp,
        lib_path: Path,
        lib_name: str,
        arch: str,
    ) -> list[Finding]:
        """Analyze a single native library."""
        findings = []

        try:
            with open(lib_path, "rb") as f:
                elf_data = f.read()

            # Verify ELF header
            if elf_data[:4] != ELF_MAGIC:
                return findings

            # Parse ELF
            is_64bit = elf_data[EI_CLASS] == ELFCLASS64
            security_info = self._parse_elf_security(elf_data, is_64bit)

            lib_full_path = f"lib/{arch}/{lib_name}"

            # Check PIE (Position Independent Executable)
            if not security_info.get("pie"):
                findings.append(self.create_finding(
                    app=app,
                    title=f"Native Library Missing PIE: {lib_name}",
                    severity="medium",
                    category="Binary Security",
                    description=(
                        f"The native library '{lib_name}' ({arch}) is not compiled as a "
                        "Position Independent Executable (PIE). PIE enables ASLR "
                        "(Address Space Layout Randomization) which makes exploitation "
                        "more difficult by randomizing memory addresses."
                    ),
                    impact=(
                        "Without PIE, the library loads at predictable memory addresses, "
                        "making it easier for attackers to exploit memory corruption "
                        "vulnerabilities through ROP (Return-Oriented Programming) or "
                        "code reuse attacks."
                    ),
                    remediation=(
                        "Recompile the native library with PIE enabled. For Android NDK:\n"
                        "1. Add to Android.mk: LOCAL_CFLAGS += -fPIE\n"
                        "2. Add to Android.mk: LOCAL_LDFLAGS += -pie\n"
                        "Or in CMakeLists.txt: set(CMAKE_POSITION_INDEPENDENT_CODE ON)"
                    ),
                    file_path=lib_full_path,
                    code_snippet=(
                        f"# ELF Header Analysis for {lib_name}\n"
                        f"Architecture: {arch}\n"
                        f"64-bit: {is_64bit}\n"
                        f"PIE Enabled: False\n"
                        f"e_type: {security_info.get('e_type', 'unknown')}"
                    ),
                    poc_evidence=(
                        f"Native library {lib_name} is not a Position Independent "
                        f"Executable. ELF type indicates non-PIE binary."
                    ),
                    poc_verification=(
                        f"1. Extract APK: unzip app.apk -d extracted/\n"
                        f"2. Check library: readelf -h extracted/{lib_full_path}\n"
                        f"3. Look for 'Type: DYN' (PIE) vs 'Type: EXEC' (non-PIE)"
                    ),
                    poc_commands=[
                        {"type": "bash", "command": f"unzip -o {app.file_path} -d /tmp/extracted", "description": "Extract APK contents"},
                        {"type": "bash", "command": f"readelf -h /tmp/extracted/{lib_full_path} | grep Type", "description": "Check ELF type (DYN=PIE, EXEC=non-PIE)"},
                        {"type": "bash", "command": f"file /tmp/extracted/{lib_full_path}", "description": "Verify file type"},
                    ],
                    cwe_id="CWE-119",
                    cwe_name="Improper Restriction of Operations within Memory Buffer",
                    owasp_masvs_category="MASVS-RESILIENCE",
                    owasp_masvs_control="MSTG-CODE-9",
                    cvss_score=5.3,
                    remediation_commands=[
                        {"type": "android", "command": "LOCAL_CFLAGS += -fPIE -fPIC", "description": "Add to Android.mk for PIE compilation"},
                        {"type": "android", "command": "LOCAL_LDFLAGS += -pie", "description": "Add to Android.mk for PIE linking"},
                        {"type": "cmake", "command": "set(CMAKE_POSITION_INDEPENDENT_CODE ON)", "description": "Or add to CMakeLists.txt"},
                    ],
                ))

            # Check Stack Canaries
            if not security_info.get("stack_canary"):
                findings.append(self.create_finding(
                    app=app,
                    title=f"Native Library Missing Stack Canaries: {lib_name}",
                    severity="medium",
                    category="Binary Security",
                    description=(
                        f"The native library '{lib_name}' ({arch}) appears to be compiled "
                        "without stack canaries (stack protector). Stack canaries detect "
                        "buffer overflows by placing a known value before the return address."
                    ),
                    impact=(
                        "Without stack canaries, stack buffer overflow vulnerabilities are "
                        "easier to exploit. Attackers can overwrite the return address to "
                        "redirect execution flow without being detected."
                    ),
                    remediation=(
                        "Recompile the native library with stack protection enabled:\n"
                        "1. Add to Android.mk: LOCAL_CFLAGS += -fstack-protector-all\n"
                        "2. For stronger protection: LOCAL_CFLAGS += -fstack-protector-strong"
                    ),
                    file_path=lib_full_path,
                    code_snippet=(
                        f"# Security Feature Analysis for {lib_name}\n"
                        f"Architecture: {arch}\n"
                        f"Stack Canary: Not detected\n"
                        f"__stack_chk_fail symbol: Not found"
                    ),
                    poc_evidence=(
                        f"Native library {lib_name} does not contain __stack_chk_fail "
                        f"symbol, indicating stack canaries may not be enabled."
                    ),
                    poc_verification=(
                        f"1. Extract APK: unzip app.apk -d extracted/\n"
                        f"2. Check symbols: nm -D extracted/{lib_full_path} | grep stack_chk\n"
                        f"3. No __stack_chk_fail means no stack canaries"
                    ),
                    poc_commands=[
                        {"type": "bash", "command": f"unzip -o {app.file_path} -d /tmp/extracted", "description": "Extract APK contents"},
                        {"type": "bash", "command": f"nm -D /tmp/extracted/{lib_full_path} | grep -i stack_chk || echo 'No stack canaries found'", "description": "Check for stack canary symbols"},
                        {"type": "bash", "command": f"readelf -s /tmp/extracted/{lib_full_path} | grep -i stack_chk", "description": "Verify stack protector presence"},
                    ],
                    cwe_id="CWE-121",
                    cwe_name="Stack-based Buffer Overflow",
                    owasp_masvs_category="MASVS-RESILIENCE",
                    owasp_masvs_control="MSTG-CODE-9",
                    cvss_score=5.3,
                    remediation_commands=[
                        {"type": "android", "command": "LOCAL_CFLAGS += -fstack-protector-all", "description": "Add to Android.mk for stack protection"},
                        {"type": "android", "command": "LOCAL_CFLAGS += -fstack-protector-strong", "description": "Or use stronger protection"},
                    ],
                ))

            # Check RELRO
            relro_status = security_info.get("relro", "none")
            if relro_status != "full":
                severity = "low" if relro_status == "partial" else "medium"
                findings.append(self.create_finding(
                    app=app,
                    title=f"Native Library Missing Full RELRO: {lib_name}",
                    severity=severity,
                    category="Binary Security",
                    description=(
                        f"The native library '{lib_name}' ({arch}) has {relro_status} RELRO "
                        "(Relocation Read-Only). Full RELRO makes the GOT (Global Offset Table) "
                        "read-only, preventing GOT overwrite attacks."
                    ),
                    impact=(
                        "Without full RELRO, the GOT remains writable and can be targeted by "
                        "attackers to redirect function calls. GOT overwrite is a common "
                        "exploitation technique for memory corruption vulnerabilities."
                    ),
                    remediation=(
                        "Enable full RELRO when compiling:\n"
                        "1. Add to Android.mk: LOCAL_LDFLAGS += -Wl,-z,relro,-z,now\n"
                        "2. Or in CMakeLists.txt: target_link_options(mylib PRIVATE -Wl,-z,relro,-z,now)"
                    ),
                    file_path=lib_full_path,
                    code_snippet=(
                        f"# RELRO Analysis for {lib_name}\n"
                        f"Architecture: {arch}\n"
                        f"RELRO Status: {relro_status}\n"
                        f"PT_GNU_RELRO: {'Present' if security_info.get('has_relro_segment') else 'Missing'}\n"
                        f"BIND_NOW: {'Enabled' if security_info.get('bind_now') else 'Disabled'}"
                    ),
                    poc_evidence=(
                        f"Native library {lib_name} has {relro_status} RELRO protection. "
                        f"Full RELRO requires both GNU_RELRO segment and BIND_NOW flag."
                    ),
                    poc_verification=(
                        f"1. Extract APK: unzip app.apk -d extracted/\n"
                        f"2. Check RELRO: readelf -l extracted/{lib_full_path} | grep RELRO\n"
                        f"3. Check BIND_NOW: readelf -d extracted/{lib_full_path} | grep BIND_NOW"
                    ),
                    poc_commands=[
                        {"type": "bash", "command": f"unzip -o {app.file_path} -d /tmp/extracted", "description": "Extract APK contents"},
                        {"type": "bash", "command": f"readelf -l /tmp/extracted/{lib_full_path} | grep -E 'GNU_RELRO|LOAD'", "description": "Check for RELRO segment"},
                        {"type": "bash", "command": f"readelf -d /tmp/extracted/{lib_full_path} | grep -E 'BIND_NOW|FLAGS'", "description": "Check for BIND_NOW flag"},
                    ],
                    cwe_id="CWE-119",
                    cwe_name="Improper Restriction of Operations within Memory Buffer",
                    owasp_masvs_category="MASVS-RESILIENCE",
                    owasp_masvs_control="MSTG-CODE-9",
                    cvss_score=4.3 if relro_status == "partial" else 5.3,
                    remediation_commands=[
                        {"type": "android", "command": "LOCAL_LDFLAGS += -Wl,-z,relro,-z,now", "description": "Add to Android.mk for full RELRO"},
                        {"type": "cmake", "command": "target_link_options(${TARGET} PRIVATE -Wl,-z,relro,-z,now)", "description": "Or add to CMakeLists.txt"},
                    ],
                ))

            # Check NX (Non-executable stack)
            if not security_info.get("nx"):
                findings.append(self.create_finding(
                    app=app,
                    title=f"Native Library with Executable Stack: {lib_name}",
                    severity="high",
                    category="Binary Security",
                    description=(
                        f"The native library '{lib_name}' ({arch}) has an executable stack. "
                        "The NX (No-eXecute) bit should be set to prevent code execution "
                        "from the stack, which is a common exploitation target."
                    ),
                    impact=(
                        "An executable stack allows attackers to inject shellcode onto the "
                        "stack and execute it directly. This significantly simplifies "
                        "exploitation of stack buffer overflow vulnerabilities."
                    ),
                    remediation=(
                        "Ensure the library is compiled with NX enabled:\n"
                        "1. Add to Android.mk: LOCAL_LDFLAGS += -Wl,-z,noexecstack\n"
                        "2. Modern compilers enable this by default - check your toolchain"
                    ),
                    file_path=lib_full_path,
                    code_snippet=(
                        f"# NX Analysis for {lib_name}\n"
                        f"Architecture: {arch}\n"
                        f"NX (Non-executable stack): Disabled\n"
                        f"GNU_STACK segment: Executable"
                    ),
                    poc_evidence=(
                        f"Native library {lib_name} has an executable stack, allowing "
                        f"shellcode execution on the stack."
                    ),
                    poc_verification=(
                        f"1. Extract APK: unzip app.apk -d extracted/\n"
                        f"2. Check NX: readelf -l extracted/{lib_full_path} | grep -A1 GNU_STACK\n"
                        f"3. Look for 'RWE' (executable) vs 'RW ' (non-executable)"
                    ),
                    poc_commands=[
                        {"type": "bash", "command": f"unzip -o {app.file_path} -d /tmp/extracted", "description": "Extract APK contents"},
                        {"type": "bash", "command": f"readelf -l /tmp/extracted/{lib_full_path} | grep -A1 GNU_STACK", "description": "Check stack executability (RWE=executable, RW=non-executable)"},
                        {"type": "bash", "command": f"execstack -q /tmp/extracted/{lib_full_path} 2>/dev/null || echo 'execstack not available'", "description": "Alternative check with execstack tool"},
                    ],
                    cwe_id="CWE-119",
                    cwe_name="Improper Restriction of Operations within Memory Buffer",
                    owasp_masvs_category="MASVS-RESILIENCE",
                    owasp_masvs_control="MSTG-CODE-9",
                    cvss_score=7.5,
                    remediation_commands=[
                        {"type": "android", "command": "LOCAL_LDFLAGS += -Wl,-z,noexecstack", "description": "Add to Android.mk to disable executable stack"},
                    ],
                ))

            # Check FORTIFY_SOURCE
            if not security_info.get("fortify"):
                findings.append(self.create_finding(
                    app=app,
                    title=f"Native Library Without FORTIFY_SOURCE: {lib_name}",
                    severity="low",
                    category="Binary Security",
                    description=(
                        f"The native library '{lib_name}' ({arch}) does not appear to be "
                        "compiled with FORTIFY_SOURCE. This GCC/Clang feature adds runtime "
                        "bounds checking to common C library functions like strcpy, sprintf, etc."
                    ),
                    impact=(
                        "Without FORTIFY_SOURCE, buffer overflows in standard C functions "
                        "may not be detected. The feature catches many common mistakes "
                        "at compile time and runtime."
                    ),
                    remediation=(
                        "Enable FORTIFY_SOURCE when compiling:\n"
                        "1. Add to Android.mk: LOCAL_CFLAGS += -D_FORTIFY_SOURCE=2\n"
                        "2. Requires optimization (-O1 or higher) to be effective"
                    ),
                    file_path=lib_full_path,
                    code_snippet=(
                        f"# FORTIFY_SOURCE Analysis for {lib_name}\n"
                        f"Architecture: {arch}\n"
                        f"FORTIFY_SOURCE: Not detected\n"
                        f"__*_chk symbols: Not found"
                    ),
                    poc_evidence=(
                        f"Native library {lib_name} does not contain fortified function "
                        f"symbols (e.g., __strcpy_chk), suggesting FORTIFY_SOURCE is disabled."
                    ),
                    poc_verification=(
                        f"1. Extract APK: unzip app.apk -d extracted/\n"
                        f"2. Check fortify: nm -D extracted/{lib_full_path} | grep _chk\n"
                        f"3. Functions like __strcpy_chk indicate fortification"
                    ),
                    poc_commands=[
                        {"type": "bash", "command": f"unzip -o {app.file_path} -d /tmp/extracted", "description": "Extract APK contents"},
                        {"type": "bash", "command": f"nm -D /tmp/extracted/{lib_full_path} | grep -E '_chk$' || echo 'No fortified functions found'", "description": "Check for fortified function symbols"},
                    ],
                    cwe_id="CWE-120",
                    cwe_name="Buffer Copy without Checking Size of Input",
                    owasp_masvs_category="MASVS-RESILIENCE",
                    owasp_masvs_control="MSTG-CODE-9",
                    cvss_score=3.7,
                    remediation_commands=[
                        {"type": "android", "command": "LOCAL_CFLAGS += -D_FORTIFY_SOURCE=2 -O2", "description": "Add to Android.mk to enable FORTIFY_SOURCE"},
                    ],
                ))

        except Exception as e:
            logger.error(f"Failed to analyze library {lib_name}: {e}")

        finally:
            # Clean up temp file
            try:
                lib_path.unlink()
            except Exception:
                pass

        return findings

    def _parse_elf_security(self, data: bytes, is_64bit: bool) -> dict:
        """Parse ELF headers for security features."""
        result = {
            "pie": False,
            "stack_canary": False,
            "relro": "none",
            "has_relro_segment": False,
            "bind_now": False,
            "nx": True,  # Assume NX unless executable stack found
            "fortify": False,
            "e_type": "unknown",
        }

        try:
            # Parse ELF header
            if is_64bit:
                # 64-bit ELF header
                e_type = struct.unpack("<H", data[16:18])[0]
                e_phoff = struct.unpack("<Q", data[32:40])[0]
                e_phentsize = struct.unpack("<H", data[54:56])[0]
                e_phnum = struct.unpack("<H", data[56:58])[0]
            else:
                # 32-bit ELF header
                e_type = struct.unpack("<H", data[16:18])[0]
                e_phoff = struct.unpack("<I", data[28:32])[0]
                e_phentsize = struct.unpack("<H", data[42:44])[0]
                e_phnum = struct.unpack("<H", data[44:46])[0]

            # Check if PIE (shared object)
            result["e_type"] = {2: "EXEC", 3: "DYN"}.get(e_type, str(e_type))
            result["pie"] = e_type == 3  # ET_DYN

            # Parse program headers
            for i in range(e_phnum):
                ph_offset = e_phoff + i * e_phentsize

                if is_64bit:
                    p_type = struct.unpack("<I", data[ph_offset:ph_offset + 4])[0]
                    p_flags = struct.unpack("<I", data[ph_offset + 4:ph_offset + 8])[0]
                else:
                    p_type = struct.unpack("<I", data[ph_offset:ph_offset + 4])[0]
                    p_flags = struct.unpack("<I", data[ph_offset + 24:ph_offset + 28])[0]

                # Check PT_GNU_RELRO
                if p_type == PT_GNU_RELRO:
                    result["has_relro_segment"] = True

                # Check PT_GNU_STACK (NX)
                if p_type == PT_GNU_STACK:
                    # p_flags: PF_X = 1 (executable)
                    if p_flags & 1:
                        result["nx"] = False

            # Check for stack canary symbols
            if b"__stack_chk_fail" in data:
                result["stack_canary"] = True

            # Check for FORTIFY_SOURCE
            fortify_funcs = [
                b"__strcpy_chk", b"__strcat_chk", b"__sprintf_chk",
                b"__memcpy_chk", b"__memmove_chk", b"__strncpy_chk",
            ]
            result["fortify"] = any(func in data for func in fortify_funcs)

            # Check BIND_NOW (for full RELRO)
            # This is a simplification - proper check needs dynamic section parsing
            if b"BIND_NOW" in data or b"\x18\x00\x00\x00" in data:
                result["bind_now"] = True

            # Determine RELRO status
            if result["has_relro_segment"]:
                if result["bind_now"]:
                    result["relro"] = "full"
                else:
                    result["relro"] = "partial"
            else:
                result["relro"] = "none"

        except Exception as e:
            logger.error(f"ELF parsing error: {e}")

        return result
