"""Frida Gadget Injection Service for APK and IPA repackaging.

This service enables Frida instrumentation on non-rooted Android devices and
non-jailbroken iOS devices by embedding frida-gadget into the application binary.
The gadget is a shared library that starts a Frida server inside the target app's
process, allowing script injection without requiring system-level access.

Key capabilities:
    - Download and cache frida-gadget binaries matching the installed Frida version
    - Decompile, patch, rebuild, align, and sign Android APKs
    - Inject frida-gadget into iOS IPAs with optional code signing
    - Support for multiple architectures (arm64, arm, x86, x86_64)
    - Automatic smali patching to load the gadget at app startup

Architecture support:
    - Android: arm64-v8a, armeabi-v7a, x86, x86_64
    - iOS: arm64 (universal dylib)

Important notes:
    - Requires apktool, zipalign, apksigner, keytool for Android
    - Requires unzip, codesign, optool/insert_dylib for iOS
    - Android apps are signed with a debug keystore (generated on first use)
    - iOS apps require a valid signing identity for device installation
"""

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


class GadgetInjectionService:
    """Manages Frida gadget injection for Android APKs and iOS IPAs.

    This service handles the complete repackaging workflow: downloading the
    correct gadget version, decompiling the app, patching the bytecode/binary,
    rebuilding, and signing the output.

    Attributes:
        gadget_cache_dir: Local cache directory for downloaded gadget binaries.
        debug_keystore_path: Path to the Android debug keystore for APK signing.
    """

    def __init__(self):
        """Initialize gadget injection service with cache and keystore paths."""
        self.gadget_cache_dir = Path("/tmp/frida-gadget-cache")
        self.gadget_cache_dir.mkdir(parents=True, exist_ok=True)
        self.debug_keystore_path = self.gadget_cache_dir / "debug.keystore"

    async def inject_android_gadget(
        self,
        apk_path: Path,
        output_path: Path,
        arch: str = "arm64",
    ) -> Path:
        """Inject frida-gadget into an Android APK.

        Downloads the matching gadget binary, decompiles the APK with apktool,
        copies the gadget .so to all detected architecture directories, patches
        the main Activity's onCreate method to load the gadget, sets
        extractNativeLibs flag in the manifest, rebuilds with apktool, aligns
        with zipalign, and signs with apksigner.

        Args:
            apk_path: Path to the original APK file.
            output_path: Path where the patched APK should be written.
            arch: Target architecture (arm64, arm, x86, x86_64). The gadget
                will be copied to all architectures present in the APK.

        Returns:
            Path to the signed, patched APK (same as output_path).

        Raises:
            RuntimeError: If apktool, zipalign, apksigner, or frida is not installed.
            subprocess.CalledProcessError: If any subprocess operation fails.
            FileNotFoundError: If the main Activity or required files are not found.
        """
        logger.info(f"Starting Android gadget injection: {apk_path} -> {output_path}")

        temp_dir = None
        try:
            # Create temporary working directory
            temp_dir = Path(tempfile.mkdtemp(prefix="gadget-inject-android-"))
            logger.debug(f"Created temp directory: {temp_dir}")

            # Download frida-gadget for Android
            arch_map = {
                "arm64": "arm64",
                "arm": "arm",
                "x86": "x86",
                "x86_64": "x86_64",
            }
            if arch not in arch_map:
                raise ValueError(f"Unsupported architecture: {arch}")

            gadget_path = await self._download_gadget("android", arch_map[arch])
            logger.info(f"Downloaded gadget: {gadget_path}")

            # Decompile APK with apktool
            decompile_dir = temp_dir / "decompiled"
            logger.info("Decompiling APK with apktool...")
            await asyncio.to_thread(
                self._run_subprocess,
                ["apktool", "d", str(apk_path), "-o", str(decompile_dir), "-f"],
                timeout=300,
            )

            # Detect architectures present in the APK
            lib_dir = decompile_dir / "lib"
            architectures = []
            if lib_dir.exists():
                architectures = [d.name for d in lib_dir.iterdir() if d.is_dir()]

            if not architectures:
                # No native libs yet - create architecture dirs
                logger.info(f"No native libraries found, creating lib/{arch_map[arch]}/")
                architectures = [f"arm64-v8a" if arch_map[arch] == "arm64" else f"{arch_map[arch]}"]
                (lib_dir / architectures[0]).mkdir(parents=True, exist_ok=True)

            logger.info(f"Detected architectures: {architectures}")

            # Copy frida-gadget.so to all architecture directories
            for arch_dir in architectures:
                target_dir = lib_dir / arch_dir
                target_dir.mkdir(parents=True, exist_ok=True)
                target_so = target_dir / "libfrida-gadget.so"
                shutil.copy2(gadget_path, target_so)
                logger.debug(f"Copied gadget to {target_so}")

            # Patch smali to load frida-gadget in main Activity
            await self._patch_android_smali(decompile_dir)

            # Set extractNativeLibs="true" in AndroidManifest.xml
            await self._patch_android_manifest(decompile_dir)

            # Rebuild APK with apktool
            unsigned_apk = temp_dir / "unsigned.apk"
            logger.info("Rebuilding APK with apktool...")
            await asyncio.to_thread(
                self._run_subprocess,
                ["apktool", "b", str(decompile_dir), "-o", str(unsigned_apk)],
                timeout=300,
            )

            # Zipalign the APK
            aligned_apk = temp_dir / "aligned.apk"
            logger.info("Aligning APK with zipalign...")
            await asyncio.to_thread(
                self._run_subprocess,
                ["zipalign", "-p", "-f", "4", str(unsigned_apk), str(aligned_apk)],
                timeout=60,
            )

            # Generate debug keystore if it doesn't exist
            if not self.debug_keystore_path.exists():
                await self._generate_debug_keystore()

            # Sign the APK with apksigner
            logger.info("Signing APK with apksigner...")
            await asyncio.to_thread(
                self._run_subprocess,
                [
                    "apksigner",
                    "sign",
                    "--ks", str(self.debug_keystore_path),
                    "--ks-pass", "pass:android",
                    "--ks-key-alias", "androiddebugkey",
                    "--out", str(output_path),
                    str(aligned_apk),
                ],
                timeout=60,
            )

            logger.info(f"Successfully injected gadget into APK: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to inject Android gadget: {e}")
            raise

        finally:
            # Cleanup temporary directory
            if temp_dir and temp_dir.exists():
                shutil.rmtree(temp_dir, ignore_errors=True)
                logger.debug(f"Cleaned up temp directory: {temp_dir}")

    async def inject_ios_gadget(
        self,
        ipa_path: Path,
        output_path: Path,
        signing_identity: Optional[str] = None,
    ) -> Path:
        """Inject frida-gadget into an iOS IPA.

        Extracts the IPA, locates the .app bundle and main binary, copies
        FridaGadget.dylib into the Frameworks directory, uses insert_dylib
        to add a load command referencing the gadget, optionally re-signs
        with codesign, and repackages as an IPA.

        Args:
            ipa_path: Path to the original IPA file.
            output_path: Path where the patched IPA should be written.
            signing_identity: Optional code signing identity (e.g.,
                "iPhone Developer: Name (ID)"). If None, the binary is not
                re-signed (will only work on jailbroken devices).

        Returns:
            Path to the patched IPA (same as output_path).

        Raises:
            RuntimeError: If insert_dylib, codesign, or frida is not installed.
            subprocess.CalledProcessError: If any subprocess operation fails.
            FileNotFoundError: If the .app bundle or binary is not found.
        """
        logger.info(f"Starting iOS gadget injection: {ipa_path} -> {output_path}")

        temp_dir = None
        try:
            # Create temporary working directory
            temp_dir = Path(tempfile.mkdtemp(prefix="gadget-inject-ios-"))
            logger.debug(f"Created temp directory: {temp_dir}")

            # Download frida-gadget for iOS (universal dylib)
            gadget_path = await self._download_gadget("ios", "universal")
            logger.info(f"Downloaded gadget: {gadget_path}")

            # Extract IPA
            extract_dir = temp_dir / "extracted"
            extract_dir.mkdir()
            logger.info("Extracting IPA...")
            with zipfile.ZipFile(ipa_path, "r") as zf:
                zf.extractall(extract_dir)

            # Find .app directory
            payload_dir = extract_dir / "Payload"
            if not payload_dir.exists():
                raise FileNotFoundError("Payload directory not found in IPA")

            app_dirs = list(payload_dir.glob("*.app"))
            if not app_dirs:
                raise FileNotFoundError("No .app bundle found in Payload directory")

            app_dir = app_dirs[0]
            logger.info(f"Found app bundle: {app_dir.name}")

            # Find main binary
            info_plist_path = app_dir / "Info.plist"
            if not info_plist_path.exists():
                raise FileNotFoundError("Info.plist not found in .app bundle")

            # Parse Info.plist to get executable name
            import plistlib
            with open(info_plist_path, "rb") as f:
                plist = plistlib.load(f)

            executable_name = plist.get("CFBundleExecutable")
            if not executable_name:
                raise ValueError("CFBundleExecutable not found in Info.plist")

            binary_path = app_dir / executable_name
            if not binary_path.exists():
                raise FileNotFoundError(f"Binary not found: {binary_path}")

            logger.info(f"Found main binary: {binary_path}")

            # Create Frameworks directory if it doesn't exist
            frameworks_dir = app_dir / "Frameworks"
            frameworks_dir.mkdir(exist_ok=True)

            # Copy FridaGadget.dylib to Frameworks
            gadget_target = frameworks_dir / "FridaGadget.dylib"
            shutil.copy2(gadget_path, gadget_target)
            logger.info(f"Copied gadget to {gadget_target}")

            # Use insert_dylib to add load command
            # insert_dylib requires the output to be different from input
            patched_binary = temp_dir / executable_name
            logger.info("Inserting dylib load command with insert_dylib...")

            insert_dylib_path = await self._find_tool("insert_dylib")
            if insert_dylib_path:
                await asyncio.to_thread(
                    self._run_subprocess,
                    [
                        insert_dylib_path,
                        "--inplace",
                        "--all-yes",
                        "@executable_path/Frameworks/FridaGadget.dylib",
                        str(binary_path),
                    ],
                    timeout=60,
                )
            else:
                # Fallback to optool if insert_dylib not available
                logger.warning("insert_dylib not found, trying optool...")
                await asyncio.to_thread(
                    self._run_subprocess,
                    [
                        "optool",
                        "install",
                        "-c", "load",
                        "-p", "@executable_path/Frameworks/FridaGadget.dylib",
                        "-t", str(binary_path),
                    ],
                    timeout=60,
                )

            # Re-sign if signing identity provided
            if signing_identity:
                logger.info(f"Re-signing with identity: {signing_identity}")
                await self._codesign_ios_app(app_dir, signing_identity)
            else:
                logger.warning("No signing identity provided - IPA will not be re-signed")

            # Repackage as IPA
            logger.info("Repackaging as IPA...")
            with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for file_path in extract_dir.rglob("*"):
                    if file_path.is_file():
                        arcname = file_path.relative_to(extract_dir)
                        zf.write(file_path, arcname)

            logger.info(f"Successfully injected gadget into IPA: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to inject iOS gadget: {e}")
            raise

        finally:
            # Cleanup temporary directory
            if temp_dir and temp_dir.exists():
                shutil.rmtree(temp_dir, ignore_errors=True)
                logger.debug(f"Cleaned up temp directory: {temp_dir}")

    async def _download_gadget(self, platform: str, arch: str) -> Path:
        """Download frida-gadget binary for the specified platform and architecture.

        Checks the local cache first. If not found, downloads from the official
        Frida GitHub releases matching the installed Frida version.

        Args:
            platform: Target platform ("android" or "ios").
            arch: Target architecture (android: arm64, arm, x86, x86_64;
                ios: universal).

        Returns:
            Path to the downloaded gadget binary (.so for Android, .dylib for iOS).

        Raises:
            RuntimeError: If frida is not installed or download fails.
        """
        frida_version = await self._get_frida_version()
        logger.debug(f"Detected Frida version: {frida_version}")

        # Build cache filename
        if platform == "android":
            filename = f"frida-gadget-{frida_version}-android-{arch}.so"
            download_name = f"frida-gadget-{frida_version}-android-{arch}.so.xz"
        elif platform == "ios":
            filename = f"frida-gadget-{frida_version}-ios-universal.dylib"
            download_name = f"frida-gadget-{frida_version}-ios-universal.dylib.xz"
        else:
            raise ValueError(f"Unsupported platform: {platform}")

        cache_path = self.gadget_cache_dir / filename

        # Return from cache if exists
        if cache_path.exists():
            logger.debug(f"Using cached gadget: {cache_path}")
            return cache_path

        # Download from GitHub releases
        download_url = f"https://github.com/frida/frida/releases/download/{frida_version}/{download_name}"
        logger.info(f"Downloading gadget from {download_url}")

        try:
            async with httpx.AsyncClient(timeout=300.0, follow_redirects=True) as client:
                response = await client.get(download_url)
                response.raise_for_status()

                # Save compressed file
                compressed_path = self.gadget_cache_dir / download_name
                compressed_path.write_bytes(response.content)
                logger.debug(f"Downloaded compressed gadget: {compressed_path}")

                # Decompress with xz
                await asyncio.to_thread(
                    self._run_subprocess,
                    ["xz", "-d", str(compressed_path)],
                    timeout=60,
                )

                logger.info(f"Decompressed gadget: {cache_path}")
                return cache_path

        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to download gadget (HTTP {e.response.status_code}): {download_url}")
            raise RuntimeError(f"Failed to download frida-gadget: {e}")
        except Exception as e:
            logger.error(f"Failed to download or decompress gadget: {e}")
            raise

    async def _get_frida_version(self) -> str:
        """Get the installed Frida version.

        Returns:
            Version string (e.g., "16.5.9").

        Raises:
            RuntimeError: If frida is not installed.
        """
        try:
            import frida
            version = frida.__version__
            logger.debug(f"Frida version: {version}")
            return version
        except ImportError:
            logger.error("Frida not installed")
            raise RuntimeError("Frida is not installed")

    async def _patch_android_smali(self, decompile_dir: Path) -> None:
        """Patch the main Activity's onCreate method to load frida-gadget.

        Locates the main Activity from AndroidManifest.xml, finds its smali file,
        and inserts System.loadLibrary("frida-gadget") at the start of onCreate.

        Args:
            decompile_dir: Path to the decompiled APK directory.

        Raises:
            FileNotFoundError: If manifest or Activity smali is not found.
        """
        logger.info("Patching smali to load frida-gadget...")

        # Parse AndroidManifest.xml to find main Activity
        manifest_path = decompile_dir / "AndroidManifest.xml"
        if not manifest_path.exists():
            raise FileNotFoundError("AndroidManifest.xml not found")

        manifest_content = manifest_path.read_text()

        # Find activity with MAIN action and LAUNCHER category
        # Example: <activity android:name=".MainActivity"
        activity_match = re.search(
            r'<activity[^>]*android:name="([^"]+)"[^>]*>.*?'
            r'<action android:name="android\.intent\.action\.MAIN".*?'
            r'<category android:name="android\.intent\.category\.LAUNCHER"',
            manifest_content,
            re.DOTALL,
        )

        if not activity_match:
            logger.warning("Main Activity not found, trying first activity...")
            activity_match = re.search(r'<activity[^>]*android:name="([^"]+)"', manifest_content)

        if not activity_match:
            raise FileNotFoundError("No Activity found in AndroidManifest.xml")

        activity_name = activity_match.group(1)
        logger.info(f"Found main Activity: {activity_name}")

        # Convert activity name to smali path
        # .MainActivity -> MainActivity
        # com.example.MainActivity -> com/example/MainActivity
        if activity_name.startswith("."):
            # Relative to package name - need to get package from manifest
            package_match = re.search(r'package="([^"]+)"', manifest_content)
            if package_match:
                package_name = package_match.group(1)
                activity_name = package_name + activity_name

        smali_path = activity_name.replace(".", "/") + ".smali"
        smali_file = decompile_dir / "smali" / smali_path

        # Try smali_classes2, smali_classes3, etc. if not in main smali
        if not smali_file.exists():
            for smali_dir in sorted(decompile_dir.glob("smali*")):
                test_path = smali_dir / smali_path
                if test_path.exists():
                    smali_file = test_path
                    break

        if not smali_file.exists():
            raise FileNotFoundError(f"Smali file not found: {smali_path}")

        logger.info(f"Found smali file: {smali_file}")

        # Read smali content
        smali_content = smali_file.read_text()

        # Find onCreate method
        oncreate_match = re.search(
            r'(\.method.*onCreate\(Landroid/os/Bundle;\)V.*?\.locals \d+)',
            smali_content,
            re.DOTALL,
        )

        if not oncreate_match:
            logger.warning("onCreate method not found, trying alternate pattern...")
            oncreate_match = re.search(
                r'(\.method.*onCreate\(Landroid/os/Bundle;\)V)',
                smali_content,
                re.DOTALL,
            )

        if not oncreate_match:
            raise ValueError("onCreate method not found in Activity smali")

        # Insert gadget loading code after .locals directive
        gadget_code = """
    const-string v0, "frida-gadget"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
"""

        insertion_point = oncreate_match.end()
        patched_content = (
            smali_content[:insertion_point] +
            gadget_code +
            smali_content[insertion_point:]
        )

        # Write patched smali
        smali_file.write_text(patched_content)
        logger.info("Successfully patched smali to load frida-gadget")

    async def _patch_android_manifest(self, decompile_dir: Path) -> None:
        """Set extractNativeLibs='true' in AndroidManifest.xml.

        Required for Android 9+ to ensure native libraries are extracted to
        the filesystem where the dynamic linker can find them.

        Args:
            decompile_dir: Path to the decompiled APK directory.
        """
        manifest_path = decompile_dir / "AndroidManifest.xml"
        if not manifest_path.exists():
            return

        manifest_content = manifest_path.read_text()

        # Check if extractNativeLibs already set
        if 'android:extractNativeLibs' in manifest_content:
            # Replace existing value
            manifest_content = re.sub(
                r'android:extractNativeLibs="false"',
                'android:extractNativeLibs="true"',
                manifest_content,
            )
        else:
            # Add to application tag
            manifest_content = re.sub(
                r'(<application[^>]*)',
                r'\1 android:extractNativeLibs="true"',
                manifest_content,
                count=1,
            )

        manifest_path.write_text(manifest_content)
        logger.info("Set extractNativeLibs='true' in AndroidManifest.xml")

    async def _generate_debug_keystore(self) -> None:
        """Generate a debug keystore for APK signing if it doesn't exist."""
        logger.info(f"Generating debug keystore: {self.debug_keystore_path}")
        await asyncio.to_thread(
            self._run_subprocess,
            [
                "keytool",
                "-genkey",
                "-v",
                "-keystore", str(self.debug_keystore_path),
                "-storepass", "android",
                "-alias", "androiddebugkey",
                "-keypass", "android",
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-validity", "10000",
                "-dname", "CN=Android Debug,O=Android,C=US",
            ],
            timeout=60,
        )
        logger.info("Debug keystore generated successfully")

    async def _codesign_ios_app(self, app_dir: Path, signing_identity: str) -> None:
        """Re-sign an iOS .app bundle with the specified signing identity.

        Args:
            app_dir: Path to the .app bundle.
            signing_identity: Code signing identity string.
        """
        logger.info(f"Re-signing {app_dir.name}...")

        # Sign Frameworks first
        frameworks_dir = app_dir / "Frameworks"
        if frameworks_dir.exists():
            for framework in frameworks_dir.iterdir():
                if framework.is_file() and framework.suffix in [".dylib", ".framework"]:
                    await asyncio.to_thread(
                        self._run_subprocess,
                        [
                            "codesign",
                            "-f",
                            "-s", signing_identity,
                            str(framework),
                        ],
                        timeout=60,
                    )

        # Sign the app bundle
        await asyncio.to_thread(
            self._run_subprocess,
            [
                "codesign",
                "-f",
                "-s", signing_identity,
                "--deep",
                str(app_dir),
            ],
            timeout=120,
        )
        logger.info("Re-signing completed")

    async def _find_tool(self, tool_name: str) -> Optional[str]:
        """Find a tool in PATH.

        Args:
            tool_name: Name of the tool to find.

        Returns:
            Full path to the tool, or None if not found.
        """
        result = await asyncio.to_thread(
            self._run_subprocess,
            ["which", tool_name],
            timeout=5,
            check=False,
        )
        if result["exit_code"] == 0:
            return result["stdout"].strip()
        return None

    def _run_subprocess(
        self,
        cmd: list[str],
        timeout: int = 60,
        check: bool = True,
    ) -> dict[str, any]:
        """Run a subprocess command synchronously.

        Args:
            cmd: Command and arguments to execute.
            timeout: Timeout in seconds.
            check: If True, raise exception on non-zero exit code.

        Returns:
            Dict with keys: exit_code, stdout, stderr.

        Raises:
            subprocess.CalledProcessError: If check=True and exit code is non-zero.
            subprocess.TimeoutExpired: If command exceeds timeout.
        """
        logger.debug(f"Running subprocess: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=check,
            )
            return {
                "exit_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        except subprocess.CalledProcessError as e:
            logger.error(f"Subprocess failed with exit code {e.returncode}: {e.stderr}")
            raise
        except subprocess.TimeoutExpired as e:
            logger.error(f"Subprocess timed out after {timeout}s: {' '.join(cmd)}")
            raise
