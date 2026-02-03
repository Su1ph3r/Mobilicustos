"""Library fingerprinting for CVE detection.

Detects libraries through multiple methods:
- Native library analysis (.so files)
- SDK detection via package patterns
- Framework version extraction
- Binary signature matching
"""

import hashlib
import logging
import re
from pathlib import Path

from api.services.cve.models import (
    DetectedLibrary,
    DetectionMethod,
    LibrarySource,
    NativeLibSignature,
    SDKSignature,
)

logger = logging.getLogger(__name__)


# Native library signatures for common vulnerable libraries
NATIVE_LIB_SIGNATURES: dict[str, NativeLibSignature] = {
    "openssl": NativeLibSignature(
        library_name="openssl",
        export_symbols=["SSL_new", "SSL_connect", "EVP_aes_256_cbc", "RSA_new"],
        version_patterns=[
            r"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)",
            r"OpenSSL/(\d+\.\d+\.\d+)",
        ],
        file_patterns=["libssl.so*", "libcrypto.so*"],
    ),
    "sqlite": NativeLibSignature(
        library_name="sqlite",
        export_symbols=["sqlite3_open", "sqlite3_exec", "sqlite3_prepare_v2"],
        version_patterns=[
            r"(\d+\.\d+\.\d+)\s+\d{4}-\d{2}-\d{2}",
            r"SQLite\s+version\s+(\d+\.\d+\.\d+)",
        ],
        file_patterns=["libsqlite.so*", "libsqlite3.so*"],
    ),
    "curl": NativeLibSignature(
        library_name="curl",
        export_symbols=["curl_easy_init", "curl_easy_perform", "curl_global_init"],
        version_patterns=[
            r"libcurl/(\d+\.\d+\.\d+)",
            r"curl\s+(\d+\.\d+\.\d+)",
        ],
        file_patterns=["libcurl.so*"],
    ),
    "ffmpeg": NativeLibSignature(
        library_name="ffmpeg",
        export_symbols=["avcodec_open2", "avformat_open_input", "av_read_frame"],
        version_patterns=[
            r"FFmpeg\s+version\s+(\d+\.\d+(?:\.\d+)?)",
            r"libavcodec\s+(\d+\.\d+\.\d+)",
        ],
        file_patterns=["libavcodec.so*", "libavformat.so*", "libavutil.so*"],
    ),
    "zlib": NativeLibSignature(
        library_name="zlib",
        export_symbols=["deflate", "inflate", "compress", "uncompress"],
        version_patterns=[
            r"(\d+\.\d+\.\d+)",
        ],
        file_patterns=["libz.so*"],
    ),
    "libjpeg": NativeLibSignature(
        library_name="libjpeg",
        export_symbols=["jpeg_create_decompress", "jpeg_read_header", "jpeg_start_decompress"],
        version_patterns=[
            r"libjpeg(?:-turbo)?\s+(\d+\.\d+(?:\.\d+)?)",
        ],
        file_patterns=["libjpeg.so*", "libjpeg-turbo.so*"],
    ),
    "libpng": NativeLibSignature(
        library_name="libpng",
        export_symbols=["png_create_read_struct", "png_read_image", "png_set_sig_bytes"],
        version_patterns=[
            r"libpng\s+version\s+(\d+\.\d+\.\d+)",
            r"(\d+\.\d+\.\d+)",
        ],
        file_patterns=["libpng*.so*"],
    ),
    "boringssl": NativeLibSignature(
        library_name="boringssl",
        export_symbols=["SSL_new", "SSL_connect", "CRYPTO_library_init"],
        version_patterns=[],  # BoringSSL doesn't have version strings
        file_patterns=["libboringssl.so*"],
    ),
}


# SDK signatures for mobile SDKs
SDK_SIGNATURES: dict[str, SDKSignature] = {
    "firebase": SDKSignature(
        sdk_name="firebase",
        package_patterns=[
            "com.google.firebase",
            "com.google.android.gms.internal.firebase",
        ],
        resource_patterns=[
            "google-services.json",
            "firebase_*.xml",
        ],
        class_patterns=[
            "Lcom/google/firebase/",
        ],
    ),
    "facebook": SDKSignature(
        sdk_name="facebook",
        package_patterns=[
            "com.facebook.android",
            "com.facebook.login",
            "com.facebook.share",
        ],
        resource_patterns=[
            "facebook_*.xml",
        ],
        class_patterns=[
            "Lcom/facebook/",
        ],
    ),
    "crashlytics": SDKSignature(
        sdk_name="crashlytics",
        package_patterns=[
            "com.crashlytics",
            "io.fabric.sdk.android",
            "com.google.firebase.crashlytics",
        ],
        class_patterns=[
            "Lcom/crashlytics/",
            "Lio/fabric/sdk/",
        ],
    ),
    "google_analytics": SDKSignature(
        sdk_name="google_analytics",
        package_patterns=[
            "com.google.android.gms.analytics",
            "com.google.firebase.analytics",
        ],
        class_patterns=[
            "Lcom/google/android/gms/analytics/",
        ],
    ),
    "okhttp": SDKSignature(
        sdk_name="okhttp",
        package_patterns=[
            "okhttp3",
            "com.squareup.okhttp3",
        ],
        class_patterns=[
            "Lokhttp3/OkHttpClient",
        ],
        version_extraction=r"okhttp/(\d+\.\d+\.\d+)",
    ),
    "retrofit": SDKSignature(
        sdk_name="retrofit",
        package_patterns=[
            "retrofit2",
            "com.squareup.retrofit2",
        ],
        class_patterns=[
            "Lretrofit2/Retrofit",
        ],
    ),
    "gson": SDKSignature(
        sdk_name="gson",
        package_patterns=[
            "com.google.gson",
        ],
        class_patterns=[
            "Lcom/google/gson/Gson",
        ],
    ),
    "jackson": SDKSignature(
        sdk_name="jackson",
        package_patterns=[
            "com.fasterxml.jackson",
        ],
        class_patterns=[
            "Lcom/fasterxml/jackson/",
        ],
    ),
    "glide": SDKSignature(
        sdk_name="glide",
        package_patterns=[
            "com.bumptech.glide",
        ],
        class_patterns=[
            "Lcom/bumptech/glide/Glide",
        ],
    ),
    "picasso": SDKSignature(
        sdk_name="picasso",
        package_patterns=[
            "com.squareup.picasso",
        ],
        class_patterns=[
            "Lcom/squareup/picasso/Picasso",
        ],
    ),
    "realm": SDKSignature(
        sdk_name="realm",
        package_patterns=[
            "io.realm",
        ],
        class_patterns=[
            "Lio/realm/Realm",
        ],
    ),
    "appsflyer": SDKSignature(
        sdk_name="appsflyer",
        package_patterns=[
            "com.appsflyer",
        ],
        class_patterns=[
            "Lcom/appsflyer/",
        ],
    ),
    "adjust": SDKSignature(
        sdk_name="adjust",
        package_patterns=[
            "com.adjust.sdk",
        ],
        class_patterns=[
            "Lcom/adjust/sdk/",
        ],
    ),
    "branch": SDKSignature(
        sdk_name="branch",
        package_patterns=[
            "io.branch",
        ],
        class_patterns=[
            "Lio/branch/",
        ],
    ),
    "aws_sdk": SDKSignature(
        sdk_name="aws_sdk",
        package_patterns=[
            "com.amazonaws",
            "software.amazon.awssdk",
        ],
        class_patterns=[
            "Lcom/amazonaws/",
        ],
    ),
}


# Framework signatures
FRAMEWORK_SIGNATURES: dict[str, dict] = {
    "flutter": {
        "indicators": ["libflutter.so", "flutter_assets", "io.flutter"],
        "version_patterns": [
            r"Flutter\s+(\d+\.\d+\.\d+)",
            r"engine_version:\s*(\d+\.\d+\.\d+)",
        ],
        "files": ["flutter_assets/AssetManifest.json", "libflutter.so"],
    },
    "react_native": {
        "indicators": ["libreactnative*.so", "index.android.bundle", "com.facebook.react"],
        "version_patterns": [
            r"react-native@(\d+\.\d+\.\d+)",
            r'"version":\s*"(\d+\.\d+\.\d+)"',
        ],
        "files": ["assets/index.android.bundle", "package.json"],
    },
    "cordova": {
        "indicators": ["cordova.js", "org.apache.cordova"],
        "version_patterns": [
            r"cordova@(\d+\.\d+\.\d+)",
            r'<preference name="CordovaVersion" value="(\d+\.\d+\.\d+)"',
        ],
        "files": ["assets/www/cordova.js", "config.xml"],
    },
    "xamarin": {
        "indicators": ["libmonodroid.so", "Xamarin", "mono.android"],
        "version_patterns": [
            r"Xamarin\.Forms\s+(\d+\.\d+\.\d+)",
        ],
        "files": ["assemblies/Xamarin.Forms.Core.dll"],
    },
    "unity": {
        "indicators": ["libunity.so", "UnityPlayer", "com.unity3d"],
        "version_patterns": [
            r"Unity\s+(\d+\.\d+\.\d+)",
        ],
        "files": ["libunity.so", "assets/bin/Data/"],
    },
}


class LibraryFingerprinter:
    """Fingerprints libraries in mobile applications."""

    def __init__(self):
        """Initialize fingerprinter with signatures."""
        self.native_signatures = NATIVE_LIB_SIGNATURES
        self.sdk_signatures = SDK_SIGNATURES
        self.framework_signatures = FRAMEWORK_SIGNATURES

    def fingerprint_all(
        self,
        extracted_path: Path,
        dex_classes: list[str] | None = None,
    ) -> list[DetectedLibrary]:
        """Fingerprint all libraries in the extracted app.

        Args:
            extracted_path: Path to extracted app contents
            dex_classes: Optional list of class names from DEX analysis

        Returns:
            List of detected libraries
        """
        libraries: list[DetectedLibrary] = []

        # Detect native libraries
        libraries.extend(self._fingerprint_native_libs(extracted_path))

        # Detect SDKs from class patterns
        if dex_classes:
            libraries.extend(self._fingerprint_sdks_from_classes(dex_classes))

        # Detect SDKs from resources
        libraries.extend(self._fingerprint_sdks_from_resources(extracted_path))

        # Detect frameworks
        libraries.extend(self._fingerprint_frameworks(extracted_path))

        # Deduplicate
        return self._deduplicate_libraries(libraries)

    def _fingerprint_native_libs(self, extracted_path: Path) -> list[DetectedLibrary]:
        """Fingerprint native .so libraries."""
        libraries: list[DetectedLibrary] = []

        # Find all .so files
        so_files = list(extracted_path.rglob("*.so"))

        for so_file in so_files:
            for lib_name, signature in self.native_signatures.items():
                # Check filename pattern
                if self._matches_file_pattern(so_file.name, signature.file_patterns):
                    # Try to extract version
                    version = self._extract_version_from_binary(so_file, signature)

                    # Check export symbols if no version found
                    if not version:
                        has_symbols = self._check_export_symbols(so_file, signature)
                        if not has_symbols:
                            continue

                    # Calculate hash for potential matching
                    file_hash = self._calculate_file_hash(so_file)

                    libraries.append(DetectedLibrary(
                        name=lib_name,
                        version=version,
                        source=LibrarySource.NATIVE,
                        detection_method=DetectionMethod.VERSION_STRING if version else DetectionMethod.EXPORT_SYMBOLS,
                        file_path=str(so_file.relative_to(extracted_path)),
                        confidence=0.9 if version else 0.7,
                        metadata={
                            "file_hash": file_hash,
                            "file_size": so_file.stat().st_size,
                        },
                    ))

        return libraries

    def _fingerprint_sdks_from_classes(self, dex_classes: list[str]) -> list[DetectedLibrary]:
        """Detect SDKs from DEX class names."""
        libraries: list[DetectedLibrary] = []
        detected_sdks: set[str] = set()

        for sdk_name, signature in self.sdk_signatures.items():
            for class_name in dex_classes:
                for pattern in signature.class_patterns:
                    if class_name.startswith(pattern) or pattern in class_name:
                        if sdk_name not in detected_sdks:
                            detected_sdks.add(sdk_name)

                            # Try to extract version from class patterns
                            version = None
                            if signature.version_extraction:
                                for cn in dex_classes:
                                    match = re.search(signature.version_extraction, cn)
                                    if match:
                                        version = match.group(1)
                                        break

                            libraries.append(DetectedLibrary(
                                name=sdk_name,
                                version=version,
                                source=LibrarySource.SDK,
                                detection_method=DetectionMethod.PACKAGE_NAME,
                                confidence=0.85,
                                metadata={
                                    "matched_pattern": pattern,
                                },
                            ))
                        break

        return libraries

    def _fingerprint_sdks_from_resources(self, extracted_path: Path) -> list[DetectedLibrary]:
        """Detect SDKs from resource files."""
        libraries: list[DetectedLibrary] = []

        for sdk_name, signature in self.sdk_signatures.items():
            for pattern in signature.resource_patterns:
                matches = list(extracted_path.rglob(pattern))
                if matches:
                    libraries.append(DetectedLibrary(
                        name=sdk_name,
                        version=None,
                        source=LibrarySource.SDK,
                        detection_method=DetectionMethod.RESOURCE_FILE,
                        file_path=str(matches[0].relative_to(extracted_path)),
                        confidence=0.8,
                        metadata={
                            "resource_pattern": pattern,
                        },
                    ))
                    break

        return libraries

    def _fingerprint_frameworks(self, extracted_path: Path) -> list[DetectedLibrary]:
        """Detect mobile frameworks (Flutter, React Native, etc.)."""
        libraries: list[DetectedLibrary] = []

        for framework_name, signature in self.framework_signatures.items():
            # Check for indicator files
            indicators_found = 0
            for indicator in signature["indicators"]:
                if list(extracted_path.rglob(f"*{indicator}*")):
                    indicators_found += 1

            if indicators_found > 0:
                # Try to extract version
                version = self._extract_framework_version(extracted_path, signature)

                libraries.append(DetectedLibrary(
                    name=framework_name,
                    version=version,
                    source=LibrarySource.FRAMEWORK,
                    detection_method=DetectionMethod.SIGNATURE,
                    confidence=0.9 if indicators_found >= 2 else 0.7,
                    metadata={
                        "indicators_found": indicators_found,
                    },
                ))

        return libraries

    def _matches_file_pattern(self, filename: str, patterns: list[str]) -> bool:
        """Check if filename matches any pattern."""
        import fnmatch
        for pattern in patterns:
            if fnmatch.fnmatch(filename, pattern):
                return True
        return False

    def _extract_version_from_binary(
        self,
        so_file: Path,
        signature: NativeLibSignature,
    ) -> str | None:
        """Extract version string from binary file."""
        try:
            # Read binary and search for version strings
            content = so_file.read_bytes()

            # Try to find printable strings
            strings = self._extract_strings_from_binary(content)

            for pattern in signature.version_patterns:
                for s in strings:
                    match = re.search(pattern, s)
                    if match:
                        return match.group(1)

        except Exception as e:
            logger.debug(f"Error extracting version from {so_file}: {e}")

        return None

    def _extract_strings_from_binary(self, content: bytes, min_length: int = 4) -> list[str]:
        """Extract printable strings from binary content."""
        strings = []
        current = []

        for byte in content:
            if 32 <= byte < 127:  # Printable ASCII
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append("".join(current))
                current = []

        if len(current) >= min_length:
            strings.append("".join(current))

        return strings

    def _check_export_symbols(
        self,
        so_file: Path,
        signature: NativeLibSignature,
    ) -> bool:
        """Check if library exports expected symbols."""
        try:
            content = so_file.read_bytes()
            strings = self._extract_strings_from_binary(content)

            found_symbols = 0
            for symbol in signature.export_symbols:
                if symbol in strings:
                    found_symbols += 1

            # Require at least half the symbols to match
            return found_symbols >= len(signature.export_symbols) / 2

        except Exception as e:
            logger.debug(f"Error checking symbols in {so_file}: {e}")
            return False

    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    def _extract_framework_version(
        self,
        extracted_path: Path,
        signature: dict,
    ) -> str | None:
        """Extract framework version from files."""
        for file_pattern in signature.get("files", []):
            for file_path in extracted_path.rglob(file_pattern):
                try:
                    content = file_path.read_text(errors="ignore")
                    for pattern in signature.get("version_patterns", []):
                        match = re.search(pattern, content)
                        if match:
                            return match.group(1)
                except Exception:
                    pass

        return None

    def _deduplicate_libraries(
        self,
        libraries: list[DetectedLibrary],
    ) -> list[DetectedLibrary]:
        """Remove duplicate library detections, keeping highest confidence."""
        seen: dict[str, DetectedLibrary] = {}

        for lib in libraries:
            key = f"{lib.name}:{lib.version or 'unknown'}"
            if key not in seen or lib.confidence > seen[key].confidence:
                seen[key] = lib

        return list(seen.values())
