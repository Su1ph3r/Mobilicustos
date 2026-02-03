"""CPE matching and mapping for CVE lookups.

Maps detected libraries to CPE (Common Platform Enumeration) identifiers
for accurate NVD/CVE database queries.
"""

import logging
import re
from dataclasses import dataclass

from api.services.cve.models import DetectedLibrary, LibrarySource

logger = logging.getLogger(__name__)


@dataclass
class CPEMatch:
    """Result of CPE matching."""
    cpe_string: str
    vendor: str
    product: str
    version: str | None
    confidence: float


# Comprehensive library to CPE mapping
# Format: library_name -> (vendor, product)
LIBRARY_TO_CPE: dict[str, tuple[str, str]] = {
    # Native Libraries
    "openssl": ("openssl", "openssl"),
    "sqlite": ("sqlite", "sqlite"),
    "curl": ("haxx", "curl"),
    "ffmpeg": ("ffmpeg", "ffmpeg"),
    "zlib": ("zlib", "zlib"),
    "libjpeg": ("ijg", "libjpeg"),
    "libjpeg-turbo": ("libjpeg-turbo", "libjpeg-turbo"),
    "libpng": ("libpng", "libpng"),
    "boringssl": ("google", "boringssl"),
    "libxml2": ("xmlsoft", "libxml2"),
    "expat": ("libexpat_project", "libexpat"),
    "freetype": ("freetype", "freetype"),
    "harfbuzz": ("harfbuzz_project", "harfbuzz"),
    "icu": ("icu-project", "international_components_for_unicode"),
    "protobuf": ("google", "protobuf"),
    "grpc": ("grpc", "grpc"),
    "leveldb": ("google", "leveldb"),
    "snappy": ("google", "snappy"),

    # Android SDKs
    "firebase": ("google", "firebase"),
    "firebase_auth": ("google", "firebase_authentication"),
    "firebase_database": ("google", "firebase_realtime_database"),
    "firebase_messaging": ("google", "firebase_cloud_messaging"),
    "firebase_analytics": ("google", "firebase_analytics"),
    "crashlytics": ("google", "firebase_crashlytics"),

    # Networking
    "okhttp": ("squareup", "okhttp"),
    "retrofit": ("squareup", "retrofit"),
    "volley": ("google", "volley"),
    "apache_http": ("apache", "httpclient"),

    # JSON/Serialization
    "gson": ("google", "gson"),
    "jackson": ("fasterxml", "jackson-databind"),
    "jackson_core": ("fasterxml", "jackson-core"),
    "moshi": ("squareup", "moshi"),
    "fastjson": ("alibaba", "fastjson"),

    # Image Loading
    "glide": ("bumptech", "glide"),
    "picasso": ("squareup", "picasso"),
    "fresco": ("facebook", "fresco"),
    "coil": ("coil-kt", "coil"),

    # Database
    "realm": ("mongodb", "realm-java"),
    "room": ("google", "room"),
    "objectbox": ("objectbox", "objectbox"),
    "greendao": ("greenrobot", "greendao"),

    # Security/Crypto
    "bouncycastle": ("bouncycastle", "bouncy_castle_crypto_package"),
    "spongycastle": ("madgag", "spongycastle"),
    "conscrypt": ("google", "conscrypt"),

    # Analytics
    "google_analytics": ("google", "analytics"),
    "facebook_analytics": ("facebook", "analytics"),
    "mixpanel": ("mixpanel", "mixpanel-android"),
    "amplitude": ("amplitude", "amplitude-android"),
    "appsflyer": ("appsflyer", "appsflyer-android-sdk"),
    "adjust": ("adjust", "android_sdk"),
    "branch": ("branch", "branch-android-sdk"),

    # Social/Auth
    "facebook": ("facebook", "facebook-android-sdk"),
    "google_auth": ("google", "google-api-client"),
    "twitter": ("twitter", "twitter-kit-android"),

    # Cloud SDKs
    "aws_sdk": ("amazon", "aws-sdk-android"),
    "azure_sdk": ("microsoft", "azure-sdk-for-android"),
    "google_cloud": ("google", "google-cloud-java"),

    # Frameworks
    "flutter": ("google", "flutter"),
    "react_native": ("facebook", "react-native"),
    "cordova": ("apache", "cordova"),
    "xamarin": ("microsoft", "xamarin"),
    "unity": ("unity_technologies", "unity"),
    "electron": ("electronjs", "electron"),

    # JavaScript Libraries (React Native)
    "lodash": ("lodash", "lodash"),
    "moment": ("momentjs", "moment"),
    "axios": ("axios", "axios"),
    "underscore": ("underscorejs", "underscore"),

    # iOS Libraries
    "alamofire": ("alamofire", "alamofire"),
    "afnetworking": ("afnetworking", "afnetworking"),
    "sdwebimage": ("sdwebimage", "sdwebimage"),
    "kingfisher": ("onevcat", "kingfisher"),
    "snapkit": ("snapkit", "snapkit"),
    "realmswift": ("mongodb", "realm-swift"),
}


# Additional mappings for common variants
LIBRARY_ALIASES: dict[str, str] = {
    "org.bouncycastle": "bouncycastle",
    "com.squareup.okhttp3": "okhttp",
    "com.squareup.retrofit2": "retrofit",
    "com.google.firebase": "firebase",
    "com.google.code.gson": "gson",
    "com.fasterxml.jackson.core": "jackson_core",
    "com.fasterxml.jackson": "jackson",
    "com.bumptech.glide": "glide",
    "com.squareup.picasso": "picasso",
    "io.realm": "realm",
    "com.facebook.android": "facebook",
    "com.amazonaws": "aws_sdk",
    "org.apache.httpcomponents": "apache_http",
    "okhttp3": "okhttp",
    "retrofit2": "retrofit",
}


class CPEMatcher:
    """Maps libraries to CPE identifiers."""

    def __init__(self):
        """Initialize CPE matcher."""
        self.library_to_cpe = LIBRARY_TO_CPE
        self.aliases = LIBRARY_ALIASES

    def match(self, library: DetectedLibrary) -> CPEMatch | None:
        """Match a detected library to a CPE identifier.

        Args:
            library: Detected library

        Returns:
            CPEMatch if found, None otherwise
        """
        # Normalize library name
        lib_name = self._normalize_library_name(library.name)

        # Look up in mapping
        if lib_name in self.library_to_cpe:
            vendor, product = self.library_to_cpe[lib_name]
            return self._create_cpe_match(vendor, product, library.version, 0.95)

        # Try alias lookup
        for alias, normalized in self.aliases.items():
            if alias in library.name.lower():
                if normalized in self.library_to_cpe:
                    vendor, product = self.library_to_cpe[normalized]
                    return self._create_cpe_match(vendor, product, library.version, 0.9)

        # Try fuzzy matching on product name
        fuzzy_match = self._fuzzy_match_library(lib_name)
        if fuzzy_match:
            return fuzzy_match

        logger.debug(f"No CPE match found for library: {library.name}")
        return None

    def match_gradle_dependency(
        self,
        group_id: str,
        artifact_id: str,
        version: str | None,
    ) -> CPEMatch | None:
        """Match a Gradle/Maven dependency to CPE.

        Args:
            group_id: Maven group ID (e.g., "com.squareup.okhttp3")
            artifact_id: Maven artifact ID (e.g., "okhttp")
            version: Dependency version

        Returns:
            CPEMatch if found
        """
        # Try full coordinate match
        full_name = f"{group_id}:{artifact_id}"

        # Check aliases first
        for alias, normalized in self.aliases.items():
            if alias in group_id.lower() or alias in artifact_id.lower():
                if normalized in self.library_to_cpe:
                    vendor, product = self.library_to_cpe[normalized]
                    return self._create_cpe_match(vendor, product, version, 0.9)

        # Try artifact ID as library name
        lib_name = self._normalize_library_name(artifact_id)
        if lib_name in self.library_to_cpe:
            vendor, product = self.library_to_cpe[lib_name]
            return self._create_cpe_match(vendor, product, version, 0.85)

        return None

    def match_cocoapod(
        self,
        pod_name: str,
        version: str | None,
    ) -> CPEMatch | None:
        """Match a CocoaPods dependency to CPE.

        Args:
            pod_name: Pod name (e.g., "Alamofire")
            version: Pod version

        Returns:
            CPEMatch if found
        """
        lib_name = self._normalize_library_name(pod_name)

        if lib_name in self.library_to_cpe:
            vendor, product = self.library_to_cpe[lib_name]
            return self._create_cpe_match(vendor, product, version, 0.9)

        return None

    def match_npm_package(
        self,
        package_name: str,
        version: str | None,
    ) -> CPEMatch | None:
        """Match an npm package to CPE.

        Args:
            package_name: npm package name
            version: Package version

        Returns:
            CPEMatch if found
        """
        lib_name = self._normalize_library_name(package_name)

        if lib_name in self.library_to_cpe:
            vendor, product = self.library_to_cpe[lib_name]
            return self._create_cpe_match(vendor, product, version, 0.9)

        # Try with organization prefix removed
        if package_name.startswith("@"):
            simple_name = package_name.split("/")[-1]
            lib_name = self._normalize_library_name(simple_name)
            if lib_name in self.library_to_cpe:
                vendor, product = self.library_to_cpe[lib_name]
                return self._create_cpe_match(vendor, product, version, 0.85)

        return None

    def _normalize_library_name(self, name: str) -> str:
        """Normalize library name for lookup."""
        # Lowercase
        normalized = name.lower()

        # Remove common prefixes/suffixes
        normalized = re.sub(r"^lib", "", normalized)
        normalized = re.sub(r"-android$", "", normalized)
        normalized = re.sub(r"-ios$", "", normalized)
        normalized = re.sub(r"-java$", "", normalized)
        normalized = re.sub(r"-kotlin$", "", normalized)

        # Replace separators
        normalized = normalized.replace("-", "_")

        return normalized

    def _create_cpe_match(
        self,
        vendor: str,
        product: str,
        version: str | None,
        confidence: float,
    ) -> CPEMatch:
        """Create a CPE match result."""
        # Build CPE 2.3 string
        version_str = version if version else "*"
        cpe_string = f"cpe:2.3:a:{vendor}:{product}:{version_str}:*:*:*:*:*:*:*"

        return CPEMatch(
            cpe_string=cpe_string,
            vendor=vendor,
            product=product,
            version=version,
            confidence=confidence,
        )

    def _fuzzy_match_library(self, lib_name: str) -> CPEMatch | None:
        """Attempt fuzzy matching for unrecognized libraries."""
        # Try partial matches
        for known_lib, (vendor, product) in self.library_to_cpe.items():
            # Check if library name contains or is contained by known lib
            if known_lib in lib_name or lib_name in known_lib:
                return self._create_cpe_match(vendor, product, None, 0.6)

            # Check product name similarity
            if product.replace("_", "").replace("-", "") == lib_name.replace("_", ""):
                return self._create_cpe_match(vendor, product, None, 0.7)

        return None

    def get_cpe_for_nvd_query(self, cpe_match: CPEMatch) -> dict:
        """Convert CPE match to NVD API query parameters.

        Args:
            cpe_match: CPE match result

        Returns:
            Dictionary of NVD API parameters
        """
        params = {
            "cpeName": cpe_match.cpe_string,
        }

        # If version is specified, use version matching
        if cpe_match.version:
            params["versionStart"] = cpe_match.version
            params["versionStartType"] = "including"
            params["versionEnd"] = cpe_match.version
            params["versionEndType"] = "including"

        return params

    def build_cpe_search_string(
        self,
        vendor: str,
        product: str,
        version: str | None = None,
    ) -> str:
        """Build a CPE search string for NVD queries.

        Args:
            vendor: Vendor name
            product: Product name
            version: Optional version

        Returns:
            CPE 2.3 formatted string
        """
        version_str = version if version else "*"
        return f"cpe:2.3:a:{vendor}:{product}:{version_str}:*:*:*:*:*:*:*"
