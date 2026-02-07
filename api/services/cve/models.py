"""Data models for CVE detection system."""

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from enum import Enum


class LibrarySource(str, Enum):
    """Source of library detection."""
    GRADLE = "gradle"
    COCOAPODS = "cocoapods"
    NPM = "npm"
    PUB = "pub"
    NATIVE = "native"
    SDK = "sdk"
    FRAMEWORK = "framework"
    BINARY = "binary"


class DetectionMethod(str, Enum):
    """Method used to detect library."""
    MANIFEST = "manifest"
    PACKAGE_NAME = "package_name"
    EXPORT_SYMBOLS = "export_symbols"
    VERSION_STRING = "version_string"
    HASH_MATCH = "hash_match"
    SIGNATURE = "signature"
    RESOURCE_FILE = "resource_file"


@dataclass
class DetectedLibrary:
    """Represents a detected library in the application."""
    name: str
    version: str | None
    source: LibrarySource
    detection_method: DetectionMethod
    file_path: str | None = None
    confidence: float = 0.9
    cpe: str | None = None
    metadata: dict = field(default_factory=dict)


@dataclass
class CVEInfo:
    """Information about a CVE."""
    cve_id: str
    description: str
    severity: str
    cvss_v3_score: Decimal | None = None
    cvss_v3_vector: str | None = None
    cwe_ids: list[str] = field(default_factory=list)
    affected_versions: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    published_date: datetime | None = None
    last_modified: datetime | None = None
    exploit_available: bool = False
    epss_score: Decimal | None = None        # Exploit probability (0.0-1.0)
    epss_percentile: Decimal | None = None   # Percentile rank (0.0-1.0)


@dataclass
class LibraryVulnerability:
    """Combines library detection with CVE information."""
    library: DetectedLibrary
    cve: CVEInfo
    is_vulnerable: bool = True
    fixed_version: str | None = None


@dataclass
class NativeLibSignature:
    """Signature for identifying native libraries."""
    library_name: str
    export_symbols: list[str] = field(default_factory=list)
    version_patterns: list[str] = field(default_factory=list)
    file_patterns: list[str] = field(default_factory=list)
    hash_signatures: dict[str, str] = field(default_factory=dict)  # version -> hash


@dataclass
class SDKSignature:
    """Signature for identifying SDKs."""
    sdk_name: str
    package_patterns: list[str] = field(default_factory=list)
    resource_patterns: list[str] = field(default_factory=list)
    class_patterns: list[str] = field(default_factory=list)
    version_extraction: str | None = None
