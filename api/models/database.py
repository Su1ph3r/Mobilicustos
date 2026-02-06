"""SQLAlchemy ORM database models for the Mobilicustos platform.

Defines all database tables and relationships using SQLAlchemy 2.0
declarative mapping with ``Mapped`` type annotations. All models inherit
from ``Base`` which configures JSONB mapping for dict and list types.

Core entity relationships:
    MobileApp --1:N--> Scan --1:N--> Finding
    MobileApp --1:N--> Secret
    MobileApp --1:N--> MLModel
    Device (standalone)
    FridaScript (standalone, linked via BypassResult)
    BypassResult (linked to MobileApp + Device)
"""

from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all ORM models.

    Configures automatic JSONB column mapping for ``dict[str, Any]`` and
    ``list[Any]`` type annotations, so Python dicts and lists are stored
    as PostgreSQL JSONB columns without explicit column type declarations.
    """

    type_annotation_map = {
        dict[str, Any]: JSONB,
        list[Any]: JSONB,
    }


class MobileApp(Base):
    """Represents an uploaded mobile application (APK or IPA).

    Stores application metadata, framework detection results, signing info,
    SDK version targets, and analysis status. Serves as the root entity for
    scans, findings, secrets, and ML model associations.
    """

    __tablename__ = "mobile_apps"

    app_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    package_name: Mapped[str] = mapped_column(String(512), nullable=False)
    app_name: Mapped[str | None] = mapped_column(String(512))
    version_name: Mapped[str | None] = mapped_column(String(64))
    version_code: Mapped[int | None] = mapped_column(Integer)
    platform: Mapped[str] = mapped_column(String(16), nullable=False)

    # File Info
    file_path: Mapped[str | None] = mapped_column(String(1024))
    file_hash_sha256: Mapped[str | None] = mapped_column(String(64))
    file_size_bytes: Mapped[int | None] = mapped_column(Integer)

    # Framework Detection
    framework: Mapped[str | None] = mapped_column(String(64))
    framework_version: Mapped[str | None] = mapped_column(String(64))
    framework_details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    # Signing Info
    signing_info: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    # SDK Versions
    min_sdk_version: Mapped[int | None] = mapped_column(Integer)
    target_sdk_version: Mapped[int | None] = mapped_column(Integer)
    min_ios_version: Mapped[str | None] = mapped_column(String(16))

    # Status
    status: Mapped[str] = mapped_column(String(32), default="pending")
    upload_date: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    last_analyzed: Mapped[datetime | None] = mapped_column(DateTime)

    # Additional Metadata
    app_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    # Relationships
    scans: Mapped[list["Scan"]] = relationship(back_populates="app", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="app", cascade="all, delete-orphan"
    )
    ml_models: Mapped[list["MLModel"]] = relationship(
        back_populates="app", cascade="all, delete-orphan"
    )
    secrets: Mapped[list["Secret"]] = relationship(
        back_populates="app", cascade="all, delete-orphan"
    )


class Scan(Base):
    """Represents a security scan execution against a mobile application.

    Tracks scan configuration (type, enabled analyzers), execution state
    (status, progress, current analyzer), results summary (findings count
    by severity), timing, and any errors encountered during analysis.
    """

    __tablename__ = "scans"

    scan_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    app_id: Mapped[str] = mapped_column(
        String(256), ForeignKey("mobile_apps.app_id", ondelete="CASCADE")
    )

    # Scan Configuration
    scan_type: Mapped[str] = mapped_column(String(32), nullable=False)
    analyzers_enabled: Mapped[list[Any]] = mapped_column(JSONB, default=list)

    # Status
    status: Mapped[str] = mapped_column(String(32), default="pending")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    current_analyzer: Mapped[str | None] = mapped_column(String(128))

    # Results Summary
    findings_count: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    )

    # Timing
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    # Error Tracking
    error_message: Mapped[str | None] = mapped_column(Text)
    analyzer_errors: Mapped[list[Any]] = mapped_column(JSONB, default=list)

    # Relationships
    app: Mapped["MobileApp"] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Finding(Base):
    """Represents a security finding discovered during analysis.

    Contains the full finding lifecycle: classification (severity, category,
    CWE, OWASP mapping), location (file path, line number, code snippet),
    proof-of-concept evidence (commands, Frida scripts, screenshots), and
    remediation guidance (commands, code examples, resource links).

    Finding deduplication uses ``canonical_id`` -- a deterministic hash of
    the finding's key attributes plus the scan ID prefix to prevent
    collisions across scans while merging identical findings within a scan.
    """

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)
    scan_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.scan_id", ondelete="CASCADE")
    )
    app_id: Mapped[str | None] = mapped_column(
        String(256), ForeignKey("mobile_apps.app_id", ondelete="CASCADE")
    )

    # Source
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    platform: Mapped[str | None] = mapped_column(String(16))

    # Classification
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="open")
    category: Mapped[str | None] = mapped_column(String(128))

    # Core Content
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    impact: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)

    # Location
    resource_type: Mapped[str | None] = mapped_column(String(128))
    file_path: Mapped[str | None] = mapped_column(String(1024))
    line_number: Mapped[int | None] = mapped_column(Integer)
    code_snippet: Mapped[str | None] = mapped_column(Text)

    # PoC Evidence
    poc_evidence: Mapped[str | None] = mapped_column(Text)
    poc_verification: Mapped[str | None] = mapped_column(Text)
    poc_commands: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    poc_frida_script: Mapped[str | None] = mapped_column(Text)
    poc_screenshot_path: Mapped[str | None] = mapped_column(Text)

    # Remediation Details
    remediation_commands: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    remediation_code: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    remediation_resources: Mapped[list[Any]] = mapped_column(JSONB, default=list)

    # Risk Scoring
    risk_score: Mapped[Decimal | None] = mapped_column(Numeric(4, 2))
    cvss_score: Mapped[Decimal | None] = mapped_column(Numeric(3, 1))
    cvss_vector: Mapped[str | None] = mapped_column(String(128))
    cwe_id: Mapped[str | None] = mapped_column(String(32))
    cwe_name: Mapped[str | None] = mapped_column(String(256))

    # OWASP Mapping
    owasp_masvs_category: Mapped[str | None] = mapped_column(String(64))
    owasp_masvs_control: Mapped[str | None] = mapped_column(String(64))
    owasp_mastg_test: Mapped[str | None] = mapped_column(String(128))

    # Deduplication
    canonical_id: Mapped[str | None] = mapped_column(String(256))
    tool_sources: Mapped[list[Any]] = mapped_column(JSONB, default=list)

    # Timestamps
    first_seen: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    # Relationships
    app: Mapped["MobileApp"] = relationship(back_populates="findings")
    scan: Mapped["Scan"] = relationship(back_populates="findings")


class AttackPath(Base):
    """Represents a chained attack path linking multiple findings.

    Models multi-step exploitation scenarios where individual findings
    combine to create higher-impact attack vectors. Synchronized with
    Neo4j for graph-based visualization and traversal.
    """

    __tablename__ = "attack_paths"

    path_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    app_id: Mapped[str | None] = mapped_column(
        String(256), ForeignKey("mobile_apps.app_id", ondelete="CASCADE")
    )
    scan_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.scan_id", ondelete="CASCADE")
    )

    # Path Definition
    path_name: Mapped[str] = mapped_column(String(256), nullable=False)
    path_description: Mapped[str | None] = mapped_column(Text)
    attack_vector: Mapped[str | None] = mapped_column(Text)

    # Chain of findings
    finding_chain: Mapped[list[Any]] = mapped_column(JSONB, nullable=False)

    # Risk Assessment
    combined_risk_score: Mapped[Decimal | None] = mapped_column(Numeric(4, 2))
    exploitability: Mapped[str | None] = mapped_column(String(16))

    # Neo4j Reference
    neo4j_path_id: Mapped[str | None] = mapped_column(String(256))

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class MLModel(Base):
    """Represents a machine learning model extracted from an application.

    Stores metadata about ML models found in app binaries (TFLite,
    CoreML, ONNX, etc.), including tensor shapes, operations, labels,
    and security-relevant findings like PII exposure or adversarial
    susceptibility.
    """

    __tablename__ = "ml_models"

    model_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    app_id: Mapped[str | None] = mapped_column(
        String(256), ForeignKey("mobile_apps.app_id", ondelete="CASCADE")
    )
    scan_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.scan_id", ondelete="CASCADE")
    )

    # Model Info
    model_name: Mapped[str | None] = mapped_column(String(256))
    model_format: Mapped[str] = mapped_column(String(32), nullable=False)
    file_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    file_size_bytes: Mapped[int | None] = mapped_column(Integer)
    file_hash: Mapped[str | None] = mapped_column(String(64))

    # Analysis Results
    input_tensors: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    output_tensors: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    operations: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    labels: Mapped[list[Any]] = mapped_column(JSONB, default=list)

    # Security Analysis
    vulnerabilities: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    adversarial_risk: Mapped[str | None] = mapped_column(String(16))
    model_stealing_risk: Mapped[str | None] = mapped_column(String(16))

    # Metadata
    extracted_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    analysis_status: Mapped[str] = mapped_column(String(32), default="pending")

    # Relationships
    app: Mapped["MobileApp"] = relationship(back_populates="ml_models")


class Secret(Base):
    """Represents a hardcoded secret or credential detected in an application.

    Stores the redacted value, hash for deduplication, provider information,
    file location, and optional validation status (whether the secret is
    still active/valid).
    """

    __tablename__ = "secrets"

    secret_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    app_id: Mapped[str | None] = mapped_column(
        String(256), ForeignKey("mobile_apps.app_id", ondelete="CASCADE")
    )
    scan_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.scan_id", ondelete="CASCADE")
    )
    finding_id: Mapped[str | None] = mapped_column(
        String(256), ForeignKey("findings.finding_id", ondelete="SET NULL")
    )

    # Secret Info
    secret_type: Mapped[str] = mapped_column(String(64), nullable=False)
    provider: Mapped[str | None] = mapped_column(String(128))

    # Location
    file_path: Mapped[str | None] = mapped_column(String(1024))
    line_number: Mapped[int | None] = mapped_column(Integer)
    context: Mapped[str | None] = mapped_column(Text)

    # Secret Value
    secret_value_redacted: Mapped[str | None] = mapped_column(String(256))
    secret_hash: Mapped[str | None] = mapped_column(String(64))

    # Validation
    is_valid: Mapped[bool | None] = mapped_column(Boolean)
    validation_error: Mapped[str | None] = mapped_column(Text)
    last_validated: Mapped[datetime | None] = mapped_column(DateTime)

    # Risk
    exposure_risk: Mapped[str | None] = mapped_column(String(16))

    detected_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    # Relationships
    app: Mapped["MobileApp"] = relationship(back_populates="secrets")


class Device(Base):
    """Represents a registered testing device (physical, emulator, or virtual).

    Stores device identity, hardware info, connection details, root/jailbreak
    status, and Frida server state. Supports Android (ADB), iOS
    (libimobiledevice), and Corellium virtual devices.
    """

    __tablename__ = "devices"

    device_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    device_type: Mapped[str] = mapped_column(String(32), nullable=False)
    platform: Mapped[str] = mapped_column(String(16), nullable=False)

    # Device Info
    device_name: Mapped[str | None] = mapped_column(String(256))
    model: Mapped[str | None] = mapped_column(String(128))
    os_version: Mapped[str | None] = mapped_column(String(32))

    # Connection
    connection_type: Mapped[str | None] = mapped_column(String(32))
    connection_string: Mapped[str | None] = mapped_column(String(512))

    # Corellium Specific
    corellium_instance_id: Mapped[str | None] = mapped_column(String(128))
    corellium_project_id: Mapped[str | None] = mapped_column(String(128))

    # Status
    status: Mapped[str] = mapped_column(String(32), default="disconnected")
    last_seen: Mapped[datetime | None] = mapped_column(DateTime)

    # Capabilities
    is_rooted: Mapped[bool] = mapped_column(Boolean, default=False)
    is_jailbroken: Mapped[bool] = mapped_column(Boolean, default=False)
    frida_server_version: Mapped[str | None] = mapped_column(String(32))
    frida_server_status: Mapped[str | None] = mapped_column(String(32))

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class FridaScript(Base):
    """Represents a Frida JavaScript script in the script library.

    Scripts are categorized (bypass, hook, recon) with subcategories for
    specific protection types. Supports platform targeting, framework
    filtering, and builtin vs. user-uploaded distinction. Used by the
    bypass orchestrator for automated protection circumvention.
    """

    __tablename__ = "frida_scripts"

    script_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )

    # Script Info
    script_name: Mapped[str] = mapped_column(String(256), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    subcategory: Mapped[str | None] = mapped_column(String(64))

    # Content
    script_content: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    # Compatibility
    platforms: Mapped[list[Any]] = mapped_column(JSONB, default=lambda: ["android", "ios"])
    min_frida_version: Mapped[str | None] = mapped_column(String(32))

    # Targeting
    target_frameworks: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    target_libraries: Mapped[list[Any]] = mapped_column(JSONB, default=list)

    # Metadata
    author: Mapped[str | None] = mapped_column(String(128))
    source_url: Mapped[str | None] = mapped_column(String(512))
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class BypassResult(Base):
    """Records the result of an anti-detection bypass attempt.

    Tracks which protection was detected, what method was used for
    detection, which Frida script was tried, whether the bypass
    succeeded, and captures proof-of-concept evidence.
    """

    __tablename__ = "bypass_results"

    result_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    app_id: Mapped[str | None] = mapped_column(
        String(256), ForeignKey("mobile_apps.app_id", ondelete="CASCADE")
    )
    device_id: Mapped[str | None] = mapped_column(
        String(128), ForeignKey("devices.device_id", ondelete="SET NULL")
    )

    # Detection Info
    detection_type: Mapped[str] = mapped_column(String(64), nullable=False)
    detection_method: Mapped[str | None] = mapped_column(String(128))
    detection_library: Mapped[str | None] = mapped_column(String(128))

    # Detection Details
    detection_signature: Mapped[str | None] = mapped_column(Text)
    detection_location: Mapped[str | None] = mapped_column(String(512))

    # Bypass Info
    bypass_script_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("frida_scripts.script_id", ondelete="SET NULL")
    )
    bypass_status: Mapped[str | None] = mapped_column(String(32))
    bypass_notes: Mapped[str | None] = mapped_column(Text)

    # Evidence
    poc_evidence: Mapped[str | None] = mapped_column(Text)
    screenshot_path: Mapped[str | None] = mapped_column(Text)

    attempted_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class DrozerSession(Base):
    """Represents a Drozer session for dynamic Android component testing.

    Tracks the Drozer agent connection, execution state, and associated
    module execution results for IPC, content provider, and component
    security testing.
    """

    __tablename__ = "drozer_sessions"

    session_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    device_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("devices.device_id", ondelete="CASCADE")
    )
    app_id: Mapped[str | None] = mapped_column(
        String(256), ForeignKey("mobile_apps.app_id", ondelete="SET NULL")
    )

    # Session Info
    package_name: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="starting")  # starting, active, stopped, error

    # Drozer Connection
    drozer_port: Mapped[int | None] = mapped_column(Integer)
    agent_pid: Mapped[int | None] = mapped_column(Integer)

    # Timing
    started_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)

    # Error Tracking
    error_message: Mapped[str | None] = mapped_column(Text)

    # Relationships
    results: Mapped[list["DrozerResult"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )


class DrozerResult(Base):
    """Stores the output from a single Drozer module execution.

    Contains the module name, arguments, raw output text, structured
    result data, and optional link to a Finding if the result was
    converted into a security finding.
    """

    __tablename__ = "drozer_results"

    result_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    session_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("drozer_sessions.session_id", ondelete="CASCADE")
    )

    # Module Info
    module_name: Mapped[str] = mapped_column(String(128), nullable=False)
    module_args: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    # Result
    result_type: Mapped[str] = mapped_column(String(32), nullable=False)  # finding, info, error
    result_data: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    raw_output: Mapped[str | None] = mapped_column(Text)

    # Finding Conversion
    finding_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("findings.finding_id", ondelete="SET NULL")
    )

    executed_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    # Relationships
    session: Mapped["DrozerSession"] = relationship(back_populates="results")


class ObjectionSession(Base):
    """Represents an Objection session for runtime security exploration.

    Objection wraps Frida to provide high-level commands for SSL pinning
    bypass, filesystem access, keychain dumping, and other runtime
    security tasks. Tracks session state and command history.
    """

    __tablename__ = "objection_sessions"

    session_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    device_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("devices.device_id", ondelete="CASCADE")
    )
    app_id: Mapped[str | None] = mapped_column(
        String(256), ForeignKey("mobile_apps.app_id", ondelete="SET NULL")
    )

    # Session Info
    package_name: Mapped[str] = mapped_column(String(512), nullable=False)
    platform: Mapped[str] = mapped_column(String(16), nullable=False)  # android, ios
    status: Mapped[str] = mapped_column(String(32), default="starting")

    # Frida Connection
    frida_session_id: Mapped[str | None] = mapped_column(String(64))

    # Timing
    started_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)

    # Error Tracking
    error_message: Mapped[str | None] = mapped_column(Text)

    # Command History
    command_history: Mapped[list[Any]] = mapped_column(JSONB, default=list)


class CVECache(Base):
    """Cached CVE (Common Vulnerabilities and Exposures) information.

    Stores CVE details fetched from NVD/OSV databases to avoid repeated
    API calls. Includes severity scoring, affected product/version info,
    exploit availability, and cache expiration for TTL-based invalidation.
    """

    __tablename__ = "cve_cache"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)

    # CVE Details
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str | None] = mapped_column(String(16))
    cvss_v3_score: Mapped[Decimal | None] = mapped_column(Numeric(3, 1))
    cvss_v3_vector: Mapped[str | None] = mapped_column(String(128))

    # Weakness Classification
    cwe_ids: Mapped[list[Any]] = mapped_column(JSONB, default=list)

    # Affected Products
    affected_products: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    affected_versions: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    fixed_versions: Mapped[list[Any]] = mapped_column(JSONB, default=list)

    # References
    references: Mapped[list[Any]] = mapped_column(JSONB, default=list)

    # Exploit Information
    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False)

    # Dates
    published_date: Mapped[datetime | None] = mapped_column(DateTime)
    last_modified: Mapped[datetime | None] = mapped_column(DateTime)
    fetched_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    # Cache Control
    cache_expires_at: Mapped[datetime | None] = mapped_column(DateTime)


class LibraryFingerprint(Base):
    """Cached library fingerprint data for binary identification.

    Stores signatures (file hashes, export symbols, version strings) that
    identify specific library versions in native binaries. Used by the
    ``LibraryFingerprinter`` to match embedded libraries against known
    versions with CVE data.
    """

    __tablename__ = "library_fingerprints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Library Identification
    library_name: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    library_version: Mapped[str | None] = mapped_column(String(64))
    cpe_string: Mapped[str | None] = mapped_column(String(512))

    # Fingerprint Data
    file_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    export_symbols: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    version_strings: Mapped[list[Any]] = mapped_column(JSONB, default=list)

    # Metadata
    source_type: Mapped[str | None] = mapped_column(String(32))  # native, sdk, framework
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
