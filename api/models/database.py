"""SQLAlchemy database models for Mobilicustos."""

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
    """Base class for all models."""

    type_annotation_map = {
        dict[str, Any]: JSONB,
        list[Any]: JSONB,
    }


class MobileApp(Base):
    """Mobile application model."""

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
    """Scan model."""

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
    """Finding model with rich content."""

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
    """Attack path model for Neo4j sync."""

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
    """ML model extracted from apps."""

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
    """Detected secrets/credentials."""

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
    """Device registry for physical/emulator/Corellium devices."""

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
    """Frida script library."""

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
    """Anti-detection bypass tracking."""

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
    """Drozer session for dynamic Android testing."""

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
    """Results from Drozer module execution."""

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
    """Objection session for runtime manipulation."""

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
