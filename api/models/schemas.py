"""Pydantic schemas for API request/response validation."""

from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


# ============================================================================
# Mobile App Schemas
# ============================================================================


class MobileAppBase(BaseModel):
    """Base schema for mobile apps."""

    package_name: str
    app_name: str | None = None
    version_name: str | None = None
    version_code: int | None = None
    platform: str = Field(..., pattern="^(android|ios)$")


class MobileAppCreate(MobileAppBase):
    """Schema for creating a mobile app."""

    pass


class MobileAppResponse(MobileAppBase):
    """Schema for mobile app response."""

    app_id: str
    file_path: str | None = None
    file_hash_sha256: str | None = None
    file_size_bytes: int | None = None
    framework: str | None = None
    framework_version: str | None = None
    framework_details: dict[str, Any] = {}
    signing_info: dict[str, Any] = {}
    min_sdk_version: int | None = None
    target_sdk_version: int | None = None
    min_ios_version: str | None = None
    status: str = "pending"
    upload_date: datetime
    last_analyzed: datetime | None = None
    app_metadata: dict[str, Any] = {}

    class Config:
        from_attributes = True


# ============================================================================
# Scan Schemas
# ============================================================================


class ScanBase(BaseModel):
    """Base schema for scans."""

    scan_type: str = Field(..., pattern="^(static|dynamic|full)$")
    analyzers_enabled: list[str] = []


class ScanCreate(ScanBase):
    """Schema for creating a scan."""

    app_id: str


class ScanResponse(ScanBase):
    """Schema for scan response."""

    scan_id: UUID
    app_id: str
    status: str = "pending"
    progress: int = 0
    current_analyzer: str | None = None
    findings_count: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    error_message: str | None = None
    analyzer_errors: list[dict[str, Any]] = []

    class Config:
        from_attributes = True


# ============================================================================
# Finding Schemas
# ============================================================================


class FindingBase(BaseModel):
    """Base schema for findings."""

    tool: str
    platform: str | None = None
    severity: str = Field(..., pattern="^(critical|high|medium|low|info)$")
    category: str | None = None
    title: str
    description: str
    impact: str
    remediation: str


class FindingCreate(FindingBase):
    """Schema for creating a finding."""

    scan_id: UUID | None = None
    app_id: str | None = None

    # Location
    resource_type: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    code_snippet: str | None = None

    # PoC Evidence
    poc_evidence: str | None = None
    poc_verification: str | None = None
    poc_commands: list[str] = []
    poc_frida_script: str | None = None

    # Remediation Details
    remediation_commands: list[str] = []
    remediation_code: dict[str, Any] = {}
    remediation_resources: list[str] = []

    # Risk Scoring
    risk_score: Decimal | None = None
    cvss_score: Decimal | None = None
    cvss_vector: str | None = None
    cwe_id: str | None = None
    cwe_name: str | None = None

    # OWASP Mapping
    owasp_masvs_category: str | None = None
    owasp_masvs_control: str | None = None
    owasp_mastg_test: str | None = None


class FindingResponse(FindingBase):
    """Schema for finding response."""

    finding_id: str
    scan_id: UUID | None = None
    app_id: str | None = None
    status: str = "open"

    # Location
    resource_type: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    code_snippet: str | None = None

    # PoC Evidence
    poc_evidence: str | None = None
    poc_verification: str | None = None
    poc_commands: list[str] = []
    poc_frida_script: str | None = None
    poc_screenshot_path: str | None = None

    # Remediation Details
    remediation_commands: list[str] = []
    remediation_code: dict[str, Any] = {}
    remediation_resources: list[str] = []

    # Risk Scoring
    risk_score: Decimal | None = None
    cvss_score: Decimal | None = None
    cvss_vector: str | None = None
    cwe_id: str | None = None
    cwe_name: str | None = None

    # OWASP Mapping
    owasp_masvs_category: str | None = None
    owasp_masvs_control: str | None = None
    owasp_mastg_test: str | None = None

    # Deduplication
    canonical_id: str | None = None
    tool_sources: list[str] = []

    # Timestamps
    first_seen: datetime
    last_seen: datetime
    created_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# Device Schemas
# ============================================================================


class DeviceBase(BaseModel):
    """Base schema for devices."""

    device_type: str = Field(..., pattern="^(physical|emulator|genymotion|corellium)$")
    platform: str = Field(..., pattern="^(android|ios)$")
    device_name: str | None = None
    model: str | None = None
    os_version: str | None = None


class DeviceCreate(DeviceBase):
    """Schema for creating a device."""

    device_id: str
    connection_type: str | None = None
    connection_string: str | None = None
    corellium_instance_id: str | None = None
    corellium_project_id: str | None = None


class DeviceResponse(DeviceBase):
    """Schema for device response."""

    device_id: str
    connection_type: str | None = None
    connection_string: str | None = None
    corellium_instance_id: str | None = None
    corellium_project_id: str | None = None
    status: str = "disconnected"
    last_seen: datetime | None = None
    is_rooted: bool = False
    is_jailbroken: bool = False
    frida_server_version: str | None = None
    frida_server_status: str | None = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# Frida Script Schemas
# ============================================================================


class FridaScriptBase(BaseModel):
    """Base schema for Frida scripts."""

    script_name: str
    category: str
    subcategory: str | None = None
    script_content: str
    description: str | None = None


class FridaScriptCreate(FridaScriptBase):
    """Schema for creating a Frida script."""

    platforms: list[str] = ["android", "ios"]
    min_frida_version: str | None = None
    target_frameworks: list[str] = []
    target_libraries: list[str] = []
    author: str | None = None
    source_url: str | None = None


class FridaScriptResponse(FridaScriptBase):
    """Schema for Frida script response."""

    script_id: UUID
    platforms: list[str] = ["android", "ios"]
    min_frida_version: str | None = None
    target_frameworks: list[str] = []
    target_libraries: list[str] = []
    author: str | None = None
    source_url: str | None = None
    is_builtin: bool = False
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# ML Model Schemas
# ============================================================================


class MLModelResponse(BaseModel):
    """Schema for ML model response."""

    model_id: UUID
    app_id: str | None = None
    scan_id: UUID | None = None
    model_name: str | None = None
    model_format: str
    file_path: str
    file_size_bytes: int | None = None
    file_hash: str | None = None
    input_tensors: list[dict[str, Any]] = []
    output_tensors: list[dict[str, Any]] = []
    operations: list[str] = []
    labels: list[str] = []
    vulnerabilities: list[dict[str, Any]] = []
    adversarial_risk: str | None = None
    model_stealing_risk: str | None = None
    extracted_at: datetime
    analysis_status: str = "pending"

    class Config:
        from_attributes = True


# ============================================================================
# Secret Schemas
# ============================================================================


class SecretResponse(BaseModel):
    """Schema for secret response."""

    secret_id: UUID
    app_id: str | None = None
    scan_id: UUID | None = None
    finding_id: str | None = None
    secret_type: str
    provider: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    context: str | None = None
    secret_value_redacted: str | None = None
    is_valid: bool | None = None
    exposure_risk: str | None = None
    detected_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# Bypass Result Schemas
# ============================================================================


class BypassResultCreate(BaseModel):
    """Schema for creating a bypass result."""

    app_id: str
    device_id: str | None = None
    detection_type: str
    detection_method: str | None = None
    detection_library: str | None = None
    detection_signature: str | None = None
    detection_location: str | None = None
    bypass_script_id: UUID | None = None
    bypass_status: str | None = None
    bypass_notes: str | None = None
    poc_evidence: str | None = None


class BypassResultResponse(BaseModel):
    """Schema for bypass result response."""

    result_id: UUID
    app_id: str | None = None
    device_id: str | None = None
    detection_type: str
    detection_method: str | None = None
    detection_library: str | None = None
    detection_signature: str | None = None
    detection_location: str | None = None
    bypass_script_id: UUID | None = None
    bypass_status: str | None = None
    bypass_notes: str | None = None
    poc_evidence: str | None = None
    screenshot_path: str | None = None
    attempted_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# Attack Path Schemas
# ============================================================================


class AttackPathResponse(BaseModel):
    """Schema for attack path response."""

    path_id: UUID
    app_id: str | None = None
    scan_id: UUID | None = None
    path_name: str
    path_description: str | None = None
    attack_vector: str | None = None
    finding_chain: list[str]
    combined_risk_score: Decimal | None = None
    exploitability: str | None = None
    neo4j_path_id: str | None = None
    created_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# Dashboard/Summary Schemas
# ============================================================================


class DashboardSummary(BaseModel):
    """Schema for dashboard summary."""

    total_apps: int
    total_scans: int
    total_findings: int
    findings_by_severity: dict[str, int]
    findings_by_platform: dict[str, int]
    recent_scans: list[ScanResponse]
    top_vulnerable_apps: list[dict[str, Any]]


class FindingFilters(BaseModel):
    """Schema for finding filters."""

    severity: list[str] | None = None
    status: list[str] | None = None
    platform: list[str] | None = None
    category: list[str] | None = None
    tool: list[str] | None = None
    owasp_masvs_category: list[str] | None = None
    cwe_id: list[str] | None = None
    app_id: str | None = None
    scan_id: UUID | None = None
    search: str | None = None


class PaginatedResponse(BaseModel):
    """Schema for paginated responses."""

    items: list[Any]
    total: int
    page: int
    page_size: int
    pages: int
