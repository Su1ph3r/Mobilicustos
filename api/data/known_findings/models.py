"""Pydantic models for known finding definitions."""

from decimal import Decimal
from typing import Any

from pydantic import BaseModel, Field, field_validator


class PocCommand(BaseModel):
    """A proof-of-concept command for verifying a finding."""

    type: str = Field(..., description="Command type: adb, bash, drozer, frida, etc.")
    command: str = Field(..., description="The command to execute")
    description: str = Field(..., description="What this command does")


class RemediationResource(BaseModel):
    """External resource for remediation guidance."""

    title: str = Field(..., description="Resource title")
    url: str = Field(..., description="Resource URL")
    type: str = Field(
        default="documentation",
        description="Resource type: documentation, tutorial, tool, etc.",
    )


class RemediationCode(BaseModel):
    """Code snippet for remediation in various languages."""

    language: str = Field(..., description="Programming language or format")
    code: str = Field(..., description="The remediation code snippet")
    description: str | None = Field(None, description="Optional explanation")


class DetectionPattern(BaseModel):
    """Pattern for automatic detection of this finding."""

    type: str = Field(
        ...,
        description="Pattern type: regex, string, xpath, method_call, etc.",
    )
    pattern: str = Field(..., description="The detection pattern")
    file_types: list[str] = Field(
        default_factory=list,
        description="File types this pattern applies to",
    )
    context: str | None = Field(
        None,
        description="Additional context for pattern matching",
    )


class KnownFinding(BaseModel):
    """A pre-defined finding definition with complete metadata.

    This model represents a finding template that can be instantiated
    for specific occurrences in analyzed apps.
    """

    # Identity
    id: str = Field(
        ...,
        description="Unique identifier for this finding definition",
        pattern=r"^[a-z][a-z0-9_]*$",
    )
    platform: str = Field(
        ...,
        description="Target platform: android, ios, or cross_platform",
    )

    # Core content
    title: str = Field(..., description="Finding title")
    category: str = Field(..., description="Finding category")
    severity: str = Field(
        ...,
        description="Severity level: critical, high, medium, low, info",
    )
    description: str = Field(..., description="Detailed description of the issue")
    impact: str = Field(..., description="Impact description")
    remediation: str = Field(..., description="Remediation guidance")

    # Risk scoring
    cvss_score: Decimal | None = Field(None, description="CVSS v3.1 score (0.0-10.0)")
    cvss_vector: str | None = Field(None, description="CVSS v3.1 vector string")
    cwe_id: str | None = Field(None, description="CWE identifier (e.g., CWE-489)")
    cwe_name: str | None = Field(None, description="CWE name")

    # OWASP mapping
    owasp_masvs_category: str | None = Field(None, description="MASVS category")
    owasp_masvs_control: str | None = Field(None, description="MASVS control ID")
    owasp_mastg_test: str | None = Field(None, description="MASTG test ID")

    # Detection patterns
    detection_patterns: list[DetectionPattern] = Field(
        default_factory=list,
        description="Patterns for automatic detection",
    )

    # PoC evidence
    poc_commands: list[PocCommand] = Field(
        default_factory=list,
        description="PoC commands for verification",
    )
    poc_frida_script: str | None = Field(None, description="Frida script for dynamic PoC")
    poc_template: str | None = Field(
        None,
        description="Template for dynamic PoC generation with placeholders",
    )

    # Remediation details
    remediation_code: list[RemediationCode] = Field(
        default_factory=list,
        description="Code snippets for remediation",
    )
    remediation_resources: list[RemediationResource] = Field(
        default_factory=list,
        description="External resources for remediation",
    )

    # Attack path integration
    attack_path_entry_point: bool = Field(
        default=False,
        description="Can this finding serve as an attack entry point?",
    )
    attack_path_enables: list[str] = Field(
        default_factory=list,
        description="Capabilities this finding enables in attack paths",
    )
    mitre_mobile_techniques: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK Mobile technique IDs",
    )

    # Additional metadata
    tags: list[str] = Field(default_factory=list, description="Tags for categorization")
    references: list[str] = Field(default_factory=list, description="Reference URLs")

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        """Validate severity is one of allowed values."""
        allowed = {"critical", "high", "medium", "low", "info"}
        if v.lower() not in allowed:
            raise ValueError(f"severity must be one of {allowed}")
        return v.lower()

    @field_validator("platform")
    @classmethod
    def validate_platform(cls, v: str) -> str:
        """Validate platform is one of allowed values."""
        allowed = {"android", "ios", "cross_platform"}
        if v.lower() not in allowed:
            raise ValueError(f"platform must be one of {allowed}")
        return v.lower()

    @field_validator("cvss_score")
    @classmethod
    def validate_cvss_score(cls, v: Decimal | None) -> Decimal | None:
        """Validate CVSS score is in range."""
        if v is not None and (v < 0 or v > 10):
            raise ValueError("cvss_score must be between 0.0 and 10.0")
        return v

    def get_poc_commands_for_app(
        self,
        package_name: str,
        component_name: str | None = None,
        file_path: str | None = None,
    ) -> list[dict[str, Any]]:
        """Generate PoC commands with app-specific placeholders filled in.

        Args:
            package_name: The app's package name
            component_name: Optional component name (activity, service, etc.)
            file_path: Optional file path for the finding

        Returns:
            List of PoC command dicts with placeholders replaced
        """
        commands = []
        for cmd in self.poc_commands:
            command_str = cmd.command
            # Replace placeholders
            command_str = command_str.replace("{package_name}", package_name)
            if component_name:
                command_str = command_str.replace("{component_name}", component_name)
            if file_path:
                command_str = command_str.replace("{file_path}", file_path)

            commands.append({
                "type": cmd.type,
                "command": command_str,
                "description": cmd.description,
            })

        return commands

    def get_frida_script_for_app(self, package_name: str) -> str | None:
        """Generate Frida script with app-specific placeholders filled in."""
        if not self.poc_frida_script:
            return None
        return self.poc_frida_script.replace("{package_name}", package_name)

    def get_remediation_code_dict(self) -> dict[str, str]:
        """Convert remediation code list to dict format for Finding model."""
        return {rc.language: rc.code for rc in self.remediation_code}

    def get_remediation_resources_list(self) -> list[dict[str, str]]:
        """Convert remediation resources to list of dicts for Finding model."""
        return [
            {"title": r.title, "url": r.url, "type": r.type}
            for r in self.remediation_resources
        ]


class KnownFindingsFile(BaseModel):
    """Schema for a YAML file containing finding definitions."""

    findings: list[KnownFinding] = Field(..., description="List of finding definitions")
