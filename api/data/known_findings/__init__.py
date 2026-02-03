"""Known findings database module.

This module provides a centralized registry of pre-defined finding definitions
with rich metadata for consistency and reuse across analyzers.
"""

from api.data.known_findings.models import (
    DetectionPattern,
    KnownFinding,
    PocCommand,
    RemediationCode,
    RemediationResource,
)
from api.data.known_findings.registry import FindingRegistry, get_finding_registry

__all__ = [
    "DetectionPattern",
    "KnownFinding",
    "PocCommand",
    "RemediationCode",
    "RemediationResource",
    "FindingRegistry",
    "get_finding_registry",
]
