"""YAML loader for known finding definitions with caching and validation."""

import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from api.data.known_findings.models import KnownFinding, KnownFindingsFile

logger = logging.getLogger(__name__)

# Base path for finding definitions
DEFINITIONS_PATH = Path(__file__).parent / "definitions"


class FindingLoadError(Exception):
    """Raised when a finding definition fails to load."""

    pass


def _load_yaml_file(file_path: Path) -> dict[str, Any]:
    """Load and parse a YAML file.

    Args:
        file_path: Path to the YAML file

    Returns:
        Parsed YAML content as dict

    Raises:
        FindingLoadError: If file cannot be read or parsed
    """
    try:
        with open(file_path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        raise FindingLoadError(f"Definition file not found: {file_path}")
    except yaml.YAMLError as e:
        raise FindingLoadError(f"Invalid YAML in {file_path}: {e}")


def _validate_findings(data: dict[str, Any], file_path: Path) -> list[KnownFinding]:
    """Validate finding definitions from parsed YAML.

    Args:
        data: Parsed YAML content
        file_path: Source file path (for error messages)

    Returns:
        List of validated KnownFinding objects

    Raises:
        FindingLoadError: If validation fails
    """
    try:
        findings_file = KnownFindingsFile(**data)
        return findings_file.findings
    except ValidationError as e:
        error_details = []
        for error in e.errors():
            loc = " -> ".join(str(l) for l in error["loc"])
            msg = error["msg"]
            error_details.append(f"  {loc}: {msg}")
        raise FindingLoadError(
            f"Validation error in {file_path}:\n" + "\n".join(error_details)
        )


@lru_cache(maxsize=128)
def load_definitions_file(file_path: str) -> tuple[KnownFinding, ...]:
    """Load finding definitions from a single YAML file (cached).

    Uses LRU cache to avoid re-reading files. The result is a tuple
    for hashability in the cache.

    Args:
        file_path: String path to the YAML file

    Returns:
        Tuple of KnownFinding objects
    """
    path = Path(file_path)
    logger.debug(f"Loading finding definitions from {path}")
    data = _load_yaml_file(path)
    findings = _validate_findings(data, path)
    logger.info(f"Loaded {len(findings)} findings from {path.name}")
    return tuple(findings)


def load_all_definitions(
    base_path: Path | None = None,
    platforms: list[str] | None = None,
) -> list[KnownFinding]:
    """Load all finding definitions from the definitions directory.

    Args:
        base_path: Base path for definitions (defaults to DEFINITIONS_PATH)
        platforms: List of platforms to load (defaults to all)

    Returns:
        List of all loaded KnownFinding objects
    """
    if base_path is None:
        base_path = DEFINITIONS_PATH

    if platforms is None:
        platforms = ["android", "ios", "cross_platform"]

    all_findings: list[KnownFinding] = []
    errors: list[str] = []

    for platform in platforms:
        platform_path = base_path / platform
        if not platform_path.exists():
            logger.warning(f"Platform directory not found: {platform_path}")
            continue

        for yaml_file in platform_path.glob("*.yaml"):
            try:
                findings = load_definitions_file(str(yaml_file))
                all_findings.extend(findings)
            except FindingLoadError as e:
                errors.append(str(e))
                logger.error(f"Failed to load {yaml_file}: {e}")

    if errors:
        logger.warning(f"Encountered {len(errors)} errors loading definitions")

    logger.info(f"Loaded {len(all_findings)} total finding definitions")
    return all_findings


def load_definitions_by_category(
    category: str,
    platform: str | None = None,
) -> list[KnownFinding]:
    """Load finding definitions filtered by category.

    Args:
        category: Category to filter by
        platform: Optional platform filter

    Returns:
        List of matching KnownFinding objects
    """
    all_findings = load_all_definitions(
        platforms=[platform] if platform else None
    )
    return [f for f in all_findings if f.category.lower() == category.lower()]


def reload_definitions() -> int:
    """Clear cache and reload all definitions.

    Returns:
        Number of definitions loaded
    """
    load_definitions_file.cache_clear()
    findings = load_all_definitions()
    return len(findings)


def get_definition_stats() -> dict[str, Any]:
    """Get statistics about loaded definitions.

    Returns:
        Dict with counts by platform, category, severity
    """
    findings = load_all_definitions()

    stats: dict[str, Any] = {
        "total": len(findings),
        "by_platform": {},
        "by_category": {},
        "by_severity": {},
        "with_cvss": 0,
        "with_cwe": 0,
        "with_owasp": 0,
        "with_frida": 0,
        "with_poc_commands": 0,
    }

    for f in findings:
        # By platform
        stats["by_platform"][f.platform] = stats["by_platform"].get(f.platform, 0) + 1

        # By category
        stats["by_category"][f.category] = stats["by_category"].get(f.category, 0) + 1

        # By severity
        stats["by_severity"][f.severity] = stats["by_severity"].get(f.severity, 0) + 1

        # Metadata presence
        if f.cvss_score:
            stats["with_cvss"] += 1
        if f.cwe_id:
            stats["with_cwe"] += 1
        if f.owasp_masvs_category:
            stats["with_owasp"] += 1
        if f.poc_frida_script:
            stats["with_frida"] += 1
        if f.poc_commands:
            stats["with_poc_commands"] += 1

    return stats
