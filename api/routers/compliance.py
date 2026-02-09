"""Compliance router for OWASP MASVS/MASTG."""

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.models.database import Finding, MobileApp

router = APIRouter()
logger = logging.getLogger(__name__)

# MASVS v2 Categories
MASVS_CATEGORIES = {
    "MASVS-STORAGE": {
        "name": "Storage",
        "description": "Secure storage of sensitive data on a device",
        "controls": [
            "MASVS-STORAGE-1",
            "MASVS-STORAGE-2",
        ],
    },
    "MASVS-CRYPTO": {
        "name": "Cryptography",
        "description": "Cryptographic functionality to protect sensitive data",
        "controls": [
            "MASVS-CRYPTO-1",
            "MASVS-CRYPTO-2",
        ],
    },
    "MASVS-AUTH": {
        "name": "Authentication",
        "description": "Authentication and session management mechanisms",
        "controls": [
            "MASVS-AUTH-1",
            "MASVS-AUTH-2",
            "MASVS-AUTH-3",
        ],
    },
    "MASVS-NETWORK": {
        "name": "Network",
        "description": "Secure network communication",
        "controls": [
            "MASVS-NETWORK-1",
            "MASVS-NETWORK-2",
        ],
    },
    "MASVS-PLATFORM": {
        "name": "Platform",
        "description": "Secure platform interaction",
        "controls": [
            "MASVS-PLATFORM-1",
            "MASVS-PLATFORM-2",
            "MASVS-PLATFORM-3",
        ],
    },
    "MASVS-CODE": {
        "name": "Code Quality",
        "description": "Security best practices for code development",
        "controls": [
            "MASVS-CODE-1",
            "MASVS-CODE-2",
            "MASVS-CODE-3",
            "MASVS-CODE-4",
        ],
    },
    "MASVS-RESILIENCE": {
        "name": "Resilience",
        "description": "Resilience against reverse engineering and tampering",
        "controls": [
            "MASVS-RESILIENCE-1",
            "MASVS-RESILIENCE-2",
            "MASVS-RESILIENCE-3",
            "MASVS-RESILIENCE-4",
        ],
    },
    "MASVS-PRIVACY": {
        "name": "Privacy",
        "description": "Privacy protection",
        "controls": [
            "MASVS-PRIVACY-1",
            "MASVS-PRIVACY-2",
            "MASVS-PRIVACY-3",
            "MASVS-PRIVACY-4",
        ],
    },
}

# MASVS v2 Control IDs with names and descriptions
MASVS_CONTROLS = {
    "MASVS-STORAGE-1": {"name": "Secure Data Storage", "description": "The app securely stores sensitive data."},
    "MASVS-STORAGE-2": {"name": "Data Leakage Prevention", "description": "The app prevents leakage of sensitive data."},
    "MASVS-CRYPTO-1": {"name": "Strong Cryptography", "description": "The app employs current strong cryptography and uses it according to industry best practices."},
    "MASVS-CRYPTO-2": {"name": "Key Management", "description": "The app performs key management according to industry best practices."},
    "MASVS-AUTH-1": {"name": "Secure Authentication", "description": "The app uses secure authentication and authorization protocols."},
    "MASVS-AUTH-2": {"name": "Session Management", "description": "The app performs proper session management."},
    "MASVS-AUTH-3": {"name": "Biometric Authentication", "description": "The app uses biometric authentication securely where available."},
    "MASVS-NETWORK-1": {"name": "Secure Connections", "description": "The app secures all network traffic according to current best practices."},
    "MASVS-NETWORK-2": {"name": "TLS Settings", "description": "The app verifies the TLS settings of the underlying platform."},
    "MASVS-PLATFORM-1": {"name": "Platform Permissions", "description": "The app only requests the minimum set of permissions necessary."},
    "MASVS-PLATFORM-2": {"name": "Input Validation", "description": "All inputs from external sources and the user are validated."},
    "MASVS-PLATFORM-3": {"name": "Secure IPC", "description": "The app secures all inter-process communication."},
    "MASVS-CODE-1": {"name": "Verified Signing", "description": "The app is signed and provisioned with a valid certificate."},
    "MASVS-CODE-2": {"name": "Debug Prevention", "description": "The app has been built in release mode with appropriate settings."},
    "MASVS-CODE-3": {"name": "Exception Handling", "description": "The app catches and handles exceptions correctly."},
    "MASVS-CODE-4": {"name": "Secure Dependencies", "description": "The app uses up-to-date libraries with no known vulnerabilities."},
    "MASVS-RESILIENCE-1": {"name": "Anti-Tampering", "description": "The app detects and responds to tampering."},
    "MASVS-RESILIENCE-2": {"name": "Anti-Debugging", "description": "The app detects and responds to debugging."},
    "MASVS-RESILIENCE-3": {"name": "Obfuscation", "description": "The app implements code obfuscation and other protections."},
    "MASVS-RESILIENCE-4": {"name": "Device Integrity", "description": "The app detects rooted/jailbroken devices and responds."},
    "MASVS-PRIVACY-1": {"name": "Data Minimization", "description": "The app minimizes access to sensitive data and resources."},
    "MASVS-PRIVACY-2": {"name": "Consent Management", "description": "The app handles user consent for data collection."},
    "MASVS-PRIVACY-3": {"name": "Tracking Prevention", "description": "The app minimizes tracking of user activity."},
    "MASVS-PRIVACY-4": {"name": "Notification Transparency", "description": "The app provides clear notifications about data collection."},
}


@router.get("/masvs")
async def get_masvs_overview():
    """Get OWASP MASVS categories overview."""
    enriched = {}
    for cat_id, cat_info in MASVS_CATEGORIES.items():
        enriched[cat_id] = {
            **cat_info,
            "controls_detail": [
                {"id": ctrl_id, **MASVS_CONTROLS.get(ctrl_id, {"name": ctrl_id, "description": ""})}
                for ctrl_id in cat_info["controls"]
            ],
        }
    return {
        "version": "2.0",
        "categories": enriched,
    }


@router.get("/masvs/{app_id}")
async def get_app_compliance(
    app_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get MASVS compliance status for an app."""
    # Verify app
    result = await db.execute(
        select(MobileApp).where(MobileApp.app_id == app_id)
    )
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")

    # Get findings by MASVS category
    findings_query = (
        select(
            Finding.owasp_masvs_category,
            Finding.owasp_masvs_control,
            Finding.severity,
            Finding.status,
            func.count(),
        )
        .where(Finding.app_id == app_id)
        .where(Finding.owasp_masvs_category.isnot(None))
        .group_by(
            Finding.owasp_masvs_category,
            Finding.owasp_masvs_control,
            Finding.severity,
            Finding.status,
        )
    )
    findings_result = await db.execute(findings_query)

    # Build compliance matrix
    compliance = {}
    for category_id, category_info in MASVS_CATEGORIES.items():
        compliance[category_id] = {
            "name": category_info["name"],
            "description": category_info["description"],
            "status": "pass",
            "controls": {},
            "findings": {
                "total": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "open": 0,
                "remediated": 0,
            },
        }

        for control in category_info["controls"]:
            compliance[category_id]["controls"][control] = {
                "status": "not_tested",
                "findings_count": 0,
            }

    # Process findings
    for row in findings_result.all():
        category, control, severity, status, count = row
        if category in compliance:
            compliance[category]["findings"]["total"] += count
            if severity in compliance[category]["findings"]:
                compliance[category]["findings"][severity] += count

            if status == "open":
                compliance[category]["findings"]["open"] += count
            elif status == "remediated":
                compliance[category]["findings"]["remediated"] += count

            if control and control in compliance[category]["controls"]:
                compliance[category]["controls"][control]["findings_count"] += count
                compliance[category]["controls"][control]["status"] = "fail"

            # Update category status
            if severity in ("critical", "high") and status == "open":
                compliance[category]["status"] = "fail"
            elif compliance[category]["status"] != "fail" and status == "open":
                compliance[category]["status"] = "warning"

    # Calculate scores for each category
    for category_id, cat_data in compliance.items():
        controls = cat_data["controls"]
        total_controls = len(controls)
        if total_controls > 0:
            # A control passes if it has 0 findings
            passing_controls = sum(
                1 for c in controls.values()
                if c["findings_count"] == 0 or c["status"] == "not_tested"
            )
            cat_data["score"] = round((passing_controls / total_controls) * 100, 1)
        else:
            cat_data["score"] = 100.0

    # Build flat controls dictionary at root level (what frontend expects)
    all_controls = {}
    for cat_id, cat_data in compliance.items():
        for control_id, control_data in cat_data["controls"].items():
            all_controls[control_id] = {
                "id": control_id,
                "category": cat_id,
                "status": control_data["status"],
                "findings_count": control_data["findings_count"],
            }

    # Calculate overall score
    total_categories = len(MASVS_CATEGORIES)
    passing = sum(1 for c in compliance.values() if c["status"] == "pass")
    overall_score = (passing / total_categories) * 100 if total_categories > 0 else 0

    return {
        "app_id": app_id,
        "masvs_version": "2.0",
        "overall_score": round(overall_score, 1),
        "categories": compliance,
        "controls": all_controls,  # Flat controls structure for frontend
        "summary": {
            "pass": passing,
            "fail": sum(1 for c in compliance.values() if c["status"] == "fail"),
            "warning": sum(1 for c in compliance.values() if c["status"] == "warning"),
        },
    }


@router.get("/masvs/{app_id}/{category}")
async def get_category_details(
    app_id: str,
    category: str,
    db: AsyncSession = Depends(get_db),
):
    """Get detailed compliance for a specific MASVS category."""
    if category not in MASVS_CATEGORIES:
        raise HTTPException(status_code=404, detail="Category not found")

    # Verify app
    result = await db.execute(
        select(MobileApp).where(MobileApp.app_id == app_id)
    )
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")

    # Get findings for this category
    findings_result = await db.execute(
        select(Finding)
        .where(Finding.app_id == app_id)
        .where(Finding.owasp_masvs_category == category)
        .order_by(
            func.array_position(
                ["critical", "high", "medium", "low", "info"],
                Finding.severity,
            )
        )
    )
    findings = findings_result.scalars().all()

    return {
        "app_id": app_id,
        "category": category,
        "category_info": MASVS_CATEGORIES[category],
        "findings": [
            {
                "finding_id": f.finding_id,
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "control": f.owasp_masvs_control,
                "mastg_test": f.owasp_mastg_test,
                "description": f.description,
                "remediation": f.remediation,
            }
            for f in findings
        ],
        "total_findings": len(findings),
    }


@router.get("/report/{app_id}")
async def generate_compliance_report(
    app_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Generate a full compliance report for an app."""
    # Get app
    result = await db.execute(
        select(MobileApp).where(MobileApp.app_id == app_id)
    )
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")

    # Get compliance data
    compliance = await get_app_compliance(app_id, db)

    # Get all findings
    findings_result = await db.execute(
        select(Finding)
        .where(Finding.app_id == app_id)
        .order_by(
            func.array_position(
                ["critical", "high", "medium", "low", "info"],
                Finding.severity,
            )
        )
    )
    findings = findings_result.scalars().all()

    return {
        "report_type": "masvs_compliance",
        "app": {
            "app_id": app.app_id,
            "package_name": app.package_name,
            "app_name": app.app_name,
            "platform": app.platform,
            "version": app.version_name,
            "framework": app.framework,
        },
        "compliance": compliance,
        "findings": [
            {
                "finding_id": f.finding_id,
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "category": f.category,
                "masvs_category": f.owasp_masvs_category,
                "masvs_control": f.owasp_masvs_control,
                "mastg_test": f.owasp_mastg_test,
                "description": f.description,
                "impact": f.impact,
                "remediation": f.remediation,
                "cwe_id": f.cwe_id,
            }
            for f in findings
        ],
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }
