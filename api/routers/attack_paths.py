"""Attack paths router."""

import logging
from decimal import Decimal
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.models.database import AttackPath, Finding, MobileApp
from api.models.schemas import AttackPathResponse, PaginatedResponse
from api.services.attack_path_analyzer import AttackPathAnalyzer

router = APIRouter()
logger = logging.getLogger(__name__)


def _risk_level(score: Decimal | float | None) -> str:
    """Convert numeric risk score to risk level string."""
    if score is None:
        return "unknown"
    score_float = float(score)
    if score_float >= 9.0:
        return "critical"
    if score_float >= 7.0:
        return "high"
    if score_float >= 4.0:
        return "medium"
    if score_float >= 1.0:
        return "low"
    return "info"


def _calculate_impact(findings: list[Finding]) -> dict[str, int]:
    """Calculate CIA impact scores from findings."""
    # Base impact calculation from severity distribution
    severity_weights = {"critical": 10, "high": 8, "medium": 5, "low": 2, "info": 1}

    total_weight = 0
    for f in findings:
        total_weight += severity_weights.get(f.severity, 0)

    if not findings:
        return {"confidentiality": 0, "integrity": 0, "availability": 0}

    avg_weight = total_weight / len(findings)

    # Distribute impact across CIA based on finding categories
    confidentiality = min(100, int(avg_weight * 10))
    integrity = min(100, int(avg_weight * 8))
    availability = min(100, int(avg_weight * 5))

    return {
        "confidentiality": confidentiality,
        "integrity": integrity,
        "availability": availability,
    }


async def _transform_for_frontend(
    path: AttackPath,
    findings: list[Finding],
) -> dict[str, Any]:
    """Transform attack path data to match frontend expectations."""
    steps = []
    findings_map = {f.finding_id: f for f in findings}

    for i, fid in enumerate(path.finding_chain or []):
        finding = findings_map.get(fid)
        if finding:
            step_type = "entry_point" if i == 0 else "vulnerability"
            if i == len(path.finding_chain) - 1:
                step_type = "impact"
            steps.append({
                "type": step_type,
                "title": finding.title,
                "description": (finding.description or "")[:200],
                "finding_id": fid,
                "severity": finding.severity,
                "category": finding.category,
            })

    return {
        "path_id": str(path.path_id),
        "title": path.path_name,
        "description": path.path_description,
        "attack_vector": path.attack_vector,
        "risk_level": _risk_level(path.combined_risk_score),
        "risk_score": float(path.combined_risk_score or 0),
        "exploitability": path.exploitability,
        "findings_count": len(path.finding_chain or []),
        "steps_count": len(steps),
        "steps": steps,
        "impact": _calculate_impact(findings),
        "finding_chain": path.finding_chain,
        "created_at": path.created_at.isoformat() if path.created_at else None,
    }


@router.get("")
async def list_attack_paths(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    app_id: str | None = None,
    exploitability: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """List all attack paths with pagination and filters."""
    query = select(AttackPath)

    if app_id:
        query = query.where(AttackPath.app_id == app_id)
    if exploitability:
        query = query.where(AttackPath.exploitability == exploitability)

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Apply pagination
    query = query.order_by(AttackPath.combined_risk_score.desc().nullslast())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    paths = result.scalars().all()

    # Get all finding IDs from all paths
    all_finding_ids = set()
    for path in paths:
        if path.finding_chain:
            all_finding_ids.update(path.finding_chain)

    # Fetch all findings at once
    findings_map = {}
    if all_finding_ids:
        findings_result = await db.execute(
            select(Finding).where(Finding.finding_id.in_(all_finding_ids))
        )
        findings_map = {f.finding_id: f for f in findings_result.scalars().all()}

    # Transform paths for frontend
    transformed_items = []
    for path in paths:
        path_findings = [
            findings_map[fid] for fid in (path.finding_chain or [])
            if fid in findings_map
        ]
        transformed = await _transform_for_frontend(path, path_findings)
        transformed_items.append(transformed)

    return {
        "items": transformed_items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
    }


@router.get("/{path_id}")
async def get_attack_path(path_id: UUID, db: AsyncSession = Depends(get_db)):
    """Get an attack path by ID."""
    result = await db.execute(
        select(AttackPath).where(AttackPath.path_id == path_id)
    )
    path = result.scalar_one_or_none()

    if not path:
        raise HTTPException(status_code=404, detail="Attack path not found")

    # Fetch findings for this path
    findings = []
    if path.finding_chain:
        findings_result = await db.execute(
            select(Finding).where(Finding.finding_id.in_(path.finding_chain))
        )
        findings = findings_result.scalars().all()

    return await _transform_for_frontend(path, findings)


@router.get("/{path_id}/findings")
async def get_attack_path_findings(
    path_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get the findings that make up an attack path."""
    result = await db.execute(
        select(AttackPath).where(AttackPath.path_id == path_id)
    )
    path = result.scalar_one_or_none()

    if not path:
        raise HTTPException(status_code=404, detail="Attack path not found")

    # Get findings in order
    findings_result = await db.execute(
        select(Finding).where(Finding.finding_id.in_(path.finding_chain or []))
    )
    findings = findings_result.scalars().all()

    # Sort by chain order
    findings_map = {f.finding_id: f for f in findings}
    ordered_findings = [
        findings_map[fid] for fid in (path.finding_chain or []) if fid in findings_map
    ]

    return {
        "path_id": str(path_id),
        "title": path.path_name,
        "path_name": path.path_name,
        "findings": [
            {
                "finding_id": f.finding_id,
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "description": f.description,
                "file_path": f.file_path,
                "code_snippet": f.code_snippet,
            }
            for f in ordered_findings
        ],
    }


@router.post("/generate")
async def generate_attack_paths(
    app_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Generate attack paths for an app based on findings."""
    # Verify app
    result = await db.execute(
        select(MobileApp).where(MobileApp.app_id == app_id)
    )
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")

    # Get findings
    findings_result = await db.execute(
        select(Finding)
        .where(Finding.app_id == app_id)
        .where(Finding.status == "open")
    )
    findings = findings_result.scalars().all()

    if not findings:
        return {"message": "No findings to generate attack paths from"}

    analyzer = AttackPathAnalyzer()
    try:
        paths = await analyzer.generate_paths(findings)

        # Save to database
        for path_data in paths:
            attack_path = AttackPath(
                app_id=app_id,
                path_name=path_data["name"],
                path_description=path_data["description"],
                attack_vector=path_data["attack_vector"],
                finding_chain=path_data["finding_chain"],
                combined_risk_score=path_data["risk_score"],
                exploitability=path_data["exploitability"],
            )
            db.add(attack_path)

        await db.commit()

        return {
            "app_id": app_id,
            "generated": len(paths),
            "paths": paths,
        }
    except Exception as e:
        logger.error(f"Failed to generate attack paths: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{path_id}/graph")
async def get_attack_path_graph(
    path_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get graph data for visualization."""
    result = await db.execute(
        select(AttackPath).where(AttackPath.path_id == path_id)
    )
    path = result.scalar_one_or_none()

    if not path:
        raise HTTPException(status_code=404, detail="Attack path not found")

    # Get findings - handle null finding_chain
    findings_result = await db.execute(
        select(Finding).where(Finding.finding_id.in_(path.finding_chain or []))
    )
    findings = findings_result.scalars().all()
    findings_map = {f.finding_id: f for f in findings}

    # Build graph nodes and edges
    nodes = []
    edges = []

    for i, finding_id in enumerate(path.finding_chain):
        finding = findings_map.get(finding_id)
        if finding:
            nodes.append({
                "id": finding_id,
                "label": finding.title[:50],
                "severity": finding.severity,
                "category": finding.category,
                "position": i,
            })

            if i > 0:
                prev_id = path.finding_chain[i - 1]
                edges.append({
                    "source": prev_id,
                    "target": finding_id,
                    "label": "leads to",
                })

    return {
        "path_id": str(path_id),
        "path_name": path.path_name,
        "nodes": nodes,
        "edges": edges,
    }


@router.delete("/{path_id}")
async def delete_attack_path(path_id: UUID, db: AsyncSession = Depends(get_db)):
    """Delete an attack path."""
    result = await db.execute(
        select(AttackPath).where(AttackPath.path_id == path_id)
    )
    path = result.scalar_one_or_none()

    if not path:
        raise HTTPException(status_code=404, detail="Attack path not found")

    await db.delete(path)
    await db.commit()

    return {"message": "Attack path deleted successfully"}
