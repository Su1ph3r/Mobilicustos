"""Secrets router."""

import logging
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.models.database import MobileApp, Secret
from api.models.schemas import PaginatedResponse, SecretResponse

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("", response_model=PaginatedResponse)
async def list_secrets(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    app_id: str | None = None,
    secret_type: str | None = None,
    provider: str | None = None,
    exposure_risk: str | None = None,
    is_valid: bool | None = None,
    db: AsyncSession = Depends(get_db),
):
    """List all detected secrets with pagination and filters."""
    query = select(Secret)

    if app_id:
        query = query.where(Secret.app_id == app_id)
    if secret_type:
        query = query.where(Secret.secret_type == secret_type)
    if provider:
        query = query.where(Secret.provider == provider)
    if exposure_risk:
        query = query.where(Secret.exposure_risk == exposure_risk)
    if is_valid is not None:
        query = query.where(Secret.is_valid == is_valid)

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Apply pagination
    query = query.order_by(
        func.array_position(
            ["critical", "high", "medium", "low"],
            Secret.exposure_risk,
        ),
        Secret.detected_at.desc(),
    )
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    secrets = result.scalars().all()

    return PaginatedResponse(
        items=[SecretResponse.model_validate(s) for s in secrets],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.get("/summary")
async def get_secrets_summary(
    app_id: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Get summary of detected secrets."""
    base_filter = Secret.app_id == app_id if app_id else True

    # By type
    type_query = (
        select(Secret.secret_type, func.count())
        .where(base_filter)
        .group_by(Secret.secret_type)
    )
    type_result = await db.execute(type_query)
    by_type = dict(type_result.all())

    # By provider
    provider_query = (
        select(Secret.provider, func.count())
        .where(base_filter)
        .where(Secret.provider.isnot(None))
        .group_by(Secret.provider)
    )
    provider_result = await db.execute(provider_query)
    by_provider = dict(provider_result.all())

    # By risk
    risk_query = (
        select(Secret.exposure_risk, func.count())
        .where(base_filter)
        .where(Secret.exposure_risk.isnot(None))
        .group_by(Secret.exposure_risk)
    )
    risk_result = await db.execute(risk_query)
    by_risk = dict(risk_result.all())

    # Validated count
    validated_query = (
        select(func.count())
        .where(base_filter)
        .where(Secret.is_valid == True)
    )
    validated = (await db.execute(validated_query)).scalar() or 0

    return {
        "total": sum(by_type.values()),
        "by_type": by_type,
        "by_provider": by_provider,
        "by_risk": by_risk,
        "validated_secrets": validated,
    }


# IMPORTANT: These static routes must be defined BEFORE /{secret_id}
# to prevent "types" and "providers" from being parsed as UUIDs
@router.get("/types")
async def get_secret_types():
    """Get supported secret types and their patterns."""
    return {
        "types": [
            {
                "type": "api_key",
                "providers": ["aws", "gcp", "azure", "stripe", "twilio", "sendgrid"],
                "description": "API keys for cloud services",
            },
            {
                "type": "token",
                "providers": ["firebase", "github", "slack", "discord"],
                "description": "Authentication tokens",
            },
            {
                "type": "password",
                "providers": None,
                "description": "Hardcoded passwords",
            },
            {
                "type": "private_key",
                "providers": ["rsa", "ec", "ssh"],
                "description": "Private cryptographic keys",
            },
            {
                "type": "certificate",
                "providers": None,
                "description": "SSL/TLS certificates with private keys",
            },
            {
                "type": "database_url",
                "providers": ["postgres", "mysql", "mongodb", "redis"],
                "description": "Database connection strings",
            },
            {
                "type": "oauth_secret",
                "providers": ["google", "facebook", "twitter", "apple"],
                "description": "OAuth client secrets",
            },
        ]
    }


@router.get("/providers")
async def get_providers(db: AsyncSession = Depends(get_db)):
    """Get list of detected providers across all secrets."""
    result = await db.execute(
        select(Secret.provider, func.count())
        .where(Secret.provider.isnot(None))
        .group_by(Secret.provider)
        .order_by(func.count().desc())
    )

    return {
        "providers": [
            {"name": provider, "count": count}
            for provider, count in result.all()
        ]
    }


@router.get("/{secret_id}", response_model=SecretResponse)
async def get_secret(secret_id: UUID, db: AsyncSession = Depends(get_db)):
    """Get a secret by ID."""
    result = await db.execute(
        select(Secret).where(Secret.secret_id == secret_id)
    )
    secret = result.scalar_one_or_none()

    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")

    return SecretResponse.model_validate(secret)


@router.post("/{secret_id}/validate")
async def validate_secret(secret_id: UUID, db: AsyncSession = Depends(get_db)):
    """Attempt to validate if a secret is active/valid."""
    result = await db.execute(
        select(Secret).where(Secret.secret_id == secret_id)
    )
    secret = result.scalar_one_or_none()

    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")

    # Import here to avoid circular dependency
    from api.services.secret_validator import SecretValidator

    validator = SecretValidator()
    try:
        is_valid, error = await validator.validate(secret)
        secret.is_valid = is_valid
        secret.validation_error = error
        secret.last_validated = datetime.utcnow()
        await db.commit()

        return {
            "secret_id": str(secret_id),
            "is_valid": is_valid,
            "error": error,
        }
    except Exception as e:
        logger.error(f"Failed to validate secret: {e}")
        raise HTTPException(status_code=500, detail=str(e))
