"""ML Models router."""

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.models.database import MLModel, MobileApp
from api.models.schemas import MLModelResponse, PaginatedResponse
from api.services.ml_analyzer import MLModelAnalyzer

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("", response_model=PaginatedResponse)
async def list_ml_models(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    app_id: str | None = None,
    model_format: str | None = None,
    analysis_status: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """List all extracted ML models with pagination and filters."""
    query = select(MLModel)

    if app_id:
        query = query.where(MLModel.app_id == app_id)
    if model_format:
        query = query.where(MLModel.model_format == model_format)
    if analysis_status:
        query = query.where(MLModel.analysis_status == analysis_status)

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Apply pagination
    query = query.order_by(MLModel.extracted_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    models = result.scalars().all()

    return PaginatedResponse(
        items=[MLModelResponse.model_validate(m) for m in models],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.get("/{model_id}", response_model=MLModelResponse)
async def get_ml_model(model_id: UUID, db: AsyncSession = Depends(get_db)):
    """Get an ML model by ID."""
    result = await db.execute(
        select(MLModel).where(MLModel.model_id == model_id)
    )
    model = result.scalar_one_or_none()

    if not model:
        raise HTTPException(status_code=404, detail="ML model not found")

    return MLModelResponse.model_validate(model)


@router.post("/extract")
async def extract_ml_models(
    app_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Extract ML models from an app."""
    # Verify app
    result = await db.execute(
        select(MobileApp).where(MobileApp.app_id == app_id)
    )
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")

    analyzer = MLModelAnalyzer()
    try:
        extracted_models = await analyzer.extract_models(app)

        # Save to database
        for model_data in extracted_models:
            model = MLModel(
                app_id=app_id,
                model_name=model_data.get("name"),
                model_format=model_data["format"],
                file_path=model_data["file_path"],
                file_size_bytes=model_data.get("file_size"),
                file_hash=model_data.get("hash"),
                analysis_status="pending",
            )
            db.add(model)

        await db.commit()

        return {
            "app_id": app_id,
            "extracted": len(extracted_models),
            "models": extracted_models,
        }
    except Exception as e:
        logger.error(f"Failed to extract ML models: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{model_id}/analyze")
async def analyze_ml_model(model_id: UUID, db: AsyncSession = Depends(get_db)):
    """Analyze an extracted ML model."""
    result = await db.execute(
        select(MLModel).where(MLModel.model_id == model_id)
    )
    model = result.scalar_one_or_none()

    if not model:
        raise HTTPException(status_code=404, detail="ML model not found")

    analyzer = MLModelAnalyzer()
    try:
        analysis = await analyzer.analyze_model(model)

        # Update model with analysis results
        model.input_tensors = analysis.get("input_tensors", [])
        model.output_tensors = analysis.get("output_tensors", [])
        model.operations = analysis.get("operations", [])
        model.labels = analysis.get("labels", [])
        model.vulnerabilities = analysis.get("vulnerabilities", [])
        model.adversarial_risk = analysis.get("adversarial_risk")
        model.model_stealing_risk = analysis.get("model_stealing_risk")
        model.analysis_status = "completed"

        await db.commit()

        return {
            "model_id": str(model_id),
            "analysis": analysis,
        }
    except Exception as e:
        model.analysis_status = "failed"
        await db.commit()
        logger.error(f"Failed to analyze ML model: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{model_id}/security")
async def get_model_security_analysis(
    model_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get security analysis for an ML model."""
    result = await db.execute(
        select(MLModel).where(MLModel.model_id == model_id)
    )
    model = result.scalar_one_or_none()

    if not model:
        raise HTTPException(status_code=404, detail="ML model not found")

    if model.analysis_status != "completed":
        raise HTTPException(
            status_code=400,
            detail="Model has not been analyzed yet",
        )

    return {
        "model_id": str(model_id),
        "vulnerabilities": model.vulnerabilities,
        "adversarial_risk": model.adversarial_risk,
        "model_stealing_risk": model.model_stealing_risk,
        "recommendations": _get_ml_security_recommendations(model),
    }


def _get_ml_security_recommendations(model: MLModel) -> list[dict]:
    """Generate security recommendations for an ML model."""
    recommendations = []

    if model.adversarial_risk in ("high", "critical"):
        recommendations.append({
            "title": "Implement Adversarial Input Validation",
            "description": "The model is vulnerable to adversarial inputs. Implement input validation and preprocessing to detect and reject adversarial examples.",
            "priority": "high",
        })

    if model.model_stealing_risk in ("high", "critical"):
        recommendations.append({
            "title": "Protect Model from Extraction",
            "description": "The model structure is easily extractable. Consider using model obfuscation, encryption, or server-side inference.",
            "priority": "high",
        })

    if model.labels:
        recommendations.append({
            "title": "Labels Exposed in Model",
            "description": f"Found {len(model.labels)} labels embedded in the model. This could reveal business logic or sensitive categories.",
            "priority": "medium",
        })

    return recommendations


@router.get("/formats")
async def get_supported_formats():
    """Get supported ML model formats."""
    return {
        "formats": [
            {
                "format": "tflite",
                "name": "TensorFlow Lite",
                "extensions": [".tflite"],
                "platforms": ["android", "ios"],
            },
            {
                "format": "coreml",
                "name": "Core ML",
                "extensions": [".mlmodel", ".mlpackage"],
                "platforms": ["ios"],
            },
            {
                "format": "onnx",
                "name": "ONNX",
                "extensions": [".onnx"],
                "platforms": ["android", "ios"],
            },
            {
                "format": "pytorch",
                "name": "PyTorch Mobile",
                "extensions": [".pt", ".ptl"],
                "platforms": ["android", "ios"],
            },
        ]
    }
