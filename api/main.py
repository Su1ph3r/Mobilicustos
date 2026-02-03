"""Mobilicustos API - Mobile Security Penetration Testing Platform."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.config import get_settings
from api.routers import (
    app_stores,
    apps,
    attack_paths,
    burp,
    bypass,
    compliance,
    corellium,
    dashboard,
    devices,
    drozer,
    exports,
    finding_workflow,
    findings,
    frida,
    fuzzing,
    health,
    ios,
    issue_tracker,
    ml_models,
    network_traffic,
    objection,
    reports,
    runtime_monitor,
    scans,
    scheduled_scans,
    screenshot,
    secrets,
    siem,
    teams,
    webhooks,
)

settings = get_settings()

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.api_log_level.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info("Starting Mobilicustos API...")
    # Startup tasks
    yield
    # Shutdown tasks
    logger.info("Shutting down Mobilicustos API...")


app = FastAPI(
    title="Mobilicustos",
    description="Mobile Security Penetration Testing Platform",
    version="0.1.0",
    lifespan=lifespan,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(health.router, tags=["Health"])
app.include_router(apps.router, prefix="/api/apps", tags=["Apps"])
app.include_router(scans.router, prefix="/api/scans", tags=["Scans"])
app.include_router(findings.router, prefix="/api/findings", tags=["Findings"])
app.include_router(devices.router, prefix="/api/devices", tags=["Devices"])
app.include_router(frida.router, prefix="/api/frida", tags=["Frida"])
app.include_router(drozer.router, prefix="/api/drozer", tags=["Drozer"])
app.include_router(objection.router, prefix="/api/objection", tags=["Objection"])
app.include_router(bypass.router, prefix="/api/bypass", tags=["Bypass"])
app.include_router(ml_models.router, prefix="/api/ml-models", tags=["ML Models"])
app.include_router(secrets.router, prefix="/api/secrets", tags=["Secrets"])
app.include_router(attack_paths.router, prefix="/api/attack-paths", tags=["Attack Paths"])
app.include_router(compliance.router, prefix="/api/compliance", tags=["Compliance"])
app.include_router(exports.router, prefix="/api/exports", tags=["Exports"])
app.include_router(ios.router, prefix="/api/ios", tags=["iOS"])
app.include_router(scheduled_scans.router, prefix="/api", tags=["Scheduled Scans"])
app.include_router(webhooks.router, prefix="/api", tags=["Webhooks"])
app.include_router(burp.router, prefix="/api", tags=["Burp Suite"])
app.include_router(issue_tracker.router, prefix="/api", tags=["Issue Tracker"])
app.include_router(dashboard.router, prefix="/api", tags=["Dashboard"])
app.include_router(reports.router, prefix="/api", tags=["Reports"])
app.include_router(teams.router, prefix="/api", tags=["Teams"])
app.include_router(finding_workflow.router, prefix="/api", tags=["Finding Workflow"])
app.include_router(siem.router, prefix="/api", tags=["SIEM/SOAR"])
app.include_router(app_stores.router, prefix="/api", tags=["App Stores"])
app.include_router(network_traffic.router, prefix="/api", tags=["Network Traffic"])
app.include_router(runtime_monitor.router, prefix="/api", tags=["Runtime Monitor"])
app.include_router(fuzzing.router, prefix="/api", tags=["Fuzzing"])
app.include_router(screenshot.router, prefix="/api", tags=["Screen Capture"])
app.include_router(corellium.router, prefix="/api", tags=["Corellium"])


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": "Mobilicustos",
        "version": "0.1.0",
        "description": "Mobile Security Penetration Testing Platform",
    }
