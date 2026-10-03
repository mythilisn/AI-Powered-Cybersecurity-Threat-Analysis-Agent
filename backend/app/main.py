import os
from datetime import datetime

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from .api.auth import router as auth_router
from .api.analysis import router as analysis_router
from .api.ioc import router as ioc_router
from .api.virustotal import router as virustotal_router
from .api.submission import router as submission_router
from .core.database import client

load_dotenv()

app = FastAPI(
    title="AI-Powered SOC Threat Analysis API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register all API modules
app.include_router(auth_router)
app.include_router(analysis_router)
app.include_router(ioc_router)
app.include_router(virustotal_router)
app.include_router(submission_router)

@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "AI-Powered Threat Analysis Agent",
        "docs": "/docs",
        "health": "/health"
    }


@app.get("/health")
async def health_check():
    db_status = "connected"

    try:
        await client.admin.command("ping")
    except Exception:
        db_status = "disconnected"

    return {
        "status": "OK",
        "timestamp": datetime.utcnow().isoformat(),
        "database": db_status
    }