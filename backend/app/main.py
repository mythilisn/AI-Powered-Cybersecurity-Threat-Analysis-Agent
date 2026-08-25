import os
from datetime import datetime, timezone
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from app.api.auth import router as auth_router
from app.api.ioc import router as ioc_router
from app.api.injection import router as injection_router
from app.core.database import client

load_dotenv()

app = FastAPI(title="AI-Powered Cybersecurity Threat Analysis Agent")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register endpoints (prefix is already defined inside each router file)
app.include_router(auth_router)
app.include_router(ioc_router)
app.include_router(injection_router)

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
        if client is not None:
            await client.admin.command("ping")
        else:
            db_status = "uninitialized"
    except Exception:
        db_status = "disconnected"
        
    return {
        "status": "OK",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": db_status
    }