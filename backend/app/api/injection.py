import os
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, HTTPException, status, UploadFile, File, Form
from pydantic import BaseModel, Field

from app.core.database import db
from app.services.injection_service import InjectionDetectorService
from app.services.injection_agent import InjectionAnalysisAgent
from app.services.file_parser import FileParserService

router = APIRouter(prefix="/injection", tags=["Malware Injection Analysis"])

detector_service = InjectionDetectorService()
agent_service = InjectionAnalysisAgent()


class InjectionAnalysisRequest(BaseModel):
    raw_log: str = Field(..., description="Raw Sysmon event log, WinAPI sequence, or execution trace.")
    source_tag: Optional[str] = Field(default="SOC Triage", description="Optional label or case identifier.")


class InjectionAnalysisResponse(BaseModel):
    status: str
    timestamp: str
    risk_level: str
    is_suspicious: bool
    detected_apis: List[str]
    process_metadata: Dict[str, Any]
    mitre_techniques: List[Dict[str, Any]]
    ai_insights: Dict[str, Any]
    filename: Optional[str] = None


@router.post("/analyze", response_model=InjectionAnalysisResponse)
async def analyze_process_injection(request: InjectionAnalysisRequest):
    """
    Analyzes telemetry logs for Process Injection (MITRE T1055),
    combining deterministic heuristic extraction with AI agent reasoning.
    """
    if not request.raw_log or not request.raw_log.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Log payload cannot be empty."
        )

    heuristic_results = detector_service.analyze(request.raw_log)
    ai_insights = await agent_service.analyze_injection(heuristic_results, request.raw_log)
    timestamp = datetime.now(timezone.utc).isoformat()

    record = {
        "status": "success",
        "timestamp": timestamp,
        "source_tag": request.source_tag,
        "risk_level": heuristic_results["risk_level"],
        "is_suspicious": heuristic_results["is_suspicious"],
        "detected_apis": heuristic_results["detected_apis"],
        "process_metadata": heuristic_results["process_metadata"],
        "mitre_techniques": heuristic_results["mitre_techniques"],
        "ai_insights": ai_insights,
        "raw_log_sample": request.raw_log[:500]
    }

    try:
        if db is not None:
            await db["injection_analyses"].insert_one(record)
    except Exception:
        pass

    return InjectionAnalysisResponse(
        status="success",
        timestamp=timestamp,
        risk_level=heuristic_results["risk_level"],
        is_suspicious=heuristic_results["is_suspicious"],
        detected_apis=heuristic_results["detected_apis"],
        process_metadata=heuristic_results["process_metadata"],
        mitre_techniques=heuristic_results["mitre_techniques"],
        ai_insights=ai_insights
    )


@router.post("/upload", response_model=InjectionAnalysisResponse)
async def upload_injection_log_file(
    file: UploadFile = File(...),
    source_tag: str = Form(default="File Upload")
):
    """
    Ingests and parses Sysmon, EDR, or memory trace log files (.log, .txt, .json, .xml)
    and executes MITRE T1055 forensic analysis.
    """
    try:
        content = await file.read()
        extracted_text = FileParserService.extract_text_from_file(file.filename, content)

        if not extracted_text.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Could not extract readable telemetry text from this log file."
            )

        heuristic_results = detector_service.analyze(extracted_text)
        ai_insights = await agent_service.analyze_injection(heuristic_results, extracted_text)
        timestamp = datetime.now(timezone.utc).isoformat()

        record = {
            "status": "success",
            "timestamp": timestamp,
            "filename": file.filename,
            "source_tag": f"{source_tag} ({file.filename})",
            "risk_level": heuristic_results["risk_level"],
            "is_suspicious": heuristic_results["is_suspicious"],
            "detected_apis": heuristic_results["detected_apis"],
            "process_metadata": heuristic_results["process_metadata"],
            "mitre_techniques": heuristic_results["mitre_techniques"],
            "ai_insights": ai_insights,
            "raw_log_sample": extracted_text[:500]
        }

        try:
            if db is not None:
                await db["injection_analyses"].insert_one(record)
        except Exception:
            pass

        return InjectionAnalysisResponse(
            status="success",
            timestamp=timestamp,
            filename=file.filename,
            risk_level=heuristic_results["risk_level"],
            is_suspicious=heuristic_results["is_suspicious"],
            detected_apis=heuristic_results["detected_apis"],
            process_metadata=heuristic_results["process_metadata"],
            mitre_techniques=heuristic_results["mitre_techniques"],
            ai_insights=ai_insights
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error parsing telemetry file: {str(e)}"
        )