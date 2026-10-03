from fastapi import APIRouter, HTTPException, status, UploadFile, File, Form
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
from datetime import datetime
from ..services.ioc_parser import IOCExtractor
from ..services.file_parser import FileParserService
from ..core.database import db

router = APIRouter(prefix="/ioc", tags=["IoC Extraction"])
ioc_logs_collection = db["ioc_extractions"]

class RawThreatTextRequest(BaseModel):
    raw_text: str = Field(..., min_length=1, description="Raw unstructured threat content")
    source_tag: str = Field(default="Manual Triage", description="Tag/Source for analysis tracking")

class IOCResponse(BaseModel):
    results: Dict[str, Any]
    source_tag: str
    filename: Optional[str] = None
    timestamp: str

@router.post("/extract", response_model=IOCResponse, status_code=status.HTTP_200_OK)
async def extract_iocs(payload: RawThreatTextRequest):
    if not payload.raw_text.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload text cannot be empty."
        )

    extracted_data = IOCExtractor.extract_all(payload.raw_text)
    timestamp = datetime.utcnow().isoformat()

    record = {
        "source_tag": payload.source_tag,
        "results": extracted_data,
        "created_at": timestamp
    }
    await ioc_logs_collection.insert_one(record)

    return {
        "results": extracted_data,
        "source_tag": payload.source_tag,
        "timestamp": timestamp
    }

@router.post("/upload", response_model=IOCResponse, status_code=status.HTTP_200_OK)
async def upload_threat_file(
    file: UploadFile = File(...),
    source_tag: str = Form(default="File Upload")
):
    try:
        content = await file.read()
        extracted_text = FileParserService.extract_text_from_file(file.filename, content)

        if not extracted_text.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Could not extract readable text or artifacts from this file."
            )

        extracted_data = IOCExtractor.extract_all(extracted_text)
        timestamp = datetime.utcnow().isoformat()

        record = {
            "source_tag": f"{source_tag} ({file.filename})",
            "results": extracted_data,
            "filename": file.filename,
            "created_at": timestamp
        }
        await ioc_logs_collection.insert_one(record)

        return {
            "results": extracted_data,
            "source_tag": source_tag,
            "filename": file.filename,
            "timestamp": timestamp
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error parsing file: {str(e)}"
        )
