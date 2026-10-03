from typing import Any
from datetime import datetime

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from ..services.ioc_parser import IOCExtractor
from ..services.static_analysis import analyze_text
from ..services.virustotal import lookup_indicator, detect_indicator_type


router = APIRouter(prefix="/submission", tags=["Submission"])


class TextSubmissionRequest(BaseModel):
    text: str = Field(
        ...,
        min_length=1,
        max_length=100_000,
        description="Text, email content, or suspicious script to analyze"
    )


class URLSubmissionRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=5,
        max_length=2048,
        description="URL to analyze (http:// or https://)"
    )


@router.post("/text")
async def submit_text(request: TextSubmissionRequest) -> dict[str, Any]:
    """
    Submit text/email content for analysis.
    
    Performs:
    1. IOC extraction (IPs, URLs, domains, hashes, emails, CVEs)
    2. Static analysis (suspicious patterns, obfuscation, keywords)
    """
    
    if not request.text.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Text content cannot be empty."
        )
    
    # Extract IOCs
    iocs = IOCExtractor.extract_all(request.text)
    
    # Run static analysis
    static_result = analyze_text(request.text)
    
    return {
        "submission_type": "text",
        "timestamp": datetime.utcnow().isoformat(),
        "iocs": iocs,
        "static_analysis": static_result
    }


@router.post("/url")
async def submit_url(request: URLSubmissionRequest) -> dict[str, Any]:
    """
    Submit a URL for analysis.
    
    Performs:
    1. URL validation
    2. IOC extraction from URL
    3. VirusTotal lookup (if VT_API_KEY is configured)
    """
    
    if not request.url.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL cannot be empty."
        )
    
    url = request.url.strip()
    
    # Validate that it's a proper URL format
    try:
        indicator_type = detect_indicator_type(url)
        if indicator_type != "url":
            raise ValueError()
    except (ValueError, Exception):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid URL format. Please provide a URL starting with http:// or https://"
        )
    
    # Extract IOCs from the URL itself
    iocs = IOCExtractor.extract_all(url)
    
    # Try to lookup in VirusTotal
    virustotal_result = None
    virustotal_error = None
    
    try:
        virustotal_result = await lookup_indicator(url)
    except RuntimeError as e:
        # VT API key not configured or API error
        virustotal_error = str(e)
    except ValueError as e:
        virustotal_error = str(e)
    
    return {
        "submission_type": "url",
        "url": url,
        "timestamp": datetime.utcnow().isoformat(),
        "iocs": iocs,
        "virustotal": virustotal_result,
        "virustotal_error": virustotal_error
    }
