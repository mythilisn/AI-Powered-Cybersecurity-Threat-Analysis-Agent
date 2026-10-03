from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..services.virustotal import lookup_indicator


router = APIRouter(
    prefix="/virustotal",
    tags=["VirusTotal"]
)


class VirusTotalLookupRequest(BaseModel):
    indicator: str


@router.post("/lookup")
async def lookup(
    request: VirusTotalLookupRequest,
) -> dict[str, Any]:

    try:
        return await lookup_indicator(request.indicator)

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc)
        )

    except RuntimeError as exc:
        message = str(exc)

        if "not configured" in message:
            raise HTTPException(
                status_code=503,
                detail=message
            )

        if "rate limit" in message:
            raise HTTPException(
                status_code=429,
                detail=message
            )

        if "authentication failed" in message:
            raise HTTPException(
                status_code=502,
                detail=message
            )

        raise HTTPException(
            status_code=502,
            detail=message
        )