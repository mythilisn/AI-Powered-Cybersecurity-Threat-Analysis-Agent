from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from ..services.static_analysis import analyze_text


router = APIRouter(
    prefix="/analysis",
    tags=["Static Analysis"]
)


class TextAnalysisRequest(BaseModel):
    text: str = Field(
        ...,
        min_length=1,
        max_length=100_000,
        description="Text or script content to analyze."
    )


@router.post("/static")
async def static_analysis(
    request: TextAnalysisRequest
) -> dict[str, Any]:
    """
    Run deterministic static analysis on submitted text or script content.
    """

    result = analyze_text(request.text)

    return {
        "analysis_type": "static",
        **result
    }