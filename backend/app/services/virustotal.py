import base64
import os
import re
from typing import Any

import httpx


VT_BASE_URL = "https://www.virustotal.com/api/v3"

MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")


def detect_indicator_type(indicator: str) -> str:
    indicator = indicator.strip()

    if indicator.lower().startswith(("http://", "https://")):
        return "url"

    if MD5_PATTERN.fullmatch(indicator):
        return "md5"

    if SHA1_PATTERN.fullmatch(indicator):
        return "sha1"

    if SHA256_PATTERN.fullmatch(indicator):
        return "sha256"

    raise ValueError(
        "Unsupported indicator. Enter a URL, MD5, SHA-1, or SHA-256 hash."
    )


def encode_url_identifier(url: str) -> str:
    return (
        base64.urlsafe_b64encode(url.encode("utf-8"))
        .decode("utf-8")
        .rstrip("=")
    )


def extract_report(
    data: dict[str, Any],
    indicator: str,
    indicator_type: str
) -> dict[str, Any]:

    attributes = data.get("data", {}).get("attributes", {})
    object_id = data.get("data", {}).get("id")

    stats = attributes.get("last_analysis_stats", {})

    return {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "found": True,
        "id": object_id,
        "reputation": attributes.get("reputation"),
        "analysis_stats": {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "timeout": stats.get("timeout", 0),
        },
        "last_analysis_date": attributes.get("last_analysis_date"),
        "meaningful_name": attributes.get("meaningful_name"),
        "names": attributes.get("names", []),
        "tags": attributes.get("tags", []),
        "categories": attributes.get("categories", {}),
        "url": attributes.get("url"),
    }


async def lookup_indicator(indicator: str) -> dict[str, Any]:

    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        raise RuntimeError(
            "VT_API_KEY is not configured in backend/.env"
        )

    indicator = indicator.strip()

    if not indicator:
        raise ValueError("Indicator cannot be empty.")

    indicator_type = detect_indicator_type(indicator)

    if indicator_type == "url":
        identifier = encode_url_identifier(indicator)
        endpoint = f"{VT_BASE_URL}/urls/{identifier}"
    else:
        endpoint = f"{VT_BASE_URL}/files/{indicator}"

    headers = {
        "x-apikey": api_key,
        "accept": "application/json",
    }

    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.get(
            endpoint,
            headers=headers,
        )

    if response.status_code == 404:
        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "found": False,
            "message": "Indicator was not found in VirusTotal.",
        }

    if response.status_code in (401, 403):
        raise RuntimeError(
            "VirusTotal authentication failed. Check VT_API_KEY."
        )

    if response.status_code == 429:
        raise RuntimeError(
            "VirusTotal API rate limit reached. Please try again later."
        )

    if response.status_code >= 400:
        try:
            error_detail = response.json()
        except Exception:
            error_detail = response.text

        raise RuntimeError(
            f"VirusTotal API request failed: {error_detail}"
        )

    return extract_report(
        response.json(),
        indicator,
        indicator_type,
    )