import re
from typing import Any


# Suspicious patterns commonly associated with malicious behavior.
SUSPICIOUS_PATTERNS = [
    {
        "name": "PowerShell encoded command",
        "category": "obfuscation",
        "severity": "high",
        "pattern": r"(?i)\bpowershell(?:\.exe)?\b.*(?:-enc|-encodedcommand)\b",
        "description": "Encoded PowerShell command detected."
    },
    {
        "name": "PowerShell execution",
        "category": "command_execution",
        "severity": "medium",
        "pattern": r"(?i)\bpowershell(?:\.exe)?\b",
        "description": "PowerShell execution detected."
    },
    {
        "name": "Command shell execution",
        "category": "command_execution",
        "severity": "medium",
        "pattern": r"(?i)\b(?:cmd\.exe|/bin/sh|/bin/bash)\b",
        "description": "Command shell execution detected."
    },
    {
        "name": "Download utility",
        "category": "network_activity",
        "severity": "medium",
        "pattern": r"(?i)\b(?:curl|wget)\b\s+https?://",
        "description": "Command-line download activity detected."
    },
    {
        "name": "Certutil download",
        "category": "network_activity",
        "severity": "high",
        "pattern": r"(?i)\bcertutil(?:\.exe)?\b.*(?:-urlcache|-split)",
        "description": "Certutil URL download behavior detected."
    },
    {
        "name": "Bitsadmin transfer",
        "category": "network_activity",
        "severity": "high",
        "pattern": r"(?i)\bbitsadmin(?:\.exe)?\b.*(?:/transfer|/addfile)",
        "description": "BITSAdmin file transfer behavior detected."
    },
    {
        "name": "Reverse shell indicator",
        "category": "shell",
        "severity": "high",
        "pattern": r"(?i)(?:bash\s+-i|nc\s+-e|ncat\s+-e|/dev/tcp/)",
        "description": "Potential reverse shell pattern detected."
    },
    {
        "name": "Credential access keyword",
        "category": "credential_access",
        "severity": "medium",
        "pattern": r"(?i)\b(?:password|credential|credentials|keylogger|steal\s+passwords)\b",
        "description": "Credential-access related keyword detected."
    },
    {
        "name": "Payload keyword",
        "category": "malicious_payload",
        "severity": "medium",
        "pattern": r"(?i)\b(?:payload|ransomware|malware|backdoor|reverse\s+shell)\b",
        "description": "Malware or payload related keyword detected."
    }
]


SUSPICIOUS_KEYWORDS = [
    "keylogger",
    "ransomware",
    "backdoor",
    "reverse shell",
    "credential dump",
    "password dump",
    "malicious payload",
]


def detect_obfuscation(text: str) -> list[dict[str, Any]]:
    """
    Detect simple, explainable indicators of obfuscation.

    This does not attempt to decode or execute the content.
    """

    findings = []

    # Detect PowerShell encoded commands.
    if re.search(
        r"(?i)\bpowershell(?:\.exe)?\b.*(?:-enc|-encodedcommand)\b",
        text
    ):
        findings.append({
            "name": "Encoded PowerShell",
            "category": "obfuscation",
            "severity": "high",
            "evidence": "PowerShell encoded-command option",
            "description": "PowerShell appears to be using an encoded command."
        })

    # Detect long Base64-looking strings.
    base64_pattern = r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])"

    if re.search(base64_pattern, text):
        findings.append({
            "name": "Possible Base64 encoded content",
            "category": "obfuscation",
            "severity": "medium",
            "evidence": "Long Base64-like string",
            "description": "A long Base64-like string was detected."
        })

    # Detect excessive string concatenation.
    concatenation_count = len(re.findall(r'["\']\s*\+\s*["\']', text))

    if concatenation_count >= 3:
        findings.append({
            "name": "String concatenation obfuscation",
            "category": "obfuscation",
            "severity": "medium",
            "evidence": f"{concatenation_count} string concatenations",
            "description": "Multiple string concatenations may indicate simple obfuscation."
        })

    return findings


def analyze_text(text: str) -> dict[str, Any]:
    """
    Analyze submitted text or script content.

    The analyzer is deterministic and does not execute the submitted content.
    """

    findings = []

    if not text or not text.strip():
        return {
            "risk_level": "low",
            "risk_score": 0,
            "findings": [],
            "summary": "No content was supplied for analysis."
        }

    # Pattern-based detection.
    for rule in SUSPICIOUS_PATTERNS:
        match = re.search(rule["pattern"], text)

        if match:
            findings.append({
                "name": rule["name"],
                "category": rule["category"],
                "severity": rule["severity"],
                "evidence": match.group(0)[:200],
                "description": rule["description"]
            })

    # Keyword detection.
    for keyword in SUSPICIOUS_KEYWORDS:
        if re.search(re.escape(keyword), text, re.IGNORECASE):
            findings.append({
                "name": "Suspicious keyword",
                "category": "keyword",
                "severity": "medium",
                "evidence": keyword,
                "description": f"Suspicious keyword '{keyword}' detected."
            })

    # Obfuscation detection.
    findings.extend(detect_obfuscation(text))

    # Remove duplicate findings.
    unique_findings = []
    seen = set()

    for finding in findings:
        key = (
            finding["name"],
            finding["category"],
            finding["evidence"]
        )

        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)

    # Deterministic scoring.
    severity_points = {
        "low": 1,
        "medium": 3,
        "high": 5
    }

    risk_score = sum(
        severity_points.get(finding["severity"], 0)
        for finding in unique_findings
    )

    # Keep the score bounded.
    risk_score = min(risk_score, 100)

    if risk_score >= 8:
        risk_level = "high"
    elif risk_score >= 3:
        risk_level = "medium"
    else:
        risk_level = "low"

    if not unique_findings:
        summary = "No known suspicious static-analysis patterns were detected."
    else:
        summary = (
            f"Detected {len(unique_findings)} suspicious "
            f"static-analysis finding(s)."
        )

    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "findings": unique_findings,
        "summary": summary
    }