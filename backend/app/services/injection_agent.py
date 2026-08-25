import os
import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Check for google-genai availability
try:
    from google import genai
    from google.genai import types
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False


class InjectionAnalysisAgent:
    """
    AI Agent that takes heuristic telemetry findings and synthesizes
    adversary intent, MITRE ATT&CK T1055 attack flow, and actionable SOC remediation.
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.client = None
        if HAS_GENAI and self.api_key:
            try:
                self.client = genai.Client(api_key=self.api_key)
            except Exception as e:
                logger.warning(f"Failed to initialize GenAI client: {e}")

    def generate_expert_fallback(self, heuristic_data: Dict[str, Any], raw_log: str) -> Dict[str, Any]:
        """Deterministic fallback synthesis if LLM is unavailable or offline."""
        detected_apis = heuristic_data.get("detected_apis", [])
        techniques = heuristic_data.get("mitre_techniques", [])
        meta = heuristic_data.get("process_metadata", {})

        src = meta.get("source_process") or "Unknown / External Process"
        tgt = meta.get("target_process") or "Legitimate Target Process"
        
        primary_tech = techniques[0]["technique_name"] if techniques else "Suspicious Code Injection / Memory Tampering"
        tech_id = techniques[0]["technique_id"] if techniques else "T1055"

        summary = (
            f"The forensic trace exhibits characteristics of {primary_tech} ({tech_id}). "
            f"Observed memory allocation and thread execution operations initiated by '{src}' "
            f"targeting '{tgt}'."
        )

        steps = [
            f"1. Memory Allocation: Attacker allocates virtual address space using {', '.join([a for a in detected_apis if 'Alloc' in a or 'Map' in a] or ['VirtualAllocEx'])}.",
            f"2. Payload Injection: Malicious binary payload or shellcode is written into target process address space.",
            f"3. Thread Execution: Execution hijacked or spawned using {', '.join([a for a in detected_apis if 'Thread' in a or 'APC' in a] or ['CreateRemoteThread'])}."
        ]

        remediations = [
            f"Isolate host endpoint immediately from network to prevent lateral movement.",
            f"Terminate source process (PID {meta.get('source_pid', 'Unknown')}) and investigate parent process lineage.",
            f"Capture full memory dump of target process '{tgt}' for shellcode extraction.",
            f"Deploy EDR block rule for remote thread creation targeting system binaries."
        ]

        return {
            "attack_narrative": summary,
            "attack_chain_steps": steps,
            "adversary_objective": "Evasion of Endpoint Detection and Response (EDR) and execution of unbacked payload in trusted process memory.",
            "remediation_playbook": remediations,
            "confidence_score": 0.88 if techniques else 0.65,
            "agent_mode": "Heuristic Rule Engine (Fallback)"
        }

    async def analyze_injection(self, heuristic_data: Dict[str, Any], raw_log: str) -> Dict[str, Any]:
        """
        Executes reasoning over heuristic findings using LLM or Rule Engine.
        """
        if not self.client:
            return self.generate_expert_fallback(heuristic_data, raw_log)

        prompt = f"""
You are an expert Tier-3 SOC Incident Response Specialist analyzing a potential Malware Process Injection event (MITRE ATT&CK T1055).

### Deterministic Engine Findings:
- Detected APIs: {heuristic_data.get('detected_apis', [])}
- Identified Techniques: {json.dumps(heuristic_data.get('mitre_techniques', []), indent=2)}
- Extracted Process Metadata: {json.dumps(heuristic_data.get('process_metadata', {}), indent=2)}
- Overall Heuristic Risk: {heuristic_data.get('risk_level', 'UNKNOWN')}

### Raw Event / Telemetry Log:
\"\"\"
{raw_log[:2000]}
\"\"\"

Analyze this activity and return a strictly valid JSON object with the following fields:
{{
  "attack_narrative": "A concise 2-3 sentence technical summary of the observed injection attempt.",
  "attack_chain_steps": [
    "Step 1 description (e.g., Process target opened)",
    "Step 2 description (e.g., Memory allocation with RWX permissions)",
    "Step 3 description (e.g., Execution trigger via remote thread)"
  ],
  "adversary_objective": "Why the attacker performed this action (e.g., Credential Dumping from LSASS, Defense Evasion, Persistence).",
  "remediation_playbook": [
    "Specific tactical action 1",
    "Specific tactical action 2",
    "Specific tactical action 3"
  ],
  "confidence_score": 0.95
}}
"""

        try:
            response = self.client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.2,
                    response_mime_type="application/json"
                )
            )
            parsed_result = json.loads(response.text)
            parsed_result["agent_mode"] = "AI Agent (Gemini Reasoning Engine)"
            return parsed_result
        except Exception as e:
            logger.error(f"GenAI reasoning error: {e}. Falling back to heuristic synthesis.")
            return self.generate_expert_fallback(heuristic_data, raw_log)