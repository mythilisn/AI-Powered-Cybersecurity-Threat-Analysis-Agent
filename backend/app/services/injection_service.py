import re
from typing import Dict, List, Any, Optional

class InjectionDetectorService:
    """
    Heuristic engine to analyze process logs, Sysmon traces, and API sequences
    for MITRE ATT&CK T1055 (Process Injection) sub-techniques.
    """

    # Critical Windows API calls cataloged by injection phase
    API_SIGNATURES = {
        "allocation": [
            r"\bVirtualAllocEx\b",
            r"\bNtAllocateVirtualMemory\b",
            r"\bZwAllocateVirtualMemory\b",
            r"\bVirtualProtectEx\b",
        ],
        "writing": [
            r"\bWriteProcessMemory\b",
            r"\bNtWriteVirtualMemory\b",
            r"\bZwWriteVirtualMemory\b",
            r"\bMapViewOfFile\b",
            r"\bNtMapViewOfSection\b",
        ],
        "execution": [
            r"\bCreateRemoteThread\b",
            r"\bNtCreateThreadEx\b",
            r"\bRtlCreateUserThread\b",
            r"\bQueueUserAPC\b",
            r"\bNtQueueApcThread\b",
            r"\bSetThreadContext\b",
            r"\bResumeThread\b",
        ],
        "process_access": [
            r"\bOpenProcess\b",
            r"\bNtOpenProcess\b",
            r"\bCreateProcess(A|W)?\b",
            r"\bCreateProcessWithLogonW\b",
        ]
    }

    # Known MITRE ATT&CK T1055 Sub-Technique Signatures
    TECHNIQUE_RULES = [
        {
            "id": "T1055.001",
            "name": "Dynamic-link Library Injection",
            "required_apis": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
            "optional_apis": ["LoadLibraryA", "LoadLibraryW", "OpenProcess"],
            "severity": "HIGH",
            "description": "Allocates memory in a remote process, writes the path of a malicious DLL, and invokes CreateRemoteThread pointing to LoadLibrary."
        },
        {
            "id": "T1055.012",
            "name": "Process Hollowing",
            "required_apis": ["CreateProcess", "NtUnmapViewOfSection", "VirtualAllocEx", "WriteProcessMemory", "SetThreadContext", "ResumeThread"],
            "optional_apis": ["ZwUnmapViewOfSection", "GetThreadContext"],
            "severity": "CRITICAL",
            "description": "Spawns a legitimate process in a suspended state, unmaps its original image, writes a malicious payload, redirects the entry point, and resumes execution."
        },
        {
            "id": "T1055.004",
            "name": "Asynchronous Procedure Call (APC) Injection",
            "required_apis": ["OpenThread", "QueueUserAPC"],
            "optional_apis": ["VirtualAllocEx", "WriteProcessMemory", "NtQueueApcThread"],
            "severity": "HIGH",
            "description": "Queues a malicious function to the APC queue of a target thread, triggering execution when the thread enters an alertable state."
        },
        {
            "id": "T1055.003",
            "name": "Thread Execution Hijacking",
            "required_apis": ["OpenThread", "SuspendThread", "VirtualAllocEx", "WriteProcessMemory", "SetThreadContext", "ResumeThread"],
            "optional_apis": ["GetThreadContext"],
            "severity": "HIGH",
            "description": "Suspends an existing thread in a target process, alters its instruction pointer (EIP/RIP) to point to injected shellcode, and resumes execution."
        }
    ]

    def __init__(self):
        pass

    def extract_apis(self, text: str) -> List[str]:
        """Scans raw log text or API sequences and identifies all observed Windows APIs."""
        found_apis = set()
        for category, patterns in self.API_SIGNATURES.items():
            for pattern in patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    found_apis.add(match if isinstance(match, str) else match[0])

        # Also search general API names
        general_patterns = [
            r"\b(LoadLibrary[AW]?|GetProcAddress|NtUnmapViewOfSection|ZwUnmapViewOfSection|OpenThread|SuspendThread|GetThreadContext)\b"
        ]
        for pattern in general_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for m in matches:
                found_apis.add(m)

        return sorted(list(found_apis))

    def extract_process_metadata(self, text: str) -> Dict[str, Any]:
        """Extracts source process, target process, PIDs, and memory flags from logs."""
        metadata = {
            "source_process": None,
            "source_pid": None,
            "target_process": None,
            "target_pid": None,
            "memory_protection": None,
            "event_type": None
        }

        # Source process extraction
        src_proc = re.search(r"(?:SourceImage|ParentImage|AttackerProcess|CallerProcess)\s*[:=]\s*([^\r\n,]+)", text, re.IGNORECASE)
        if src_proc:
            metadata["source_process"] = src_proc.group(1).strip()

        # Target process extraction
        tgt_proc = re.search(r"(?:TargetImage|VictimProcess|TargetProcess|Image)\s*[:=]\s*([^\r\n,]+)", text, re.IGNORECASE)
        if tgt_proc:
            metadata["target_process"] = tgt_proc.group(1).strip()

        # PIDs
        src_pid = re.search(r"(?:SourceProcessId|ParentProcessId|CallerPID)\s*[:=]\s*(\d+)", text, re.IGNORECASE)
        if src_pid:
            metadata["source_pid"] = int(src_pid.group(1))

        tgt_pid = re.search(r"(?:TargetProcessId|VictimPID|TargetPID|ProcessId)\s*[:=]\s*(\d+)", text, re.IGNORECASE)
        if tgt_pid:
            metadata["target_pid"] = int(tgt_pid.group(1))

        # Memory protection flags (e.g. PAGE_EXECUTE_READWRITE)
        mem_prot = re.search(r"\b(PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_READ|PAGE_READWRITE|0x40|0x20)\b", text, re.IGNORECASE)
        if mem_prot:
            metadata["memory_protection"] = mem_prot.group(1)

        # Sysmon / Event indicators
        if "CreateRemoteThread" in text or "EventID: 8" in text or "Event ID 8" in text:
            metadata["event_type"] = "Sysmon Event 8 (CreateRemoteThread Detected)"
        elif "EventID: 7" in text or "Image loaded" in text:
            metadata["event_type"] = "Sysmon Event 7 (Image Loaded / DLL Load)"

        return metadata

    def classify_technique(self, apis_found: List[str]) -> List[Dict[str, Any]]:
        """Matches detected APIs against MITRE ATT&CK sub-techniques."""
        matches = []
        apis_lower = [api.lower() for api in apis_found]

        for rule in self.TECHNIQUE_RULES:
            required_count = len(rule["required_apis"])
            matched_req = [
                req for req in rule["required_apis"]
                if any(req.lower() in found for found in apis_lower)
            ]

            # Calculate match confidence
            score = len(matched_req) / required_count if required_count > 0 else 0
            
            if score >= 0.6:  # Over 60% of required sequence matched
                confidence = "HIGH" if score >= 0.85 else "MEDIUM"
                matches.append({
                    "technique_id": rule["id"],
                    "technique_name": rule["name"],
                    "severity": rule["severity"],
                    "confidence": confidence,
                    "matched_apis": matched_req,
                    "missing_apis": [req for req in rule["required_apis"] if req not in matched_req],
                    "description": rule["description"]
                })

        return sorted(matches, key=lambda x: (x["confidence"] == "HIGH", x["severity"] == "CRITICAL"), reverse=True)

    def analyze(self, raw_input: str) -> Dict[str, Any]:
        """Runs complete heuristic extraction and classification."""
        apis_found = self.extract_apis(raw_input)
        process_meta = self.extract_process_metadata(raw_input)
        techniques = self.classify_technique(apis_found)

        is_suspicious = len(techniques) > 0 or len(apis_found) >= 2

        return {
            "is_suspicious": is_suspicious,
            "detected_apis": apis_found,
            "process_metadata": process_meta,
            "mitre_techniques": techniques,
            "risk_level": "CRITICAL" if any(t["severity"] == "CRITICAL" for t in techniques) else ("HIGH" if techniques else ("MEDIUM" if apis_found else "LOW"))
        }