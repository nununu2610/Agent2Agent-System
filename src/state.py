from typing import TypedDict, Dict, Any, List, Optional

class TaskSpec(TypedDict):
    """Structured task dispatched by Orchestrator to a Worker."""
    task_id: str
    worker: str          # "rag" | "search" | "analyst" | "auditor" | "judge"
    instruction: str     # Locked, sanitized instruction text
    context: Dict[str, Any]

class AgentState(TypedDict):
    # ── Input ──
    malware_name: str
    raw_user_input: str          # Original, untouched input for audit trail

    # ── Security Gate ──
    intent_valid: bool
    intent_reason: str           # Why gate passed or blocked
    sanitized_input: str         # Cleaned input forwarded to Orchestrator

    # ── Orchestrator ──
    task_plan: List[TaskSpec]    # Sub-tasks decomposed by Orchestrator
    intent_fingerprint: str      # Hash/summary of original intent, passed to all workers

    # ── Worker Outputs ──
    rag_context: str
    web_context: str
    draft_report: Dict[str, Any]
    audit_result: Dict[str, Any]
    judge_result: Dict[str, Any]

    # ── Control ──
    final_report: Dict[str, Any]
    feedback: List[str]
    iterations: int
    attack_detected: bool        # Flag set if ASI01/injection detected
    attack_payload: str          # Captured payload for forensics
