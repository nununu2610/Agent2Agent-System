from typing import TypedDict, Dict, Any, List

class AgentState(TypedDict):
    malware_name: str

    # Analyst
    draft_report: Dict[str, Any]

    # Auditor
    audit_result: Dict[str, Any]
    final_report: Dict[str, Any]

    # Judge
    judge_result: Dict[str, Any]

    # Control
    feedback: List[str]
    iterations: int
    attack_mode: str