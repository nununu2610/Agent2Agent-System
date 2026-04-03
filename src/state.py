from typing import TypedDict

class AgentState(TypedDict):
    malware_name: str
    draft_report: str
    final_report: str
    feedback: str        
    iterations: int