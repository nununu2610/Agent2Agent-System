import os
import sys
from dotenv import load_dotenv
from langgraph.graph import StateGraph, END
from langchain_groq import ChatGroq

load_dotenv()

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.state import AgentState
from src.agents.analyst import analyst_node
from src.agents.auditor import auditor_node
from src.agents.judge import judge_node

llm = ChatGroq(
    model="llama-3.1-8b-instant",
    temperature=0
)

def should_continue(state: AgentState):
    judge = state.get("judge_result", {})
    decision = judge.get("final_decision", "REJECT")

    if decision == "APPROVE" or state.get("iterations", 0) >= 3:
        return "end"
    return "continue"


def build_app():
    workflow = StateGraph(AgentState)

    workflow.add_node("analyst", analyst_node)
    workflow.add_node("auditor", lambda s: auditor_node(s, llm))
    workflow.add_node("judge", lambda s: judge_node(s, llm))

    workflow.set_entry_point("analyst")

    workflow.add_edge("analyst", "auditor")
    workflow.add_edge("auditor", "judge")

    workflow.add_conditional_edges(
        "judge",
        should_continue,
        {
            "continue": "analyst",
            "end": END
        }
    )

    return workflow.compile()


if __name__ == "__main__":
    app = build_app()

    state = {
        "malware_name": "ransomware",
        "draft_report": {},
        "audit_result": {},
        "judge_result": {},
        "final_report": {},
        "feedback": [],
        "iterations": 0,
        "attack_mode": "normal"
    }

    result = app.invoke(state)

    print("\n=== FINAL RESULT ===")
    print(result["judge_result"])

    if result["judge_result"]["final_decision"] == "APPROVE":
        print("\n=== FINAL REPORT ===")
        print(result["final_report"])