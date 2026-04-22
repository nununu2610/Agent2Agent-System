"""
Main Graph — Orchestrator-Worker (Star) Topology
=================================================
Hệ thống phân tích mã độc sử dụng kiến trúc điều phối tập trung.
Đã tối ưu chạy song song (Multi-threading) để tránh lỗi Concurrent Update.
"""

import concurrent.futures
import os
import sys
from dotenv import load_dotenv
from langgraph.graph import StateGraph, END

# Load biến môi trường và thiết lập đường dẫn hệ thống
load_dotenv()
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.state import AgentState
from src.agents.intent_gate import intent_gate_node
from src.agents.orchestrator import orchestrator_node, synthesizer_node
from src.agents.data_workers import rag_worker_node, search_worker_node
from src.agents.analyst import analyst_worker_node
from src.agents.evaluator import evaluator_worker_node

# ── Routing functions ─────────────────────────────────────────────────────────

def route_after_gate(state: AgentState) -> str:
    """Điều hướng sau bước kiểm tra Intent Gate."""
    if state.get("attack_detected") or not state.get("intent_valid", False):
        print(f"\n[ROUTER] Intent gate BLOCKED: {state.get('intent_reason')}")
        return "blocked"
    return "orchestrator"

def route_after_evaluator(state: AgentState) -> str:
    """Điều hướng dựa trên phán quyết của Evaluator (CISO)."""
    eval_res = state.get("evaluator_result", {})
    decision = eval_res.get("final_decision", "REJECT")
    iterations = state.get("iterations", 0)
    
    if decision == "APPROVE" or iterations >= 3:
        return "synthesizer"
    
    print(f"\n[ROUTER] Evaluator REJECTED (Round {iterations}) — re-running Orchestrator")
    return "orchestrator"

def build_blocked_state_node(state: AgentState) -> dict:
    """Node kết thúc khi Intent Gate phát hiện rủi ro bảo mật."""
    return {
        "final_report": {
            "error": "Request blocked by Intent Validation Gate",
            "reason": state.get("intent_reason", "Unknown"),
            "attack_detected": state.get("attack_detected", False),
        },
        "evaluator_result": {
            "final_decision": "BLOCKED",
            "reason": state.get("intent_reason"),
            "risk_level": "CRITICAL" if state.get("attack_detected") else "HIGH"
        }
    }

# ── Parallel Execution Node ──────────────────────────────────────────────────

def parallel_data_node(state: AgentState) -> dict:
    """
    Kỹ thuật Threading: Chạy RAG và Search song song trong 1 Node duy nhất.
    Giúp tăng tốc độ thu thập dữ liệu mà không gây lỗi xung đột State.
    """
    print("\n[DATA WORKERS] ⚡ Đang thu thập dữ liệu RAG và Web song song...")
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Chạy đồng thời 2 worker
        future_rag = executor.submit(rag_worker_node, state)
        future_search = executor.submit(search_worker_node, state)

        # Đợi và gộp kết quả
        rag_res = future_rag.result()
        search_res = future_search.result()

    return {**rag_res, **search_res}

# ── Graph builder ─────────────────────────────────────────────────────────────

def build_app():
    workflow = StateGraph(AgentState)

    # --- Nodes ---
    workflow.add_node("intent_gate", intent_gate_node)
    workflow.add_node("blocked", build_blocked_state_node)
    workflow.add_node("orchestrator", orchestrator_node)
    
    # Node song song mới thay thế cho 2 node cũ
    workflow.add_node("data_gathering", parallel_data_node)
    
    workflow.add_node("analyst_worker", analyst_worker_node)
    workflow.add_node("evaluator_worker", evaluator_worker_node)
    workflow.add_node("synthesizer", synthesizer_node)

    # --- Entry ---
    workflow.set_entry_point("intent_gate")

    # --- Edges ---
    # 1. Gate check
    workflow.add_conditional_edges(
        "intent_gate",
        route_after_gate,
        {
            "orchestrator": "orchestrator",
            "blocked": "blocked",
        }
    )
    workflow.add_edge("blocked", END)

    # 2. Main Flow: Orchestrator -> Parallel Data -> Analyst -> Evaluator
    workflow.add_edge("orchestrator", "data_gathering")
    workflow.add_edge("data_gathering", "analyst_worker")
    workflow.add_edge("analyst_worker", "evaluator_worker")

    # 3. Judge Loop: Evaluator -> (Synthesizer | Orchestrator)
    workflow.add_conditional_edges(
        "evaluator_worker",
        route_after_evaluator,
        {
            "synthesizer": "synthesizer",
            "orchestrator": "orchestrator",
        }
    )
    workflow.add_edge("synthesizer", END)

    return workflow.compile()

# --- Global App Instance ---
app = build_app()

if __name__ == "__main__":
    print("Hệ thống Multi-Agent Malware Intelligence đã sẵn sàng.")
    print("Vui lòng khởi chạy Giao diện thông qua gui_app.py")