"""
Data Retrieval Workers
======================
RAG Worker và Web Search Worker.

Khác với pipeline cũ: các worker này KHÔNG nhận raw user input.
Họ chỉ nhận TaskSpec JSON từ Orchestrator, bao gồm:
  - instruction: sanitized, structured
  - context.malware_name: đã được validate
  - context.intent_fingerprint: để verify task nguồn gốc hợp lệ

Đây là cơ chế "worker isolation" trong Star topology.
"""

import os
from langchain_community.tools import DuckDuckGoSearchRun
from src.tools.rag_engine import load_db, query_rag


_db = None

def get_db():
    global _db
    if _db is None:
        _db = load_db()
    return _db


def verify_task_fingerprint(task: dict, state_fingerprint: str) -> bool:
    """
    Worker verify rằng TaskSpec nhận được có intent_fingerprint
    khớp với state — phát hiện nếu task bị tamper giữa Orchestrator và Worker.
    """
    task_fp = task.get("context", {}).get("intent_fingerprint", "")
    if task_fp != state_fingerprint:
        print(f"[SECURITY] Fingerprint mismatch! Task: {task_fp} | State: {state_fingerprint}")
        return False
    return True


def find_task(task_plan: list, worker_name: str) -> dict:
    """Tìm TaskSpec cho worker cụ thể trong task plan."""
    for task in task_plan:
        if task.get("worker") == worker_name:
            return task
    return {}


def rag_worker_node(state: dict) -> dict:
    """
    LangGraph node: RAG Worker.
    Nhận task từ Orchestrator, verify fingerprint, query FAISS.
    """
    task_plan = state.get("task_plan", [])
    fingerprint = state.get("intent_fingerprint", "")
    
    task = find_task(task_plan, "rag")
    
    if not task:
        print("[RAG WORKER] No task assigned by Orchestrator")
        return {"rag_context": ""}
    
    # ── Security: verify task integrity ──
    if not verify_task_fingerprint(task, fingerprint):
        print("[RAG WORKER] ⚠️  Task fingerprint invalid — refusing to execute")
        return {"rag_context": "WORKER_REFUSED: fingerprint_mismatch"}

    # ── Execute task ──
    malware_name = task["context"]["malware_name"]
    doc_types = task["context"].get("doc_types", ["mitigation"])
    top_k = task["context"].get("top_k", 5)

    print(f"\n[RAG WORKER] Executing task {task['task_id']} for: {malware_name}")

    try:
        db = get_db()
        all_docs = []
        for doc_type in doc_types:
            docs = query_rag(db, malware_name, doc_type, k=top_k)
            all_docs.extend(docs)
        
        context = "\n".join([f"[{d.metadata.get('type','?')}] {d.page_content}" for d in all_docs])
        print(f"[RAG WORKER] Retrieved {len(all_docs)} documents")
        return {"rag_context": context or "No relevant documents found in KB"}
    except Exception as e:
        print(f"[RAG WORKER] Error: {e}")
        return {"rag_context": f"RAG retrieval error: {e}"}


def search_worker_node(state: dict) -> dict:
    """
    LangGraph node: Web Search Worker.
    """
    task_plan = state.get("task_plan", [])
    fingerprint = state.get("intent_fingerprint", "")
    
    task = find_task(task_plan, "search")
    
    if not task:
        print("[SEARCH WORKER] No task assigned by Orchestrator")
        return {"web_context": ""}
    
    if not verify_task_fingerprint(task, fingerprint):
        print("[SEARCH WORKER] ⚠️  Task fingerprint invalid — refusing to execute")
        return {"web_context": "WORKER_REFUSED: fingerprint_mismatch"}

    query = task["context"].get("query", task["context"]["malware_name"])
    print(f"\n[SEARCH WORKER] Executing task {task['task_id']}: {query[:60]}")

    try:
        search = DuckDuckGoSearchRun()
        result = search.invoke(query)
        

        short_result = result[:1500] if result else ""
        
        print(f"[SEARCH WORKER] Thu hẹp dữ liệu xuống còn {len(short_result)} ký tự")
        return {"web_context": short_result}
    except Exception as e:
        print(f"[SEARCH WORKER] Error: {e}")
        return {"web_context": f"Web search error: {e}"}
