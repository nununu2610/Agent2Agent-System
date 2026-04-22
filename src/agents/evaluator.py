import os
import json
import re
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from src.tools.rag_engine import load_db, query_rag
from src.state import AgentState

load_dotenv()

llm = ChatGroq(
    model="llama-3.3-70b-versatile",
    temperature=0,  # Temperature = 0 để đánh giá khách quan nhất
    api_key=os.getenv("GROQ_API_KEY")
)

_db = None

def get_db():
    global _db
    if _db is None:
        _db = load_db()
    return _db

def clean_json(text):
    text = re.sub(r"```json|```", "", text)
    match = re.search(r"\{.*\}", text, re.DOTALL)
    return match.group(0) if match else text

# ===== DETERMINISTIC GUARDRAILS (PYTHON LOGIC) =====
def normalize_steps(steps):
    clean = []
    for s in steps:
        if isinstance(s, dict):
            for v in s.values(): clean.append(str(v))
        else:
            clean.append(str(s))
    return clean

def has_duplicate_steps(steps):
    steps = normalize_steps(steps)
    return len(set([s.lower().strip() for s in steps])) != len(steps)

def has_generic_steps(steps):
    steps = normalize_steps(steps)
    # Tổng hợp tất cả các từ cấm
    bad_keywords = [
        "xóa", "quét", "antivirus", "delete", "scan", 
        "remove malware", "generic", "standard tool", "clean system"
    ]
    for s in steps:
        if any(k in s.lower() for k in bad_keywords): return True
    return False

def is_invalid_content(report):
    if not report: return True
    text = json.dumps(report).lower()
    return any(b in text for b in ["parse error", "...", "n/a", "unknown", "placeholder"])

# ===== EVALUATOR NODE =====
def evaluator_worker_node(state: AgentState, external_llm=None):
    model = external_llm if external_llm else llm
    malware = state.get("malware_name", "")
    draft = state.get("draft_report", {})
    
    # 1. Thu thập dữ liệu đối soát
    db = get_db()
    docs = query_rag(db, malware, "mitigation")
    context = "\n".join([d.page_content for d in docs]) if docs else "No specific internal mitigation data."

    # 2. LLM Evaluation (Giữ prompt Tiếng Anh để format chuẩn)
    prompt = f"""
You are the Chief Information Security Officer (CISO). Evaluate the DRAFT REPORT.

DRAFT REPORT:
{json.dumps(draft, indent=2)}

INTERNAL RAG MITIGATION DATA:
{context}

RULES:
1. Validate technical depth. Reject if generic advice (e.g., "run antivirus") is used.
2. Ensure values are in Vietnamese, but JSON keys are English.
3. If anything is wrong, decision MUST be REJECT and you must list `required_fixes`.

OUTPUT FORMAT (JSON ONLY):
{{
  "final_decision": "APPROVE/REJECT",
  "risk_level": "LOW/MEDIUM/HIGH/CRITICAL",
  "violations": [],
  "required_fixes": [],
  "confidence": "LOW/MEDIUM/HIGH"
}}
"""
    res = model.invoke(prompt).content
    print("\n[EVALUATOR] Analyzing draft report...")

    try:
        data = json.loads(clean_json(res))
    except Exception as e:
        print("[EVALUATOR ERROR] Parse failed:", e)
        data = {"final_decision": "REJECT", "violations": ["parse_error"], "required_fixes": ["Return valid JSON"], "confidence": "LOW"}

    # Đảm bảo các mảng tồn tại để tránh lỗi KeyError
    if "violations" not in data or not isinstance(data["violations"], list): data["violations"] = []
    if "required_fixes" not in data or not isinstance(data["required_fixes"], list): data["required_fixes"] = []

    # 3. Python Overrides (Code luật pháp)
    steps = draft.get("response_steps", [])
    
    if is_invalid_content(draft):
        data["final_decision"] = "REJECT"
        data["violations"].append("invalid_content")
        data["required_fixes"].append("Do not use placeholders like N/A or ...")

    if len(steps) < 2:
        data["final_decision"] = "REJECT"
        data["violations"].append("insufficient_mitigation_steps")
        data["required_fixes"].append("Provide at least 2 highly specific mitigation steps.")

    if has_duplicate_steps(steps):
        data["final_decision"] = "REJECT"
        data["violations"].append("duplicate_steps")
        data["required_fixes"].append("Remove duplicated steps.")

    if has_generic_steps(steps):
        data["final_decision"] = "REJECT"
        data["violations"].append("generic_advice_detected")
        data["required_fixes"].append("CẤM dùng từ 'quét', 'xóa', 'antivirus'. Hãy dùng biện pháp cụ thể như 'Cô lập tiến trình', 'Chặn IP'.")

    if data.get("violations"):
        data["final_decision"] = "REJECT"

    # 4. Trả về State (Cộng iterations ở đây)
    current_iterations = state.get("iterations", 0)
    
    return {
        "evaluator_result": data,
        "draft_report": draft, # Truyền nguyên bản nháp đi
        "feedback": data.get("required_fixes", []),
        "iterations": current_iterations + 1 # <--- ĐẾM NHỊP 
    }