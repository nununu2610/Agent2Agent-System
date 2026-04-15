import os
import json
import re
from langchain_groq import ChatGroq
from src.tools.rag_engine import load_db, query_rag
from src.state import AgentState

llm = ChatGroq(
    model="llama-3.1-8b-instant",
    temperature=0,
    api_key=os.getenv("GROQ_API_KEY")
)

db = load_db()


def clean_json(text):
    text = re.sub(r"```json|```", "", text)
    match = re.search(r"\{.*\}", text, re.DOTALL)
    return match.group(0) if match else text


# ===== VALIDATION HELPERS =====
def normalize_steps(steps):
    clean = []

    for s in steps:
        if isinstance(s, dict):
            # flatten dict
            for v in s.values():
                clean.append(str(v))
        else:
            clean.append(str(s))

    return clean


def has_duplicate_steps(steps):
    steps = normalize_steps(steps)
    return len(set([s.lower().strip() for s in steps])) != len(steps)


def has_generic_steps(steps):
    steps = normalize_steps(steps)

    bad_keywords = [
        "xóa", "quét", "antivirus",
        "delete", "scan"
    ]

    for s in steps:
        if any(k in s.lower() for k in bad_keywords):
            return True
    return False


def is_invalid_content(report):
    if not report:
        return True

    text = json.dumps(report).lower()
    bad = ["parse error", "...", "n/a", "unknown"]

    return any(b in text for b in bad)


def auditor_node(state: AgentState, external_llm=None):
    model = external_llm if external_llm else llm

    malware = state["malware_name"]
    draft = state["draft_report"]
    iterations = state.get("iterations", 0)

    # ===== RAG =====
    docs = query_rag(db, malware, "mitigation")
    context = "\n".join([d.page_content for d in docs]) if docs else ""

    prompt = f"""
Bạn là Auditor an ninh mạng.

DRAFT REPORT:
{draft}

INTERNAL MITIGATION DATA:
{context}

YÊU CẦU:
1. Báo cáo phải có:
   - incident_summary hợp lý
   - technical_analysis có nội dung thực
   - ít nhất 2 bước mitigation từ dữ liệu nội bộ

2. Nếu thiếu → REJECT
3. Nếu đủ → APPROVE

 KHÔNG được:
- parse error
- nội dung rỗng
- mitigation chung chung

 CHỈ TRẢ JSON:

{{
  "decision": "APPROVE/REJECT",
  "violations": [],
  "required_fixes": [],
  "final_report": {{
    "incident_summary": "...",
    "technical_analysis": "...",
    "response_steps": []
  }},
  "confidence": "LOW/MEDIUM/HIGH"
}}
"""

    res = model.invoke(prompt).content

    print("\n[DEBUG AUDITOR RAW OUTPUT]:\n", res)

    try:
        clean_res = clean_json(res)
        data = json.loads(clean_res)
    except Exception as e:
        print("[ERROR PARSE]:", e)
        data = {
            "decision": "REJECT",
            "violations": ["parse_error"],
            "required_fixes": ["invalid JSON"],
            "final_report": {},
            "confidence": "LOW"
        }

    report = data.get("final_report", {})
    steps = report.get("response_steps", [])

    if is_invalid_content(report):
        data["decision"] = "REJECT"
        data["violations"].append("invalid_content")
        data["required_fixes"].append("fix empty or placeholder content")

    if len(steps) < 2:
        data["decision"] = "REJECT"
        data["violations"].append("not_enough_mitigation")

    if has_duplicate_steps(steps):
        data["decision"] = "REJECT"
        data["violations"].append("duplicate_mitigation")

    if has_generic_steps(steps):
        data["decision"] = "REJECT"
        data["violations"].append("generic_mitigation")
        data["required_fixes"].append("use specific mitigation steps")

    return {
        "audit_result": data,
        "final_report": data.get("final_report", {}),
        "feedback": data.get("required_fixes", []),
        "iterations": iterations + 1
    }