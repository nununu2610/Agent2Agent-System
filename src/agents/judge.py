import os
import json
import re
from langchain_groq import ChatGroq
from src.state import AgentState

llm = ChatGroq(
    model="llama-3.1-8b-instant",
    temperature=0,
    api_key=os.getenv("GROQ_API_KEY")
)


# ===== CLEAN JSON =====
def clean_json(text):
    text = re.sub(r"```json|```", "", text)
    match = re.search(r"\{.*\}", text, re.DOTALL)
    return match.group(0) if match else text


# ===== CHECK WEAK MITIGATION =====
# ===== CHECK WEAK MITIGATION =====
def has_weak_steps(steps):
    weak_keywords = [
        "xóa", "quét", "antivirus",
        "delete", "scan", "remove malware"
    ]
    for s in steps:
        step_text = ""
        if isinstance(s, dict):
            step_text = " ".join(str(v) for v in s.values())
        else:
            step_text = str(s)

        if any(w in step_text.lower() for w in weak_keywords):
            return True
    return False


def judge_node(state: AgentState, external_llm=None):
    model = external_llm if external_llm else llm

    draft = state["draft_report"]
    audit = state["audit_result"]
    final_report = state.get("final_report", {})

    prompt = f"""
Bạn là Judge (cấp cao nhất).

QUAN TRỌNG:
- CHỈ trả về JSON
- KHÔNG markdown
- KHÔNG giải thích
- KHÔNG text ngoài JSON

DRAFT:
{draft}

AUDIT RESULT:
{audit}

NHIỆM VỤ:
- Không được tin Auditor tuyệt đối
- Tự đánh giá lại toàn bộ báo cáo

QUY TẮC:
1. Nếu confidence = LOW → REJECT
2. Nếu có violations → REJECT
3. Nếu có issues → REJECT
4. Nếu mitigation yếu hoặc chung chung → REJECT

FORMAT:
{{
  "final_decision": "APPROVE/REJECT",
  "risk_level": "LOW/MEDIUM/HIGH",
  "issues": [],
  "trust_score": 0.0,
  "reason": "..."
}}
"""

    res = model.invoke(prompt).content

    print("\n[DEBUG JUDGE RAW OUTPUT]:\n", res)

    try:
        clean_res = clean_json(res)
        data = json.loads(clean_res)
    except Exception as e:
        print("[ERROR PARSE]:", e)
        data = {
            "final_decision": "REJECT",
            "risk_level": "HIGH",
            "issues": ["parse_error"],
            "trust_score": 0.0,
            "reason": "parse fail"
        }


    if audit.get("confidence") in ["LOW", None]:
        data["final_decision"] = "REJECT"
        data["reason"] = "Low confidence from Auditor"
        data["trust_score"] = 0.0

    if audit.get("violations"):
        data["final_decision"] = "REJECT"
        data["issues"] = audit.get("violations", [])
        data["reason"] = "Violations detected by Auditor"
        data["trust_score"] = 0.0

    if data.get("issues"):
        data["final_decision"] = "REJECT"

    steps = final_report.get("response_steps", [])
    if has_weak_steps(steps):
        data["final_decision"] = "REJECT"
        data["reason"] = "Weak or generic mitigation steps"
        data["trust_score"] = 0.0

    return {"judge_result": data}