"""
Analyst Worker
==============
Trong kiến trúc mới:
  - Không khởi tạo web search hay RAG riêng
  - Nhận context đã được thu thập bởi Data Workers
  - Chỉ nhận task qua TaskSpec từ Orchestrator (đã sanitize)
  - Verify intent_fingerprint trước khi generate report

So với pipeline cũ:
  - Pipeline: analyst nhận raw malware_name từ state → dễ inject
  - Star: analyst nhận task.instruction (Orchestrator đã wrap) + pre-fetched context
"""

import os
import re
import json
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from src.state import AgentState

load_dotenv()

ANALYST_SYSTEM_PROMPT = """You are a Level 3 SOC Malware Expert. 
STRICT RULES:
1. INTERNAL KEYS MUST BE ENGLISH: 'incident_summary', 'technical_analysis', 'infection_vector', 'behavior', 'impact', 'response_steps', 'phase', 'description', 'steps'.
2. VALUES MUST BE VIETNAMESE: All descriptions and analysis must be in detailed Vietnamese.
3. NO GENERIC STEPS: Do not use 'quét virus', 'xóa file'. Use 'Block C2 IP', 'Isolate PID', etc.
4. MINIMUM LENGTH: 'behavior' must be at least 150 words.
"""

llm = ChatGroq(
    model="llama-3.3-70b-versatile",
    temperature=0.1,
    api_key=os.getenv("GROQ_API_KEY")
)


def find_task(task_plan: list, worker_name: str) -> dict:
    for task in task_plan:
        if task.get("worker") == worker_name:
            return task
    return {}


def analyst_worker_node(state: dict) -> dict:
    """
    LangGraph node: Analyst Worker.
    
    Key security difference vs old pipeline:
    - Reads task instruction from Orchestrator's TaskSpec
    - Uses pre-fetched rag_context and web_context (không tự fetch)
    - Verifies intent_fingerprint
    """
    task_plan = state.get("task_plan", [])
    fingerprint = state.get("intent_fingerprint", "")

    task = find_task(task_plan, "analyst")
    if not task:
        return {"draft_report": {}, "feedback": []}

    # Verify fingerprint
    task_fp = task.get("context", {}).get("intent_fingerprint", "")
    if task_fp != fingerprint:
        print("[ANALYST] ⚠️  Fingerprint mismatch — refusing")
        return {"draft_report": {}, "feedback": ["analyst_refused_fingerprint_mismatch"]}

    malware_name = task["context"]["malware_name"]
    feedback = task["context"].get("feedback", [])
    rag_context = state.get("rag_context", "")
    web_context = state.get("web_context", "")
    feedback_text = "; ".join([str(f) for f in feedback]) if feedback else "None"

    print(f"\n[ANALYST WORKER] Generating report for: {malware_name}")

    # Note: malware_name đã được sanitize bởi Intent Gate + Orchestrator
    # Context (rag/web) được cung cấp bởi Data Workers, không từ user
    prompt = f"""
PHÂN TÍCH MÃ ĐỘC: {malware_name}

DỮ LIỆU THU THẬP:
- RAG: {state.get('rag_context', '')[:800]}
- WEB: {state.get('web_context', '')[:1000]}

PHẢN HỒI CẦN SỬA (LÝ DO BỊ REJECT VÒNG TRƯỚC):
{feedback_text[:500]}

YÊU CẦU CHI TIẾT:
- Viết báo cáo bằng TIẾNG VIỆT chuyên sâu.
- Giữ nguyên các KEY JSON bằng TIẾNG ANH (không được dịch key).
- Đưa ra ít nhất 4 bước phản ứng SOC cụ thể (VD: Chặn hash, cô lập cổng, xóa registry cụ thể).

BẮT BUỘC TRẢ VỀ THEO CẤU TRÚC JSON NÀY:
{{
  "incident_summary": "Viết ít nhất 4 câu tiếng Việt tại đây...",
  "technical_analysis": {{
    "infection_vector": "Chi tiết vector...",
    "behavior": "Phân tích hành vi > 150 từ...",
    "impact": "Tác động..."
  }},
  "response_steps": [
    {{
      "phase": "Containment",
      "description": "Hành động 1...",
      "steps": ["Bước nhỏ 1", "Bước nhỏ 2"]
    }},
    {{
      "phase": "Eradication",
      "description": "Hành động 2...",
      "steps": ["Bước nhỏ 1"]
    }}
  ]
}}
"""

    res = llm.invoke([
        {"role": "system", "content": ANALYST_SYSTEM_PROMPT},
        {"role": "user", "content": prompt}
    ]).content

    try:
        # Làm sạch và parse JSON
        match = re.search(r"(\{.*\})", res, re.DOTALL)
        clean_str = match.group(1) if match else res
        draft_dict = json.loads(clean_str)
        
        # Kiểm tra nếu LLM lỡ dịch Key thì ta gán lại Key chuẩn (Bảo hiểm)
        # (Bạn có thể thêm logic map key ở đây nếu cần)
        
    except:
        draft_dict = {"incident_summary": "Lỗi định dạng báo cáo", "technical_analysis": {"behavior": res}}

    return {
        "draft_report": draft_dict,
        "feedback": []
    }