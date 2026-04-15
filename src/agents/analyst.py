import os
import re
from langchain_groq import ChatGroq
from src.tools.search_tool import get_web_search
from src.tools.rag_engine import load_db, query_rag
from src.state import AgentState

llm = ChatGroq(
    model="llama-3.1-8b-instant",
    temperature=0.1, 
    api_key=os.getenv("GROQ_API_KEY")
)

search_tool = get_web_search()
db = load_db()

def analyst_node(state: AgentState):
    malware = state["malware_name"]
    feedback = state.get("feedback", [])
    
    query = f"{malware} malware technical analysis behavior mitigation"
    web_data = search_tool.invoke(query)
    
    rag_docs = query_rag(db, malware, "mitigation")
    rag_context = "\n".join([d.page_content for d in rag_docs]) if rag_docs else ""
    feedback_text = "\n".join(feedback) if feedback else "None"

    prompt = f"""
ROLE: Senior Malware Analyst (SOC Level 3).
TASK: Viết báo cáo phân tích kỹ thuật chuyên sâu cho {malware}.

DATA SOURCE:
[WEB]: {web_data}
[INTERNAL]: {rag_context}
[FIX REQUESTS]: {feedback_text}

YÊU CẦU NGHIÊM NGẶT:
- KHÔNG lặp lại bất kỳ câu lệnh nào trong Prompt này.
- KHÔNG sử dụng các từ chung chung như "quét virus", "cập nhật máy".
- PHẢI sử dụng thuật ngữ chuyên môn: "persistence via Registry Run Keys", "API hooking", "C2 beaconing", "Lateral movement".
- MỤC response_steps: Phải là các hành động kỹ thuật cụ thể (Isolate IP, Kill Process ID, Block Port).

OUTPUT FORMAT (DUY NHẤT JSON, KHÔNG TEXT NGOÀI):
{{
  "incident_summary": "Viết tối thiểu 4 câu mô tả sâu về nguồn gốc và độ nguy hiểm.",
  "technical_analysis": {{
    "infection_vector": "Mô tả chi tiết cách xâm nhập (ví dụ: CVE-XXXX-XXXX).",
    "behavior": "Viết ít nhất 200 chữ về hành vi mã hóa, các file tạo ra, và tiến trình hệ thống bị can thiệp.",
    "impact": "Tác động đến hạ tầng mạng và dữ liệu doanh nghiệp."
  }},
  "response_steps": [
    "Cách cô lập máy tính...",
    "Các file/Registry cần xóa...",
    "Cách chặn kết nối C2...",
    "Cách khôi phục từ bản sao lưu..."
  ]
}}
"""

    res = llm.invoke(prompt).content
    
    match = re.search(r"(\{.*\})", res, re.DOTALL)
    clean_json = match.group(1) if match else res

    return {
        "draft_report": clean_json,
        "feedback": ""
    }