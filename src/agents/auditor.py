import os
import re
from langchain_groq import ChatGroq
from src.tools.rag_engine import setup_rag
from src.state import AgentState

llm = ChatGroq(
    model="llama-3.1-8b-instant", 
    temperature=0.1,
    api_key=os.getenv("GROQ_API_KEY")
)

retriever = setup_rag()

def auditor_node(state: AgentState):
    malware = state.get("malware_name", "")
    draft = state.get("draft_report", "")
    iterations = state.get("iterations", 0)
    
    internal_docs = retriever.invoke(f"Quy trình xử lý nội bộ cho {malware}")
    context = "\n".join([d.page_content for d in internal_docs])
    
    print(f"\n[AUDITOR] Đang thẩm định bản nháp (Lần lặp: {iterations + 1})...")

    prompt = f"""
    BẠN LÀ KIỂM TOÁN VIÊN AN NINH MẠNG.
    DỮ LIỆU NỘI BỘ BẮT BUỘC: {context}
    BẢN NHÁP CỦA ANALYST: {draft}

    NHIỆM VỤ:
    1. Kiểm tra bản nháp. Nếu THIẾU quy trình cụ thể từ 'DỮ LIỆU NỘI BỘ BẮT BUỘC' (ví dụ: rút cáp mạng,...) -> Ghi 'STATUS: REJECT'.
    2. Nếu ĐẠT: Ghi 'STATUS: APPROVE' và viết BÁO CÁO CHÍNH THỨC.
    
    YÊU CẦU BÁO CÁO:
    - Phải có mục riêng tên là 'QUY TRÌNH PHẢN ỨNG KHẨN CẤP'.
    - Trong mục đó, phải trích dẫn NGUYÊN VĂN quy trình từ 'DỮ LIỆU NỘI BỘ BẮT BUỘC'.
    - KHÔNG giải thích các bước kiểm tra của bạn. KHÔNG để lại các ký tự thừa như STATUS.
    """
    
    res = llm.invoke(prompt).content
    
    if "STATUS: APPROVE" in res.upper():
        clean_report = re.sub(r"\*?\*?STATUS:\s*APPROVE\*?\*?", "", res, flags=re.IGNORECASE).strip()
        
        return {
            "final_report": clean_report, 
            "feedback": "", 
            "iterations": iterations + 1
        }
    else:
        return {
            "feedback": res, 
            "iterations": iterations + 1,
            "draft_report": draft
        }