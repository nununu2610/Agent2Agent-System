import os
from langchain_groq import ChatGroq
from src.tools.search_tool import get_web_search
from src.state import AgentState

llm = ChatGroq(
    model="llama-3.1-8b-instant", 
    temperature=0.1,
    api_key=os.getenv("GROQ_API_KEY")
)

search_tool = get_web_search()

def analyst_node(state: AgentState):
    malware = state["malware_name"]
    feedback = state.get("feedback", "")
    
    if feedback:
        print(f"[ANALYST] Nhận phản hồi: '{feedback}'. Đang tìm kiếm bổ sung...")
        search_query = f"{malware} {feedback}"
    else:
        print(f"[ANALYST] Đang phân tích mục tiêu mới: {malware}")
        search_query = f"technical analysis of {malware} malware"

    web_data = search_tool.invoke(search_query)
    
    prompt = f"""
    Bạn là Analyst. Hãy viết báo cáo về {malware}.
    Thông tin mới từ Web: {web_data}
    {f'Phản hồi từ Auditor cần sửa: {feedback}' if feedback else ''}
    """
    
    res = llm.invoke(prompt).content
    return {"draft_report": res, "feedback": ""} 

# def analyst_node(state: AgentState):
#     malware = state["malware_name"]
#     print(f"[ANALYST] Đang tra cứu thông tin về '{malware}' trên Internet...")
    
#     # Thu thập dữ liệu từ Web
#     web_data = search_tool.invoke(f"{malware} malware definition and behavior")
    
#     prompt = f"""
#     Bạn là Chuyên gia phân tích mã độc (Analyst). 
#     Hãy tóm tắt định nghĩa, đặc điểm và hành vi của mã độc: {malware}
#     Dựa trên thông tin thu thập được từ Web: {web_data}
    
#     Yêu cầu: Trình bày ngắn gọn, tập trung vào góc độ kỹ thuật bảo mật.
#     """
    
#     res = llm.invoke(prompt).content
#     return {"draft_report": res}