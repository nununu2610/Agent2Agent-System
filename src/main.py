import os
import sys
from dotenv import load_dotenv
from langgraph.graph import StateGraph, END

load_dotenv()

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.state import AgentState
from src.agents.analyst import analyst_node
from src.agents.auditor import auditor_node



# def build_app():
#     workflow = StateGraph(AgentState)
    
#     workflow.add_node("analyst", analyst_node)
#     workflow.add_node("auditor", auditor_node)
    
#     workflow.set_entry_point("analyst")
#     workflow.add_edge("analyst", "auditor")
#     workflow.add_edge("auditor", END)
    
#     return workflow.compile()

def should_continue(state: AgentState):
    # Debug: In ra để kiểm tra xem có feedback không
    fb = state.get("feedback", "")
    it = state.get("iterations", 0)
    
    if fb and it < 3:
        print(f"\n[HỆ THỐNG] Auditor phát hiện lỗi kỹ thuật. Đang gửi phản hồi cho Analyst sửa lại (Lần {it})...")
        return "continue"
    
    print("\n[HỆ THỐNG] Phân tích hoàn tất hoặc đạt giới hạn lặp.")
    return "end"

def build_app():
    workflow = StateGraph(AgentState)
    
    workflow.add_node("analyst", analyst_node)
    workflow.add_node("auditor", auditor_node)
    
    workflow.set_entry_point("analyst")
    workflow.add_edge("analyst", "auditor")
    
    workflow.add_conditional_edges(
    "auditor",
    should_continue,
    {
        "continue": "analyst", 
        "end": END
    }
)
    return workflow.compile()

if __name__ == "__main__":
    app = build_app()
    print("HỆ THỐNG A2A-MIS")
    print("="*60)
    
    while True:
        target = input("\nNhập tên mã độc cần phân tích (VD: Ransomware, AutoHacker) hoặc 'exit': ")
        if target.lower() in ['exit', 'quit']: 
            break
            
        initial_state = {"malware_name": target, "draft_report": "", "final_report": ""}
        result = app.invoke(initial_state)
        
        print("\n" + "═"*75)
        print(f"KHỞI ĐỘNG PHÂN TÍCH: {target.upper()}")
        print("═"*75)
        
        for event in app.stream(initial_state):
            for agent_name, state_update in event.items():
                
                if agent_name == "analyst":
                    print("\nTHU THẬP OSINT (AGENT: ANALYST)")
                    print(" ├── Trạng thái: Đã cào dữ liệu từ Web.")
                    snippet = state_update['draft_report'][:100].replace('\n', ' ')
                    print(f" └── Trích xuất: \"{snippet}...\"")
                    
                elif agent_name == "auditor":
                    print("\nKIỂM ĐỊNH RAG (AGENT: AUDITOR)")
                    print(" ├── Trạng thái: Đã đối chiếu với Database nội bộ.")
                    print(" └── Kết quả: Hoàn tất hợp nhất dữ liệu.")
                    
        print("\n" + "─" * 75)
        print("BÁO CÁO PHẢN ỨNG SỰ CỐ (INCIDENT RESPONSE)")
        print("─" * 75)

        if "final_report" in state_update and state_update["final_report"]:
            print(state_update["final_report"])
        else:
            print("CẢNH BÁO: Hệ thống không thể thống nhất báo cáo sau 3 lần lặp.")
            print(f"Lý do từ chối cuối cùng từ Auditor:\n{state_update.get('feedback', 'Không có phản hồi.')}")
            
        print("═" * 75 + "\n")