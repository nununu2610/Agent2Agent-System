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
            
        initial_state = {"malware_name": target, "draft_report": "", "final_report": "", "iterations": 0}
        
        print("\n" + "═"*75)
        print(f"KHỞI ĐỘNG PHÂN TÍCH: {target.upper()}")
        print("═"*75)
        
        # Biến để lưu giữ trạng thái cuối cùng sau khi thoát vòng lặp
        final_state = initial_state

        # Vòng lặp Stream để hiện thị tiến trình
        for event in app.stream(initial_state):
            for agent_name, state_update in event.items():
                # Cập nhật trạng thái mới nhất vào biến final_state
                final_state.update(state_update)
                
                if agent_name == "analyst":
                    print(f"\n[BƯỚC 1] THU THẬP OSINT (AGENT: ANALYST)")
                    print(" ├── Trạng thái: Đã truy xuất dữ liệu Web.")
                    snippet = state_update.get('draft_report', '')[:100].replace('\n', ' ')
                    print(f" └── Nội dung nháp: \"{snippet}...\"")
                    
                elif agent_name == "auditor":
                    print(f"\n[BƯỚC 2] KIỂM ĐỊNH RAG (AGENT: AUDITOR)")
                    fb = state_update.get('feedback', '')
                    if fb:
                        print(f" ├── Kết quả: REJECT (Phát hiện thiếu sót kỹ thuật).")
                        print(f" └── Yêu cầu: {fb[:80]}...")
                    else:
                        print(" └── Kết quả: APPROVE (Báo cáo đã đạt chuẩn nội bộ).")

        # --- PHẦN HIỂN THỊ KẾT QUẢ CUỐI CÙNG (Sau khi kết thúc luồng) ---
        print("\n" + "─" * 75)
        print("BÁO CÁO PHẢN ỨNG SỰ CỐ CHÍNH THỨC (FINAL REPORT)")
        print("─" * 75)

        # Kiểm tra kỹ trong final_state thay vì state_update (biến tạm trong loop)
        if final_state.get("final_report"):
            print(final_state["final_report"])
        else:
            print("⚠️ CẢNH BÁO: Hệ thống dừng do đạt giới hạn lặp (3 lần).")
            print("-" * 30)
            print(f"Bản nháp cuối cùng chưa được duyệt:\n\n{final_state.get('draft_report')}")
            print("-" * 30)
            print(f"Lý do Auditor chưa duyệt: {final_state.get('feedback')}")
            
        print("\n" + "═" * 75 + "\n")