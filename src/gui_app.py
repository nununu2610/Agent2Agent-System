import streamlit as st
import os
import sys
import time
import json
import re
from dotenv import load_dotenv

# Thiết lập đường dẫn hệ thống
load_dotenv()
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# IMPORT LUỒNG GRAPH CHÍNH (Thay vì import từng worker lẻ)
try:
    from src.main import app
except ImportError:
    st.error("Không thể tìm thấy 'app' trong src.main. Hãy đảm bảo bạn đã compile graph bằng 'app = workflow.compile()'")

def extract_json_safe(text):
    """Trích xuất JSON an toàn từ phản hồi của LLM."""
    if not text:
        return None, ""
    if isinstance(text, dict):
        return text, ""
    
    text = re.sub(r"```json|```", "", text).strip()
    try:
        match = re.search(r"(\{.*\})", text, re.DOTALL)
        if match:
            json_str = match.group(1)
            # Sửa lỗi JSON thiếu dấu phẩy giữa các thuộc tính (nếu có)
            json_str = re.sub(r'(")\s*\n\s*(")', r'\1,\n\2', json_str)
            return json.loads(json_str), None
        return None, text
    except:
        return None, text

# === CẤU HÌNH GIAO DIỆN ===
st.set_page_config(page_title="Cyborg Malware Intelligence", layout="wide", page_icon="🤖")

st.markdown("""
    <style>
    .report-card { background-color: #ffffff; padding: 25px; border-radius: 15px; border-left: 8px solid #007bff; box-shadow: 0 4px 15px rgba(0,0,0,0.1); color: #1e1e1e; }
    .step-box { background-color: #f8f9fa; border: 1px solid #dee2e6; padding: 15px; border-radius: 10px; margin-bottom: 10px; color: #333; }
    .status-text { font-size: 0.9em; color: #666; font-style: italic; }
    </style>
""", unsafe_allow_html=True)

def main():
    st.title(" AI Malware Intelligence Dashboard")
    st.markdown("Hệ thống phân tích mã độc đa tác tử (Orchestrator-Worker Architecture)")
    
    with st.sidebar:
        st.header("Cấu hình hệ thống")
        mode = st.radio("Chế độ vận hành:", ["Phân tích chuyên sâu (Multi-Agent)", "Tra cứu nhanh (Single LLM)"])


    user_query = st.text_input("🤖 Nhập tên hoặc hành vi Malware:", placeholder="Ví dụ: Phân tích mã độc LockBit...")

    if st.button("BẮT ĐẦU PHÂN TÍCH", type="primary"):
        if not user_query:
            st.warning("Vui lòng nhập nội dung cần phân tích.")
            return

        if mode == "Tra cứu nhanh (Single LLM)":
            with st.spinner("Đang truy vấn dữ liệu..."):
                from langchain_groq import ChatGroq
                llm = ChatGroq(model="llama-3.1-8b-instant")
                st.info(llm.invoke(user_query).content)
        else:
            # === KHỞI CHẠY HỆ THỐNG MULTI-AGENT ===
            # Khởi tạo state ban đầu đúng chuẩn đầu vào của Intent Gate
            initial_state = {
                "raw_user_input": user_query,
                "malware_name": user_query,
                "iterations": 0,
                "feedback": [],
                "task_plan": []
            }
            
            final_state = {}
            
            with st.status(" Đang khởi động ...", expanded=True) as status:
                # Chạy Graph theo dạng Stream để cập nhật UI từng bước
                try:
                    for output in app.stream(initial_state):
                        for node_name, node_state in output.items():
                            final_state.update(node_state)
                            
                            if node_name == "intent_gate":
                                if node_state.get("intent_valid"):
                                    st.write(" **Intent Gate:** Input hợp lệ. Đã tạo dấu vân tay định danh.")
                                else:
                                    st.error(f" **Intent Gate:** Chặn truy cập! Lý do: {node_state.get('intent_reason')}")
                                    status.update(label="Bị chặn bởi tường lửa bảo mật", state="error")
                                    st.stop()
                            
                            elif node_name == "orchestrator":
                                tasks = node_state.get("task_plan", [])
                                st.write(f" **Orchestrator:** Đã lập kế hoạch phân rã thành {len(tasks)} nhiệm vụ.")
                            
                            elif node_name in ["rag_worker", "search_worker"]:
                                st.write(f" **Data Worker:** Đang thu thập dữ liệu từ {node_name.replace('_', ' ')}...")
                            
                            elif node_name == "analyst_worker":
                                st.write(" **Analyst:** Đang tổng hợp báo cáo kỹ thuật...")
                            
                            elif node_name == "auditor_worker":
                                st.write(" **Auditor:** Đang kiểm duyệt nội dung và đối soát rủi ro...")
                                
                            elif node_name == "judge_worker":
                                decision = node_state.get("judge_result", {}).get("final_decision", "PENDING")
                                if decision == "APPROVE":
                                    st.write(" **Judge:** Báo cáo đã được phê duyệt!")
                                else:
                                    st.write(f" **Judge:** Yêu cầu tối ưu lại (Vòng {final_state.get('iterations', 0)})...")
                    
                    status.update(label="Quy trình hoàn tất!", state="complete")
                except Exception as e:
                    st.error(f"Lỗi hệ thống: {str(e)}")
                    st.stop()

            evaluator_res = final_state.get("evaluator_result", {})
            is_approved = evaluator_res.get("final_decision") == "APPROVE"
            
            report_source = final_state.get("final_report") if is_approved else final_state.get("draft_report")
            final_json, _ = extract_json_safe(report_source)

            if is_approved:
                st.balloons()
                st.success("BÁO CÁO CHIẾN LƯỢC ĐÃ ĐƯỢC XÁC MINH")
            else:
                st.error(f"BÁO CÁO CHƯA ĐƯỢC PHÊ DUYỆT (Số vòng lặp: {final_state.get('iterations')})")
                st.info(f"**Lý do:** {evaluator_res.get('reason', 'Không đạt tiêu chuẩn chất lượng')}")
                

            if final_json:
                col1, col2 = st.columns([1, 1])
                with col1:
                    st.markdown("### Tóm tắt sự cố")
                    st.markdown(f'<div class="report-card">{final_json.get("incident_summary", "Không có dữ liệu")}</div>', unsafe_allow_html=True)
                
                with col2:
                    st.markdown("### Phân tích kỹ thuật")
                    tech = final_json.get("technical_analysis", {})
                    with st.container(border=True):
                        if isinstance(tech, dict):
                            st.write(f"**Vector tấn công:** {tech.get('infection_vector', 'N/A')}")
                            st.write(f"**Hành vi:** {tech.get('behavior', 'N/A')}")
                            st.write(f"**Tác động:** {tech.get('impact', 'N/A')}")
                        else:
                            st.write(tech)

                st.markdown("---")
                st.markdown("### Quy trình ứng phó ")
                steps = final_json.get("response_steps", [])
                
                if isinstance(steps, list) and len(steps) > 0:
                    for i, s in enumerate(steps):
                        if isinstance(s, dict):
                            phase = s.get('phase', f'GIAI ĐOẠN {i+1}')
                            desc = s.get('description', '')
                            sub_steps = s.get('steps', [])
                            
                            content = desc
                            if sub_steps:
                                content += "<br><ul>" + "".join([f"<li>{x}</li>" for x in sub_steps]) + "</ul>"
                        else:
                            phase = f"GIAI ĐOẠN {i+1}"
                            content = str(s)

                        st.markdown(f'''
                            <div class="step-box">
                                <span style="color: #007bff; font-weight: bold; text-transform: uppercase;">{phase}</span><br>
                                {content}
                            </div>
                        ''', unsafe_allow_html=True)
                else:
                    st.info("Không có dữ liệu quy trình ứng phó chi tiết.")

if __name__ == "__main__":
    main()