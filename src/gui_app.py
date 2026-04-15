import streamlit as st
import os
import sys
import time
import json
import re
from dotenv import load_dotenv
from langchain_groq import ChatGroq


load_dotenv()
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.agents.analyst import analyst_node
from src.agents.auditor import auditor_node
from src.agents.judge import judge_node

def extract_json_safe(text):
    if not text or not isinstance(text, str):
        return None, text
    text = re.sub(r"```json|```", "", text).strip()
    try:
        match = re.search(r"(\{.*\})", text, re.DOTALL)
        if match:
            json_str = match.group(1)
            json_str = re.sub(r'(")\s*\n\s*(")', r'\1,\n\2', json_str)
            return json.loads(json_str), None
        return None, text
    except:
        return None, text

st.set_page_config(page_title="Cyborg Malware Intelligence", layout="wide")

st.markdown("""
    <style>
    .report-card { background-color: #ffffff; padding: 25px; border-radius: 15px; border-left: 8px solid #007bff; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
    .step-box { background-color: #f8f9fa; border: 1px solid #dee2e6; padding: 15px; border-radius: 10px; margin-bottom: 10px; }
    </style>
""", unsafe_allow_html=True)

def main():
    st.title("AI Malware Intelligence Dashboard")
    
    with st.sidebar:
        st.header("⚙️ Setting")
        mode = st.radio("Chế độ:", ["Phân tích chuyên sâu", "Hỏi đáp nhanh"])
        max_retries = st.slider("Số lần tối ưu", 1, 5, 2)

    user_query = st.text_input("🤖 Tên Malware cần phân tích:", placeholder="Ví dụ: LockBit, WannaCry, Dharma...")

    if st.button("Thực thi quy trình", type="primary"):
        if not user_query: return

        if mode == "Hỏi đáp nhanh":
            with st.spinner("Đang suy nghĩ..."):
                llm = ChatGroq(model="llama-3.1-8b-instant")
                st.info(llm.invoke(user_query).content)
        else:
            state = {"malware_name": user_query, "iterations": 0, "draft_report": "", "feedback": []}
            
            with st.status("Đang chạy hệ thống Agent...", expanded=True) as status:
                while state["iterations"] < max_retries:
                    it = state["iterations"] + 1
                    st.write(f"**Round {it}:** Đang phân tích & kiểm duyệt...")
                    
                    state.update(analyst_node(state))
                    time.sleep(2) 
                    state.update(auditor_node(state))
                    time.sleep(2)
                    judge_res = judge_node(state)
                    decision = judge_res["judge_result"]
                    
                    if decision["final_decision"] == "APPROVE":
                        status.update(label="Đã xác minh thành công!", state="complete")
                        break
                    else:
                        state["iterations"] += 1
                        state["feedback"] = state["audit_result"].get("required_fixes", [])

            draft_json, draft_text = extract_json_safe(state.get("draft_report", ""))

            if decision["final_decision"] == "APPROVE":
                st.balloons()
                st.success("BÁO CÁO ĐÃ ĐƯỢC PHÊ DUYỆT")
                final = state.get("final_report", draft_json)
            else:
                st.error(f"Bị từ chối (Round {state['iterations']}): {decision.get('reason')}")
                st.warning("HIỂN THỊ BẢN THẢO CHƯA XÁC MINH")
                final = draft_json

            if final:
                col1, col2 = st.columns([1, 1])
                with col1:
                    st.markdown("### Tóm tắt sự cố")
                    st.markdown(f'<div class="report-card">{final.get("incident_summary")}</div>', unsafe_allow_html=True)
                
                with col2:
                    st.markdown("### Chi tiết kỹ thuật")
                    tech = final.get("technical_analysis", {})
                    if isinstance(tech, dict):
                        st.write(f"**Vector:** {tech.get('infection_vector')}")
                        st.write(f"**Hành vi:** {tech.get('behavior')}")
                        st.write(f"**Tác động:** {tech.get('impact')}")
                    else: st.write(tech)

                st.markdown("### Quy trình ứng phó (SOC Action Plan)")
                steps = final.get("response_steps", [])
                                
                if isinstance(steps, list):
                    for i, s in enumerate(steps):
                        if isinstance(s, dict):
                            step_content = s.get('description', '')
                            sub_details = s.get('steps', [])
                            if isinstance(sub_details, list):
                                step_content += " " + " ".join(sub_details)
                        else:
                            step_content = str(s)

                        step_content = re.sub(r"^(Bước|Step)\s*\d+[:.-]*\s*", "", step_content, flags=re.IGNORECASE).strip()

                        if step_content:
                            st.markdown(f'''
                                <div class="step-box">
                                    <span style="color: #007bff; font-weight: bold;">GIAI ĐOẠN {i+1}:</span><br>
                                    {step_content}
                                </div>
                            ''', unsafe_allow_html=True)
                else:
                    st.info("Không tìm thấy các bước ứng phó theo định dạng chuẩn.")
            else:
                st.markdown(draft_text)

if __name__ == "__main__":
    main()