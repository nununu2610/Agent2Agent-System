🛡️ A2A-MIS: Malware Intelligence System
Hệ thống phân tích mã độc thông minh sử dụng kiến trúc Multi-Agent (Analyst & Auditor) để tự động hóa quy trình phân tích và đối chiếu chính sách bảo mật nội bộ.

✨ Tính năng chính
Analyst Node: Tự động thu thập thông tin mã độc từ Internet (OSINT).

Auditor Node: Đối chiếu bản nháp với cơ sở dữ liệu quy trình nội bộ (RAG).

Reflection Loop: Cơ chế phản biện, Auditor yêu cầu Analyst sửa đổi nếu báo cáo thiếu quy trình kỹ thuật hoặc sai lệch chính sách.

🏗️ Quy trình hoạt động
Nhập liệu: Người dùng nhập tên mã độc (VD: WannaCry, AutoHacker).

Phân tích: Analyst tìm kiếm thông tin và viết bản nháp.

Kiểm duyệt: Auditor so khớp với dữ liệu nội bộ (malware_kb.txt).

Phản hồi: Nếu chưa đạt, Auditor gửi feedback yêu cầu Analyst sửa lại.

Hoàn tất: Xuất báo cáo Incident Response cuối cùng.

🛠️ Cài đặt & Chạy
Clone dự án:

Bash
git clone https://github.com/username/a2a-system.git
cd a2a-system
Cài đặt thư viện:

Bash
pip install -r requirements.txt
Cấu hình file .env:
Tạo file .env và thêm API Key từ Groq Cloud:

Đoạn mã
GROQ_API_KEY=gsk_your_api_key_here
Khởi chạy:

Bash
python src/main.py
📚 Công nghệ sử dụng
LLM: Llama-3.1-8b (via Groq)

Orchestration: LangGraph, LangChain

Vector DB: FAISS

Embeddings: HuggingFace all-MiniLM-L6-v2
