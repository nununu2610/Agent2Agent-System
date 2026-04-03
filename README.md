# A2A-MIS: Hệ thống Tình báo Mã độc (Phân tích + Kiểm duyệt)

## Tổng quan

Repository này triển khai một hệ thống chatbot **đa tác vụ (multi-agent)** phục vụ việc phân tích mã độc và tư vấn phản ứng sự cố (Incident Response). Hệ thống tập trung vào việc tạo ra các báo cáo kỹ thuật có độ tin cậy cao, đồng thời đảm bảo tuân thủ các quy trình an toàn thông tin nội bộ.

Hệ thống hoạt động qua hai giai đoạn chính:

1. **AnalystAgent**: Thực hiện thu thập thông tin kỹ thuật nhanh chóng về mục tiêu thông qua tìm kiếm dữ liệu mở (**OSINT**), cung cấp các chỉ số về hành vi và dấu hiệu nhận biết mã độc mới nhất.
2. **AuditorAgent**: Truy xuất các quy trình xử lý nội bộ từ **cơ sở dữ liệu vector** (RAG-lite), sau đó kiểm chứng và tinh chỉnh báo cáo thông qua **vòng lặp phản hồi (reflection loop)** để đảm bảo kết quả cuối cùng khớp với tiêu chuẩn phản ứng sự cố của tổ chức (ví dụ: yêu cầu bắt buộc về cô lập mạng).

---

## Cài đặt & Khởi chạy hệ thống

### 1. Cài đặt thư viện cần thiết

**Yêu cầu:** Python 3.10+ (Khuyến nghị sử dụng Python 3.12).

**Chạy lệnh:**

```bash
pip install -r requirements.txt
```

### 2. Cấu hình môi trường
Tạo file .env tại thư mục gốc và thêm API key của bạn (Lấy key tại Groq Cloud):
```bash
GROQ_API_KEY=your_groq_api_key_here
```

### 3. Khởi chạy hệ thống
Chạy script chính để bắt đầu giao diện dòng lệnh tương tác:
```bash
python src/main.py
```

### Nền tảng công nghệ (Technical Stack)
 - **Core Framework:** LangGraph & LangChain (Điều phối tác vụ Agent).
 - **LLM Engine:** Meta Llama-3.1-8b (Thông qua Groq Cloud cho tốc độ xử lý cao).
 - **Vector Store:** FAISS (Facebook AI Similarity Search) để lưu trữ quy trình nội bộ.
 - **Knowledge Retrieval:** HuggingFace Embeddings (all-MiniLM-L6-v2) để chuyển đổi ngôn ngữ sang vector.
