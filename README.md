# 🛡️ AI Malware Intelligence System (AMIS)

> **Hệ thống phân tích mã độc đa tác tử dựa trên kiến trúc Orchestrator-Worker (Star Topology)**

AMIS là một giải pháp phân tích mã độc thế hệ mới, kết hợp sức mạnh của các mô hình ngôn ngữ lớn (LLM) và quy trình Multi-Agent tự động. Hệ thống tập trung vào việc cung cấp báo cáo SOC chuẩn kỹ thuật, đồng thời thực thi nghiêm ngặt các rào cản bảo mật để chống lại các đòn tấn công Prompt Injection và Goal Hijacking theo tiêu chuẩn OWASP.

---

##  Kiến trúc Hệ thống (Star Topology)

Hệ thống hoạt động theo mô hình **Điều phối tập trung (Orchestration)**, đảm bảo tính toàn vẹn và minh bạch trong luồng xử lý dữ liệu.

* **Intent Gate (Phòng tuyến số 1):** Kiểm tra ý định người dùng bằng Regex và Guardrails trước khi dữ liệu chạm tới LLM. Ngăn chặn các câu lệnh bẻ lái mục tiêu ngay từ đầu vào.
* **Orchestrator (Não bộ):** Tiếp nhận yêu cầu, phân rã thành các nhiệm vụ nhỏ (sub-tasks) và dispatch tới các Worker phù hợp.
* **RAG Worker (Tri thức nội bộ):** Truy xuất dữ liệu từ cơ sở dữ liệu Vector (FAISS) được xây dựng từ Knowledge Base nội bộ (`malware_kb.txt`).
* **Search Worker (Tri thức toàn cầu):** Thu thập thông tin malware thời gian thực thông qua DuckDuckGo Search API, giúp cập nhật các biến thể mã độc mới nhất.
* **Analyst Agent (Chuyên gia):** Nhận dữ liệu thô từ RAG và Search để tổng hợp thành báo cáo kỹ thuật chuyên sâu bằng tiếng Việt.
* **Evaluator / CISO (Thẩm định):** Chốt chặn cuối cùng kiểm tra chất lượng. Nếu báo cáo không đạt yêu cầu hoặc có dấu hiệu bị thao túng, Evaluator sẽ yêu cầu Analyst thực hiện lại (Feedback Loop).

---

##  Cơ chế Bảo mật "Zero Trust"

Để đảm bảo các Agent không bị thao túng bởi dữ liệu độc hại, AMIS áp dụng các kỹ thuật bảo mật tầng sâu:

1.  **Task Fingerprinting (SHA-256):** Mọi nhiệm vụ truyền đi đều được đính kèm mã Hash dựa trên nội dung gốc. Bất kỳ sự thay đổi trái phép nào trong State (như Hacker sửa lệnh tìm kiếm thành lệnh lấy trộm Cookie) đều bị Worker phát hiện và từ chối thực thi.
2.  **Locked System Prompts:** Định nghĩa vai trò không thể thay đổi (Immutable Identity) cho từng Agent. Dù dữ liệu bên ngoài có yêu cầu AI "quên các lệnh trước đó", Agent vẫn tuân thủ chỉ thị bảo mật cốt lõi.
3.  **Validation Loop:** Evaluator sử dụng bộ quy tắc cứng (Code-based checks) để loại bỏ các báo cáo rác, nội dung chung chung hoặc báo cáo bị nhiễm "độc" từ kết quả tìm kiếm web (Indirect Prompt Injection).

---

##  Hướng dẫn Cài đặt & Triển khai

### 1. Cài đặt môi trường
```bash
git clone [https://github.com/nununu2610/Agent2Agent-System.git](https://github.com/nununu2610/Agent2Agent-System.git)
cd Agent2Agent-System
pip install -r requirements.txt
```

### 2. Cấu hình biến môi trường
Tạo file `.env` tại thư mục gốc và cấu hình API Key cùng các Model:
```env
GROQ_API_KEY=your_groq_api_key_here
LARGE_MODEL=llama-3.3-70b-versatile
FAST_MODEL=llama-3.1-8b-instant
```

### 3. Nạp dữ liệu tri thức (RAG Ingestion)
Để hệ thống AI có thể truy xuất chính xác các quy trình xử lý nội bộ, bạn cần thực hiện các bước sau:

1.  **Cập nhật dữ liệu:** Chỉnh sửa hoặc thêm thông tin mã độc mới vào file `data/malware_kb.txt` theo đúng định dạng các thẻ `[MALWARE]`, `[SYMPTOMS]`, `[MITIGATION]`.
2.  **Chuyển đổi dữ liệu:** Chạy script để trích xuất dữ liệu thô sang định dạng JSON cấu trúc:
    ```bash
    python data/convert_kb.py
    ```
3.  **Làm mới bộ nhớ Vector:** Nếu bạn đã có dữ liệu cũ, hãy xóa thư mục `faiss_index` tại thư mục gốc. Hệ thống sẽ tự động xây dựng lại cơ sở dữ liệu Vector (Embedding) trong lần chạy tiếp theo.



---

##  Hướng dẫn Sử dụng Dashboard

Để khởi chạy giao diện người dùng trực quan, sử dụng lệnh sau:

```bash
streamlit run gui_app.py
```

## Quy trình sử dụng

1. **Nhập thông tin:** Điền tên mã độc (ví dụ: `WannaCry`, `Cobalt Strike`) hoặc mô tả hành vi vào ô tìm kiếm.
2. **Theo dõi luồng xử lý:** Hệ thống sẽ hiển thị trạng thái hoạt động của từng Agent (**Orchestrator** -> **RAG/Search** -> **Analyst** -> **Evaluator**).
3. **Nhận kết quả:** Sau khi được **Evaluator** phê duyệt, báo cáo SOC hoàn chỉnh sẽ hiển thị bao gồm: Tóm tắt sự cố, Phân tích kỹ thuật chuyên sâu và Quy trình ứng phó chi tiết.

---

##  Công nghệ sử dụng

* **Framework chính:** LangGraph & LangChain (Điều phối đa tác tử có trạng thái).
* **LLM Provider:** Groq Cloud (Tối ưu hóa tốc độ với Llama 3.3 70B & Llama 3.1 8B).
* **Vector Database:** FAISS (Facebook AI Similarity Search).
* **Embedding Model:** HuggingFace `sentence-transformers/all-MiniLM-L6-v2`.
* **Giao diện:** Streamlit.

---

##  Định hướng phát triển (Roadmap)

- [ ] Tích hợp tính năng phân tích file mẫu (.exe, .dll) trong môi trường Sandbox.
- [ ] Hỗ trợ xuất báo cáo định dạng PDF theo mẫu SOC tiêu chuẩn.
- [ ] Mở rộng cơ sở dữ liệu tri thức lên hơn 100+ loại mã độc phổ biến.
- [ ] Tích hợp thêm các lớp kiểm soát an toàn từ Llama Guard.