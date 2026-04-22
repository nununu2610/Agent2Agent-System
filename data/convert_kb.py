import json
import os
import re

def parse_txt(file_path):
    # Thử đọc với nhiều loại encoding khác nhau để tránh lỗi Windows
    encodings = ['utf-8-sig', 'utf-8', 'latin-1', 'utf-16']
    content = ""
    
    for enc in encodings:
        try:
            with open(file_path, "r", encoding=enc) as f:
                content = f.read()
            if "[MALWARE]" in content.upper():
                break
        except:
            continue

    if not content:
        print(f"❌ LỖI: Không thể đọc được nội dung file {file_path}")
        return []

    # CHẨN ĐOÁN: Nếu vẫn không thấy thẻ, in ra 100 ký tự đầu để xem lỗi encoding
    if "[MALWARE]" not in content.upper():
        print(f"⚠️ Debug - 100 ký tự đầu tiên của file: \n{repr(content[:100])}")
        return []

    # Tìm thẻ đầu tiên (không phân biệt hoa thường)
    match = re.search(r"\[MALWARE\]", content, re.IGNORECASE)
    clean_content = content[match.start():]

    # Tách các mục
    entries = re.split(r"\[MALWARE\]", clean_content, flags=re.IGNORECASE)
    data = []

    for e in entries:
        e = e.strip()
        if not e: continue

        lines = [l.strip() for l in e.splitlines() if l.strip()]
        if not lines: continue

        section_data = {
            "malware": lines[0].lower(),
            "symptoms": [], "infection_vector": [], "mitigation": [], "severity": "high"
        }

        current_key = None
        for line in lines[1:]:
            tag_match = re.match(r"\[(.*?)\]", line)
            if tag_match:
                tag_name = tag_match.group(1).lower()
                if "symptom" in tag_name: current_key = "symptoms"
                elif "infection" in tag_name: current_key = "infection_vector"
                elif "mitigation" in tag_name: current_key = "mitigation"
                else: current_key = None
            elif current_key and (line.startswith("-") or line.startswith("*")):
                clean_value = re.sub(r"^[-*]\s*", "", line)
                section_data[current_key].append(clean_value)

        data.append(section_data)
    return data

if __name__ == "__main__":
    base_path = os.path.dirname(os.path.abspath(__file__))
    input_path = os.path.join(base_path, "malware_kb.txt")
    output_path = os.path.join(base_path, "structured_kb.json")

    print(f"🔄 Đang đọc file: {input_path}")
    final_data = parse_txt(input_path)
    
    if final_data:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(final_data, f, indent=2, ensure_ascii=False)
        print(f"✅ THÀNH CÔNG: Đã trích xuất {len(final_data)} loại mã độc.")
    else:
        print("❌ Thất bại. Vui lòng kiểm tra lại định dạng hoặc encoding của file .txt")