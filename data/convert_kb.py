import json

def parse_txt(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    entries = content.split("[MALWARE]")
    data = []

    for e in entries:
        if not e.strip():
            continue

        lines = e.strip().split("\n")
        malware = lines[0].strip()

        section = {}
        current_key = None

        for line in lines[1:]:
            line = line.strip()

            if line.startswith("[") and line.endswith("]"):
                current_key = line.replace("[", "").replace("]", "").lower()
                section[current_key] = []
            elif current_key and line.startswith("-"):
                section[current_key].append(line[1:].strip())

        data.append({
            "malware": malware.lower(),
            "symptoms": section.get("symptoms", []),
            "infection_vector": section.get("infection_vector", []),
            "mitigation": section.get("mitigation", []),
            "severity": "high"
        })

    return data


if __name__ == "__main__":
    data = parse_txt("malware_kb.txt")

    with open("structured_kb.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print("✔ Converted to structured_kb.json")