import json
import os
from langchain_community.vectorstores import FAISS
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_core.documents import Document

DB_PATH = "faiss_index"
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_PATH = os.path.join(BASE_DIR, "data", "structured_kb.json")

embeddings = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2"
)


def build_db():
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    docs = []

    for item in data:
        malware = item["malware"]
        severity = item.get("severity", "unknown")

        for s in item.get("symptoms", []):
            docs.append(Document(
                page_content=s,
                metadata={"malware": malware, "type": "symptom", "severity": severity}
            ))

        for v in item.get("infection_vector", []):
            docs.append(Document(
                page_content=v,
                metadata={"malware": malware, "type": "infection", "severity": severity}
            ))

        for m in item.get("mitigation", []):
            docs.append(Document(
                page_content=m,
                metadata={"malware": malware, "type": "mitigation", "severity": severity}
            ))

    if not docs:
        raise ValueError(" No documents loaded from structured_kb.json")

    db = FAISS.from_documents(docs, embeddings)
    db.save_local(DB_PATH)

    print(" FAISS index built successfully")
    return db


def load_db():
    if os.path.exists(DB_PATH):
        print("📦 Loading FAISS index...")
        return FAISS.load_local(DB_PATH, embeddings, allow_dangerous_deserialization=True)
    else:
        print("⚙️ Building FAISS index...")
        return build_db()


def query_rag(db, malware, doc_type="mitigation", k=5):
    return db.similarity_search(
        query=malware,
        k=k,
        filter={"type": doc_type}
    )