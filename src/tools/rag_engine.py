import os
from langchain_community.vectorstores import FAISS
from langchain_community.embeddings import HuggingFaceEmbeddings 
from langchain_core.documents import Document

def setup_rag():
    file_path = os.path.join("data", "malware_kb.txt")
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            docs = [Document(page_content=chunk.strip()) for chunk in content.split("\n") if chunk.strip()]
    except FileNotFoundError:
        docs = [Document(page_content="Không có dữ liệu quy định nội bộ.")]

    # dùng local embeddings offline 
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    
    vector_store = FAISS.from_documents(docs, embeddings)
    return vector_store.as_retriever(search_kwargs={"k": 1})