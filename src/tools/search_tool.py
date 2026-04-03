from langchain_community.tools import DuckDuckGoSearchRun

def get_web_search():
    return DuckDuckGoSearchRun()