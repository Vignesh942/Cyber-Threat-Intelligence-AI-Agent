from langchain_core.tools import tool
import json
from news import get_news
from blogs import fetch_security_blogs
from cve import fetch_cve_data
from correlation import correlate_data
from scoring import score_threats
from memory import update_memory
from report import create_pdf

@tool
def fetch_news(days: int = 1) -> str:
    """Fetch latest cybersecurity news articles."""
    data = get_news(days)
    return json.dumps(data, ensure_ascii=False)

@tool
def fetch_blogs() -> str:
    """Fetch latest posts from top security blogs."""
    data = fetch_security_blogs()
    return json.dumps(data, ensure_ascii=False)

@tool
def fetch_cves(days: int = 2) -> str:
    """Fetch recent CVEs from NVD database."""
    data = fetch_cve_data(days)
    return json.dumps(data, ensure_ascii=False)

@tool
def correlate_threats(news_json: str, cves_json: str) -> str:
    """Correlate news with CVEs."""
    import json
    news = json.loads(news_json)
    cves = json.loads(cves_json)
    result = correlate_data(news, cves)
    return json.dumps(result, ensure_ascii=False)

@tool
def score_threats_tool(data_json: str) -> str:
    """Score and prioritize threats."""
    import json
    data = json.loads(data_json)
    scored = score_threats(data)
    return json.dumps(scored, ensure_ascii=False)

@tool
def store_in_memory(data_json: str) -> str:
    """Store threats in persistent memory."""
    import json
    data = json.loads(data_json)
    result = update_memory(data)
    return json.dumps(result)

@tool
def generate_pdf_report(content: str) -> str:
    """Generate professional PDF report."""
    filename = create_pdf(content)
    return f"PDF Report generated successfully: {filename}"