from __future__ import annotations

from typing import Any, Dict, List

from blogs import fetch_security_blogs
from correlation import build_threat_dataset
from cve import fetch_cve_data
from memory import load_memory, update_memory
from news import get_news
from report import create_pdf, render_markdown_report
from scoring import score_threats


def fetch_news(days: int = 2) -> List[Dict[str, Any]]:
    return get_news(days=days)


def fetch_blogs(limit_per_feed: int = 5) -> List[Dict[str, Any]]:
    return fetch_security_blogs(limit_per_feed=limit_per_feed)


def fetch_cves(days: int = 7) -> List[Dict[str, Any]]:
    return fetch_cve_data(days=days)


def analyze_threats(days: int = 2, cve_days: int = 7) -> List[Dict[str, Any]]:
    memory = load_memory()
    memory_titles = {(item.get("title") or "").strip().lower() for item in memory}
    memory_ids = {(item.get("id") or "").strip().lower() for item in memory}

    news_items = fetch_news(days=days)
    blog_items = fetch_blogs()
    cve_items = fetch_cves(days=cve_days)
    dataset = build_threat_dataset(news_items, blog_items, cve_items)
    return score_threats(dataset, known_titles=memory_titles, known_ids=memory_ids)


def persist_threats(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    return update_memory(items)


def generate_pdf_report(goal: str, report_type: str, items: List[Dict[str, Any]]) -> str:
    content = render_markdown_report(goal, report_type, items, decisions=[], errors=[])
    return create_pdf(content, report_type=report_type)