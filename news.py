from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

from env_utils import load_dotenv
from http_utils import request_json


load_dotenv(Path(__file__).resolve().with_name(".env"))

NEWS_API_URL = "https://newsapi.org/v2/everything"
DEFAULT_QUERY = os.getenv(
    "NEWS_QUERY",
    'cybersecurity OR ransomware OR "data breach" OR zero-day OR vulnerability OR malware',
)


def _to_iso8601(value: str) -> str:
    if not value:
        return datetime.now(timezone.utc).isoformat()
    return value.replace("Z", "+00:00")


def _normalize_article(article: Dict[str, Any]) -> Dict[str, Any]:
    title = (article.get("title") or "").strip()
    description = (article.get("description") or "").strip()
    content = (article.get("content") or "").strip()

    return {
        "id": article.get("url") or title,
        "title": title,
        "description": description,
        "content": content,
        "source_type": "news",
        "source_name": (article.get("source") or {}).get("name", "NewsAPI"),
        "published_at": _to_iso8601(article.get("publishedAt", "")),
        "url": article.get("url", ""),
        "severity": "",
        "cvss_score": None,
        "related_cves": [],
        "tags": [],
    }


def get_news(days: int = 2, page_size: int = 20) -> List[Dict[str, Any]]:
    api_key = os.getenv("NEWS_API_KEY", "").strip()
    if not api_key or "replace_with" in api_key:
        return []

    from_date = (datetime.now(timezone.utc) - timedelta(days=max(days, 1))).strftime("%Y-%m-%d")
    params = {
        "q": DEFAULT_QUERY,
        "from": from_date,
        "sortBy": "publishedAt",
        "language": "en",
        "pageSize": max(1, min(page_size, 100)),
        "apiKey": api_key,
    }

    payload = request_json(NEWS_API_URL, params=params, timeout=30)
    if payload.get("status") != "ok":
        raise RuntimeError(payload.get("message", "News API returned an unexpected response"))

    articles = []
    for raw_article in payload.get("articles", []):
        normalized = _normalize_article(raw_article)
        if normalized["title"]:
            articles.append(normalized)
    return articles
