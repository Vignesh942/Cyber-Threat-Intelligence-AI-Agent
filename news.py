import requests
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

def get_news(days: int = 1):
    url = "https://newsapi.org/v2/everything"
    from_date = (datetime.utcnow() - timedelta(days=days)).strftime('%Y-%m-%d')
    params = {
        "q": "cybersecurity OR hacking OR ransomware OR data breach",
        "from": from_date,
        "sortBy": "publishedAt",
        "language": "en",
        "apiKey": os.getenv("NEWS_API_KEY")
    }
    try:
        res = requests.get(url, params=params, timeout=15)
        data = res.json()
        articles = []
        for article in data.get("articles", [])[:12]:
            articles.append({
                "title": article.get("title", ""),
                "description": article.get("description", ""),
                "source": article.get("source", {}).get("name", "NewsAPI"),
                "publishedAt": article.get("publishedAt", ""),
                "url": article.get("url", "")
            })
        return articles
    except Exception:
        return []