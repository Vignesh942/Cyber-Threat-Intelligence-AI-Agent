import feedparser
from datetime import datetime, timedelta

RSS_FEEDS = [
    "https://krebsonsecurity.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/",
]

def fetch_security_blogs():
    articles = []
    for url in RSS_FEEDS:
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries[:6]:
                articles.append({
                    "title": entry.title,
                    "description": entry.get("summary", ""),
                    "source": feed.feed.get("title", "Security Blog"),
                    "publishedAt": entry.get("published", ""),
                    "url": entry.link
                })
        except Exception:
            continue
    return articles