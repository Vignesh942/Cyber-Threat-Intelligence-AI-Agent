from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, Iterable, List, Optional
from xml.etree import ElementTree as ET

from http_utils import request_text


RSS_FEEDS = [
    "https://krebsonsecurity.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.darkreading.com/rss.xml",
]


def _strip_namespace(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _direct_children(element: ET.Element, name: str) -> List[ET.Element]:
    return [child for child in list(element) if _strip_namespace(child.tag) == name]


def _first_text(element: ET.Element, names: Iterable[str]) -> str:
    name_set = set(names)
    for child in list(element):
        if _strip_namespace(child.tag) in name_set:
            text = "".join(child.itertext()).strip()
            if text:
                return text
    return ""


def _extract_link(entry: ET.Element) -> str:
    for child in list(entry):
        if _strip_namespace(child.tag) != "link":
            continue
        href = child.attrib.get("href")
        if href:
            return href.strip()
        text = "".join(child.itertext()).strip()
        if text:
            return text
    return ""


def _parse_published(value: str) -> str:
    if not value:
        return datetime.now(timezone.utc).isoformat()

    for parser in (
        lambda raw: parsedate_to_datetime(raw).astimezone(timezone.utc).isoformat(),
        lambda raw: datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat(),
    ):
        try:
            return parser(value)
        except (TypeError, ValueError, IndexError):
            continue

    return value


def _feed_title(root: ET.Element) -> str:
    channel_nodes = _direct_children(root, "channel")
    if channel_nodes:
        title = _first_text(channel_nodes[0], ["title"])
        if title:
            return title

    title = _first_text(root, ["title"])
    return title or "Security Blog"


def _entry_nodes(root: ET.Element) -> List[ET.Element]:
    channel_nodes = _direct_children(root, "channel")
    if channel_nodes:
        return _direct_children(channel_nodes[0], "item")
    return _direct_children(root, "entry")


def _normalize_entry(feed_title: str, entry: ET.Element) -> Dict[str, Any]:
    published = _first_text(entry, ["published", "updated", "pubDate"])
    title = _first_text(entry, ["title"])
    summary = _first_text(entry, ["summary", "description", "content"])
    entry_id = _first_text(entry, ["id", "guid"])
    link = _extract_link(entry)

    return {
        "id": entry_id or link or title,
        "title": title.strip(),
        "description": summary.strip(),
        "content": summary.strip(),
        "source_type": "blog",
        "source_name": feed_title or "Security Blog",
        "published_at": _parse_published(published),
        "url": link,
        "severity": "",
        "cvss_score": None,
        "related_cves": [],
        "tags": [],
    }


def fetch_security_blogs(limit_per_feed: int = 5) -> List[Dict[str, Any]]:
    articles: List[Dict[str, Any]] = []

    for feed_url in RSS_FEEDS:
        xml_payload = request_text(feed_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=30)
        root = ET.fromstring(xml_payload)
        feed_title = _feed_title(root)

        for entry in _entry_nodes(root)[: max(limit_per_feed, 1)]:
            normalized = _normalize_entry(feed_title, entry)
            if normalized["title"]:
                articles.append(normalized)

    return articles
