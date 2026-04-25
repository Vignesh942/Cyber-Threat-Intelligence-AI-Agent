from __future__ import annotations

import re
from copy import deepcopy
from typing import Any, Dict, Iterable, List


CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def extract_cve_ids(text: str) -> List[str]:
    if not text:
        return []
    return list(dict.fromkeys(match.upper() for match in CVE_PATTERN.findall(text)))


def deduplicate_items(items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    unique_items: List[Dict[str, Any]] = []

    for item in items:
        key = (
            (item.get("source_type") or "").lower(),
            (item.get("id") or "").strip().lower(),
            (item.get("title") or "").strip().lower(),
            (item.get("url") or "").strip().lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        unique_items.append(item)

    return unique_items


def correlate_data(content_items: List[Dict[str, Any]], cve_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    cve_map = {item.get("id", "").upper(): item for item in cve_items if item.get("id")}
    correlated: List[Dict[str, Any]] = []

    for item in content_items:
        enriched = deepcopy(item)
        combined_text = " ".join(
            [
                item.get("title", ""),
                item.get("description", ""),
                item.get("content", ""),
            ]
        )
        detected_ids = [cve_id for cve_id in extract_cve_ids(combined_text) if cve_id in cve_map]
        enriched["related_cves"] = [deepcopy(cve_map[cve_id]) for cve_id in detected_ids]
        enriched["detected_cve_ids"] = detected_ids
        correlated.append(enriched)

    return correlated


def build_threat_dataset(
    news_items: List[Dict[str, Any]],
    blog_items: List[Dict[str, Any]],
    cve_items: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    content_items = correlate_data(news_items + blog_items, cve_items)
    combined = content_items + deepcopy(cve_items)
    return deduplicate_items(combined)