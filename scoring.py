from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set


KEYWORD_WEIGHTS = {
    "ransomware": 18,
    "zero-day": 20,
    "zero day": 20,
    "actively exploited": 20,
    "data breach": 18,
    "supply chain": 14,
    "remote code execution": 16,
    "rce": 14,
    "credential theft": 12,
    "malware": 10,
    "botnet": 10,
    "phishing": 8,
    "vulnerability": 8,
    "exploit": 12,
    "critical": 10,
}

SEVERITY_WEIGHTS = {
    "CRITICAL": 35,
    "HIGH": 25,
    "MEDIUM": 15,
    "LOW": 8,
    "UNKNOWN": 0,
}

TRUSTED_SOURCES = {"NVD", "BleepingComputer", "Krebs on Security", "The Hacker News", "Dark Reading"}


def _parse_datetime(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def classify_priority(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def calculate_score(item: Dict[str, Any], known_titles: Optional[Set[str]] = None, known_ids: Optional[Set[str]] = None) -> Dict[str, Any]:
    score = 0
    reasons: List[str] = []
    text = " ".join(
        [
            item.get("title", ""),
            item.get("description", ""),
            item.get("content", ""),
        ]
    ).lower()

    for keyword, weight in KEYWORD_WEIGHTS.items():
        if keyword in text:
            score += weight
            reasons.append(f"keyword:{keyword}")

    severity = str(item.get("severity") or "UNKNOWN").upper()
    if severity in SEVERITY_WEIGHTS:
        score += SEVERITY_WEIGHTS[severity]
        if severity != "UNKNOWN":
            reasons.append(f"severity:{severity}")

    cvss_score = item.get("cvss_score")
    if isinstance(cvss_score, (int, float)):
        boost = min(int(float(cvss_score) * 2), 20)
        score += boost
        reasons.append(f"cvss:{cvss_score}")

    related_cves = item.get("related_cves") or []
    if related_cves:
        score += 15
        reasons.append("related_cves")
        highest_related = max(str(cve.get("severity") or "UNKNOWN").upper() for cve in related_cves)
        if highest_related in {"CRITICAL", "HIGH"}:
            score += 10
            reasons.append(f"related_severity:{highest_related}")

    published_at = _parse_datetime(item.get("published_at", ""))
    if published_at:
        age = datetime.now(timezone.utc) - published_at.astimezone(timezone.utc)
        if age.total_seconds() <= 86400:
            score += 10
            reasons.append("recent_24h")
        elif age.total_seconds() <= 259200:
            score += 5
            reasons.append("recent_72h")

    source_name = item.get("source_name", "")
    if source_name in TRUSTED_SOURCES:
        score += 5
        reasons.append(f"source:{source_name}")

    title_key = (item.get("title") or "").strip().lower()
    id_key = (item.get("id") or "").strip().lower()
    is_new = True
    if known_titles and title_key and title_key in known_titles:
        is_new = False
    if known_ids and id_key and id_key in known_ids:
        is_new = False

    if is_new:
        score += 10
        reasons.append("novel_item")

    final_score = min(score, 100)
    return {
        "threat_score": final_score,
        "priority": classify_priority(final_score),
        "score_reasons": reasons,
        "is_new": is_new,
    }


def score_threats(
    items: List[Dict[str, Any]],
    known_titles: Optional[Set[str]] = None,
    known_ids: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    scored_items: List[Dict[str, Any]] = []
    for item in items:
        scored = item.copy()
        scored.update(calculate_score(item, known_titles=known_titles, known_ids=known_ids))
        scored_items.append(scored)

    return sorted(scored_items, key=lambda item: item.get("threat_score", 0), reverse=True)