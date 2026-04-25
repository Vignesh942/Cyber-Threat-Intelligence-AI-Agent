from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from http_utils import request_json


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_RANGE_DAYS = 120


def _format_nvd_datetime(value: datetime) -> str:
    utc_value = value.astimezone(timezone.utc)
    return utc_value.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _first_description(cve: Dict[str, Any]) -> str:
    for description in cve.get("descriptions", []):
        if description.get("lang") == "en":
            return description.get("value", "")
    descriptions = cve.get("descriptions", [])
    if descriptions:
        return descriptions[0].get("value", "")
    return ""


def _extract_cvss(metrics: Dict[str, Any]) -> Tuple[Optional[float], str]:
    metric_sets = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
    for metric_name in metric_sets:
        values = metrics.get(metric_name) or []
        if not values:
            continue
        cvss_data = values[0].get("cvssData", {})
        base_score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity") or values[0].get("baseSeverity") or "UNKNOWN"
        if base_score is not None:
            return float(base_score), str(severity).upper()
    return None, "UNKNOWN"


def _extract_weaknesses(cve: Dict[str, Any]) -> List[str]:
    weaknesses: List[str] = []
    for weakness in cve.get("weaknesses", []):
        for description in weakness.get("description", []):
            value = description.get("value")
            if value:
                weaknesses.append(value)
    return list(dict.fromkeys(weaknesses))


def _normalize_cve(item: Dict[str, Any]) -> Dict[str, Any]:
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    score, severity = _extract_cvss(cve.get("metrics", {}))

    return {
        "id": cve_id,
        "title": cve_id,
        "description": _first_description(cve),
        "content": _first_description(cve),
        "source_type": "cve",
        "source_name": "NVD",
        "published_at": cve.get("published", datetime.now(timezone.utc).isoformat()),
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "",
        "severity": severity,
        "cvss_score": score,
        "related_cves": [],
        "cwes": _extract_weaknesses(cve),
        "references": [ref.get("url") for ref in cve.get("references", []) if ref.get("url")],
        "tags": [],
    }


def fetch_cve_data(days: int = 7, results_per_page: int = 25) -> List[Dict[str, Any]]:
    bounded_days = min(max(days, 1), MAX_RANGE_DAYS)
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=bounded_days)
    params = {
        "pubStartDate": _format_nvd_datetime(start_date),
        "pubEndDate": _format_nvd_datetime(end_date),
        "resultsPerPage": max(1, min(results_per_page, 50)),
    }

    payload = request_json(NVD_API_URL, params=params, timeout=45)
    vulnerabilities = payload.get("vulnerabilities", [])
    return [_normalize_cve(item) for item in vulnerabilities if item.get("cve", {}).get("id")]
