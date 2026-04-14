import requests
from datetime import datetime, timedelta

def fetch_cve_data(days: int = 2):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    start_date = (datetime.utcnow() - timedelta(days=days)).isoformat() + "Z"
    params = {
        "pubStartDate": start_date,
        "resultsPerPage": 15
    }
    try:
        res = requests.get(url, params=params, timeout=15)
        if res.status_code != 200:
            return []
        data = res.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            severity = "UNKNOWN"
            metrics = cve.get("metrics", {})
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
            cves.append({
                "title": cve.get("id", ""),
                "description": cve.get("descriptions", [{}])[0].get("value", ""),
                "severity": severity,
                "source": "NVD"
            })
        return cves
    except Exception:
        return []