def calculate_score(item):
    score = 0
    text = (item.get("title", "") + " " + item.get("description", "")).lower()
    
    keywords = {
        "ransomware": 4, "zero-day": 5, "exploit": 3, "data breach": 4,
        "rce": 4, "remote code": 4, "supply chain": 3, "critical": 5
    }
    
    for kw, points in keywords.items():
        if kw in text:
            score += points
    
    if "related_cves" in item:
        score += 5
        for cve in item["related_cves"]:
            sev = cve.get("severity", "").upper()
            if sev == "CRITICAL": score += 6
            elif sev == "HIGH": score += 4
            elif sev == "MEDIUM": score += 2
    
    return min(score, 25)  # cap the score

def score_threats(data):
    for item in data:
        item["threat_score"] = calculate_score(item)
    return sorted(data, key=lambda x: x.get("threat_score", 0), reverse=True)