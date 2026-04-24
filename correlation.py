import re

def extract_cve_ids(text):
    return re.findall(r"CVE-\d{4}-\d{4,7}", text or "")

def correlate_data(news_data, cve_data):
    result = []
    cve_dict = {cve["title"].upper(): cve for cve in cve_data}
    
    for article in news_data:
        text = (article.get("title", "") + " " + article.get("description", "")).upper()
        found_ids = extract_cve_ids(text)
        matches = [cve_dict[cve_id] for cve_id in found_ids if cve_id in cve_dict]
        
        if matches:
            article = article.copy()
            article["related_cves"] = matches
        result.append(article)
    return result
