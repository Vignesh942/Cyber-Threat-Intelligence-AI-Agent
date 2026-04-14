import json
import os
from datetime import datetime

FILE = "threat_memory.json"

def load_memory():
    if not os.path.exists(FILE):
        return []
    try:
        with open(FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return []

def update_memory(data):
    memory = load_memory()
    titles = {x.get("title") for x in memory if "title" in x}
    added = 0
    for item in data:
        if item.get("title") not in titles:
            item["stored_at"] = datetime.now().isoformat()
            memory.append(item)
            added += 1
    with open(FILE, "w", encoding="utf-8") as f:
        json.dump(memory[-200:], f, indent=2, ensure_ascii=False)  # keep last 200
    return {"stored": added, "total": len(memory)}