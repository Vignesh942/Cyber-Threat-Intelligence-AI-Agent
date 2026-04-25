from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


MEMORY_FILE = Path(__file__).resolve().with_name("threat_memory.json")


def load_memory(path: Optional[Path] = None) -> List[Dict[str, Any]]:
    target = path or MEMORY_FILE
    if not target.exists():
        return []

    try:
        with target.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
            return payload if isinstance(payload, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def build_memory_index(records: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
    titles = set()
    ids = set()
    urls = set()

    for record in records:
        title = (record.get("title") or "").strip().lower()
        record_id = (record.get("id") or "").strip().lower()
        url = (record.get("url") or "").strip().lower()

        if title:
            titles.add(title)
        if record_id:
            ids.add(record_id)
        if url:
            urls.add(url)

    return {"titles": titles, "ids": ids, "urls": urls}


def update_memory(
    items: List[Dict[str, Any]],
    path: Optional[Path] = None,
    max_items: int = 750,
) -> Dict[str, Any]:
    target = path or MEMORY_FILE
    existing = load_memory(target)
    memory_index = build_memory_index(existing)
    stored = 0

    for item in items:
        title = (item.get("title") or "").strip().lower()
        record_id = (item.get("id") or "").strip().lower()
        url = (item.get("url") or "").strip().lower()

        if title and title in memory_index["titles"]:
            continue
        if record_id and record_id in memory_index["ids"]:
            continue
        if url and url in memory_index["urls"]:
            continue

        record = item.copy()
        record["stored_at"] = datetime.now(timezone.utc).isoformat()
        existing.append(record)
        stored += 1

        if title:
            memory_index["titles"].add(title)
        if record_id:
            memory_index["ids"].add(record_id)
        if url:
            memory_index["urls"].add(url)

    trimmed = existing[-max_items:]
    with target.open("w", encoding="utf-8") as handle:
        json.dump(trimmed, handle, ensure_ascii=False, indent=2)

    return {"stored": stored, "total": len(trimmed), "path": str(target)}