from __future__ import annotations

import json
import logging
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from blogs import fetch_security_blogs
from correlation import build_threat_dataset
from cve import fetch_cve_data
from env_utils import load_dotenv
from http_utils import request_json
from memory import build_memory_index, load_memory, update_memory
from news import get_news
from report import build_operational_recommendations, create_pdf, render_markdown_report
from scoring import score_threats


PROJECT_DIR = Path(__file__).resolve().parent
LOG_FILE = PROJECT_DIR / "cti_agent.log"
LATEST_RUN_FILE = PROJECT_DIR / "latest_run.json"
load_dotenv(PROJECT_DIR / ".env")


def _configure_logging() -> logging.Logger:
    logger = logging.getLogger("cti_agent")
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    return logger


LOGGER = _configure_logging()


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name, str(default)).strip()
    try:
        return int(value)
    except ValueError:
        return default


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _decision_breakdown(decisions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    counts: Dict[str, int] = {}
    for decision in decisions:
        step = decision.get("step", "unknown")
        counts[step] = counts.get(step, 0) + 1
    return [{"step": step, "count": count} for step, count in sorted(counts.items())]


def _source_rollup(collected: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    grouped: Dict[tuple[str, str], Dict[str, Any]] = {}

    for category, items in collected.items():
        for item in items:
            source_type = (item.get("source_type") or category or "unknown").lower()
            source_name = item.get("source_name") or "Unknown source"
            key = (source_type, source_name)
            if key not in grouped:
                grouped[key] = {
                    "source_type": source_type,
                    "source_name": source_name,
                    "count": 0,
                    "sample_titles": [],
                    "latest_url": item.get("url", ""),
                }

            bucket = grouped[key]
            bucket["count"] += 1
            if item.get("url"):
                bucket["latest_url"] = item["url"]

            title = (item.get("title") or "").strip()
            if title and len(bucket["sample_titles"]) < 3:
                bucket["sample_titles"].append(title)

    return sorted(grouped.values(), key=lambda item: (-item.get("count", 0), item.get("source_name", "")))


def _report_record(path: Path) -> Dict[str, Any]:
    stat = path.stat()
    return {
        "filename": path.name,
        "path": str(path),
        "size_bytes": stat.st_size,
        "modified_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        "view_url": f"/reports/{path.name}",
        "download_url": f"/reports/{path.name}?download=1",
    }


def list_report_files(output_dir: Optional[Path] = None, limit: int = 12) -> List[Dict[str, Any]]:
    target_dir = output_dir or PROJECT_DIR
    reports = sorted(
        target_dir.glob("Cyber_Threat_Report_*.pdf"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    return [_report_record(path) for path in reports[: max(limit, 1)]]


def load_latest_run(path: Optional[Path] = None) -> Dict[str, Any]:
    target = path or LATEST_RUN_FILE
    if not target.exists():
        return {}

    try:
        with target.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
            return payload if isinstance(payload, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def save_latest_run(result: Dict[str, Any], path: Optional[Path] = None) -> str:
    target = path or LATEST_RUN_FILE
    with target.open("w", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
    return str(target)


def _step_label(step: str) -> str:
    labels = {
        "collect_news": "News collection",
        "collect_blogs": "Blog collection",
        "collect_cves": "CVE collection",
        "summarize": "LLM summarization",
        "memory": "Memory update",
        "report": "Report generation",
        "analyze": "Threat analysis",
        "score": "Threat scoring",
    }
    return labels.get(step, step.replace("_", " ").strip().title())


def _clean_detail_text(value: str, max_length: int = 260) -> str:
    cleaned = re.sub(r"\s+", " ", value or "").strip()
    if len(cleaned) <= max_length:
        return cleaned
    return cleaned[: max_length - 3].rstrip() + "..."


def _sanitize_technical_details(value: str, max_length: int = 1200) -> str:
    detail = (value or "").strip()
    if not detail:
        return "No additional technical details were captured."

    lowered = detail.lower()
    if "<html" in lowered or "<!doctype html" in lowered:
        if "cloudflare" in lowered:
            detail = "Cloudflare challenge page returned by remote source. Raw HTML omitted."
        else:
            detail = "Remote source returned an HTML response instead of structured feed content. Raw HTML omitted."
    else:
        detail = re.sub(r"\s+", " ", detail)

    if len(detail) > max_length:
        detail = detail[: max_length - 3].rstrip() + "..."
    return detail


def _build_operational_alert(step: str, exc: Exception, timestamp: str) -> Dict[str, Any]:
    raw_message = str(exc).strip()
    lowered = raw_message.lower()
    label = _step_label(step)
    severity = "medium"
    summary = f"{label} failed"
    detail = _clean_detail_text(raw_message)

    if "cloudflare" in lowered and "403" in lowered:
        summary = f"{label} failed - HTTP 403 (Cloudflare protection)"
        detail = "Remote source returned a Cloudflare anti-bot challenge instead of the expected feed."
        severity = "high"
    elif "http 403" in lowered:
        summary = f"{label} failed - HTTP 403"
        detail = "Remote source rejected the request before content could be collected."
        severity = "high"
    elif "http 401" in lowered or "access denied" in lowered:
        summary = f"{label} failed - access denied"
        detail = "Authentication or upstream access policy blocked the request."
        severity = "high"
    elif "timed out" in lowered or "timeout" in lowered:
        summary = f"{label} failed - request timed out"
        detail = "The upstream request exceeded the configured timeout window."
        severity = "medium"
    elif "forbidden by its access permissions" in lowered or "winerror 10013" in lowered:
        summary = f"{label} failed - network access blocked"
        detail = "The current runtime environment could not establish the outbound network connection."
        severity = "medium"
    elif "name or service not known" in lowered or "temporary failure in name resolution" in lowered:
        summary = f"{label} failed - DNS resolution issue"
        detail = "The runtime could not resolve the upstream hostname."
        severity = "medium"
    elif step == "summarize":
        summary = f"{label} failed - fallback summary used"
        detail = "The model response could not be retrieved, so the deterministic summary path was used."
        severity = "medium"

    return {
        "timestamp": timestamp,
        "step": step,
        "label": label,
        "severity": severity,
        "summary": summary,
        "detail": detail,
        "technical_details": _sanitize_technical_details(raw_message),
    }


@dataclass
class AgentConfig:
    goal: str = "Continuously identify, prioritize, and summarize the most actionable cyber threats."
    news_days: int = _env_int("NEWS_DAYS", 2)
    cve_days: int = _env_int("CVE_DAYS", 7)
    top_threats: int = _env_int("TOP_THREATS", 10)
    groq_api_key: str = os.getenv("GROQ_API_KEY", "").strip()
    groq_model: str = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant").strip()


class GroqClient:
    def __init__(self, api_key: str, model: str) -> None:
        self.api_key = api_key
        self.model = model
        self.url = "https://api.groq.com/openai/v1/chat/completions"

    def available(self) -> bool:
        return bool(self.api_key and "replace_with" not in self.api_key)

    def summarize(self, goal: str, top_threats: List[Dict[str, Any]]) -> str:
        if not self.available() or not top_threats:
            return ""

        prompt = {
            "goal": goal,
            "top_threats": [
                {
                    "title": item.get("title"),
                    "priority": item.get("priority"),
                    "score": item.get("threat_score"),
                    "summary": item.get("description") or item.get("content"),
                    "severity": item.get("severity"),
                    "source": item.get("source_name"),
                    "related_cves": [cve.get("id") for cve in item.get("related_cves", []) if cve.get("id")],
                }
                for item in top_threats[:5]
            ],
        }

        payload = {
            "model": self.model,
            "temperature": 0.2,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a cyber threat intelligence analyst. "
                        "Return a concise executive summary using only the provided data. "
                        "Use 3 to 5 short lines. No markdown bullets."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(prompt, ensure_ascii=False),
                },
            ],
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        data = request_json(
            self.url,
            method="POST",
            headers=headers,
            json_body=payload,
            timeout=45,
        )
        return data["choices"][0]["message"]["content"].strip()


class AutonomousCTIAgent:
    def __init__(self, config: Optional[AgentConfig] = None) -> None:
        self.config = config or AgentConfig()
        self.llm = GroqClient(self.config.groq_api_key, self.config.groq_model)
        self.decisions: List[Dict[str, Any]] = []
        self.errors: List[str] = []
        self.operational_alerts: List[Dict[str, Any]] = []

    def _record_decision(self, step: str, detail: str) -> None:
        self.decisions.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "step": step,
                "detail": detail,
            }
        )
        LOGGER.info("%s: %s", step, detail)

    def _capture_error(self, step: str, exc: Exception) -> None:
        timestamp = _utc_now_iso()
        alert = _build_operational_alert(step, exc, timestamp)
        self.errors.append(alert["summary"])
        self.operational_alerts.append(alert)
        LOGGER.exception("%s failed: %s", step, exc)

    def collect_intelligence(self) -> Dict[str, List[Dict[str, Any]]]:
        collectors = {
            "news": lambda: get_news(days=self.config.news_days),
            "blogs": fetch_security_blogs,
            "cves": lambda: fetch_cve_data(days=self.config.cve_days),
        }
        results: Dict[str, List[Dict[str, Any]]] = {"news": [], "blogs": [], "cves": []}

        with ThreadPoolExecutor(max_workers=3) as executor:
            future_map = {executor.submit(func): name for name, func in collectors.items()}
            for future in as_completed(future_map):
                name = future_map[future]
                try:
                    results[name] = future.result()
                    self._record_decision("collect", f"{name} collected: {len(results[name])} items")
                except Exception as exc:
                    self._capture_error(f"collect_{name}", exc)
                    results[name] = []

        return results

    def analyze(self, collected: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        memory = load_memory()
        memory_index = build_memory_index(memory)

        dataset = build_threat_dataset(
            collected.get("news", []),
            collected.get("blogs", []),
            collected.get("cves", []),
        )
        self._record_decision("analyze", f"dataset built: {len(dataset)} unique records")

        scored = score_threats(
            dataset,
            known_titles=memory_index["titles"],
            known_ids=memory_index["ids"],
        )
        self._record_decision("score", f"threats scored: {len(scored)}")
        return scored

    def decide_report_type(self, scored: List[Dict[str, Any]]) -> str:
        if not scored:
            report_type = "standard"
        else:
            critical_count = sum(1 for item in scored[:10] if item.get("priority") == "critical")
            top_score = scored[0].get("threat_score", 0)
            if critical_count >= 2 or top_score >= 90:
                report_type = "urgent"
            elif top_score >= 70:
                report_type = "priority"
            else:
                report_type = "standard"

        self._record_decision("decide", f"report type selected: {report_type}")
        return report_type

    def build_summary(self, top_threats: List[Dict[str, Any]]) -> str:
        try:
            summary = self.llm.summarize(self.config.goal, top_threats)
            if summary:
                self._record_decision("summarize", "llm summary generated")
            else:
                self._record_decision("summarize", "llm unavailable, using deterministic summary")
            return summary
        except Exception as exc:
            self._capture_error("summarize", exc)
            return ""

    def persist(self, scored: List[Dict[str, Any]], report_content: str, report_type: str) -> Dict[str, Any]:
        memory_result = update_memory(scored)
        self._record_decision("memory", f"stored {memory_result['stored']} new records")

        report_file = create_pdf(report_content, report_type=report_type, output_dir=PROJECT_DIR)
        self._record_decision("report", f"pdf generated: {report_file}")
        return {"memory": memory_result, "report_file": report_file}

    def run(self, goal: Optional[str] = None) -> Dict[str, Any]:
        if goal:
            self.config.goal = goal
            self._record_decision("goal", "custom mission goal received")

        self._record_decision("start", "autonomous CTI run started")
        collected = self.collect_intelligence()
        scored = self.analyze(collected)
        report_type = self.decide_report_type(scored)
        top_threats = scored[: max(self.config.top_threats, 1)]
        ai_summary = self.build_summary(top_threats)
        recommendations = build_operational_recommendations(top_threats)
        report_content = render_markdown_report(
            goal=self.config.goal,
            report_type=report_type,
            top_threats=top_threats,
            decisions=self.decisions,
            errors=self.errors,
            ai_summary=ai_summary,
        )
        persisted = self.persist(scored, report_content, report_type)
        self._record_decision("finish", "autonomous CTI run completed")

        result = {
            "generated_at": _utc_now_iso(),
            "goal": self.config.goal,
            "report_type": report_type,
            "top_threats": top_threats,
            "decision_log": list(self.decisions),
            "decision_breakdown": _decision_breakdown(self.decisions),
            "errors": self.errors,
            "operational_alerts": list(self.operational_alerts),
            "memory": persisted["memory"],
            "report": persisted["report_file"],
            "report_filename": Path(persisted["report_file"]).name,
            "report_markdown": report_content,
            "executive_summary": ai_summary.strip(),
            "operational_recommendations": recommendations,
            "collected_counts": {name: len(items) for name, items in collected.items()},
            "collected_items": collected,
            "source_rollup": _source_rollup(collected),
            "report_library": list_report_files(),
        }
        return result


def run_ai_agent(goal: Optional[str] = None) -> Dict[str, Any]:
    agent = AutonomousCTIAgent()
    result = agent.run(goal=goal)
    save_latest_run(result)

    print("\nAutonomous CTI Agent Run Complete")
    print(f"Goal: {result['goal']}")
    print(f"Report Type: {result['report_type']}")
    print(f"Collected: {result['collected_counts']}")
    print(f"Top Threats: {len(result['top_threats'])}")
    print(f"Report: {result['report']}")
    if result["errors"]:
        print(f"Errors: {len(result['errors'])}")
    else:
        print("Errors: 0")

    return result


if __name__ == "__main__":
    run_ai_agent()
