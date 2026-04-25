from __future__ import annotations

import json
import mimetypes
import threading
from collections import deque
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, unquote, urlparse

from agent import (
    AutonomousCTIAgent,
    LOG_FILE,
    PROJECT_DIR,
    list_report_files,
    load_latest_run,
    save_latest_run,
)


WEB_DIR = PROJECT_DIR / "web"
RUN_LOCK = threading.Lock()


def _read_log_excerpt(lines: int = 120) -> list[str]:
    if not LOG_FILE.exists():
        return []

    buffer: deque[str] = deque(maxlen=max(lines, 1))
    with LOG_FILE.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            buffer.append(line.rstrip())
    return list(buffer)


def _safe_report_path(filename: str) -> Path:
    candidate = (PROJECT_DIR / filename).resolve()
    if candidate.parent != PROJECT_DIR.resolve() or candidate.suffix.lower() != ".pdf" or not candidate.exists():
        raise FileNotFoundError(filename)
    return candidate


def build_dashboard_payload() -> Dict[str, Any]:
    latest_run = load_latest_run()
    reports = list_report_files()
    latest_report = reports[0] if reports else None
    top_threats = latest_run.get("top_threats", [])
    collected_counts = latest_run.get("collected_counts", {})
    alerts = latest_run.get("operational_alerts", [])
    severity_counts = {"high": 0, "medium": 0, "low": 0}
    for alert in alerts:
        severity = str(alert.get("severity", "medium")).lower()
        if severity not in severity_counts:
            severity = "medium"
        severity_counts[severity] += 1

    return {
        "latest_run": latest_run,
        "reports": reports,
        "latest_report": latest_report,
        "health": {
            "ok": True,
            "running": RUN_LOCK.locked(),
            "report_count": len(reports),
            "alert_count": len(alerts),
            "alert_severity": severity_counts,
        },
        "overview": {
            "has_run": bool(latest_run),
            "source_total": sum(int(value) for value in collected_counts.values()) if collected_counts else 0,
            "decision_total": len(latest_run.get("decision_log", [])),
            "threat_total": len(top_threats),
            "critical_total": sum(1 for threat in top_threats if threat.get("priority") == "critical"),
            "high_total": sum(1 for threat in top_threats if threat.get("priority") == "high"),
            "top_score": max((int(threat.get("threat_score", 0)) for threat in top_threats), default=0),
        },
        "log_excerpt": _read_log_excerpt(),
    }


class DashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_json(self, payload: Dict[str, Any], status: int = HTTPStatus.OK) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, status: int, message: str) -> None:
        self._send_json({"error": message}, status=status)

    def _serve_report(self, filename: str, download: bool = False) -> None:
        try:
            report_path = _safe_report_path(unquote(filename))
        except FileNotFoundError:
            self._send_error_json(HTTPStatus.NOT_FOUND, "Report not found.")
            return

        content_type = mimetypes.guess_type(report_path.name)[0] or "application/pdf"
        body = report_path.read_bytes()
        disposition = "attachment" if download else "inline"

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Disposition", f'{disposition}; filename="{report_path.name}"')
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        if parsed.path in {"/", ""}:
            self.path = "/index.html"
            return super().do_GET()

        if parsed.path == "/api/dashboard":
            return self._send_json(build_dashboard_payload())

        if parsed.path == "/api/health":
            return self._send_json(build_dashboard_payload()["health"])

        if parsed.path == "/api/reports":
            return self._send_json({"reports": list_report_files()})

        if parsed.path == "/api/logs":
            lines = int(query.get("lines", ["120"])[0] or "120")
            return self._send_json({"lines": _read_log_excerpt(lines=lines)})

        if parsed.path.startswith("/reports/"):
            filename = parsed.path.removeprefix("/reports/")
            return self._serve_report(filename, download=query.get("download", ["0"])[0] == "1")

        if parsed.path == "/favicon.ico":
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_headers()
            return

        return super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path != "/api/run":
            return self._send_error_json(HTTPStatus.NOT_FOUND, "Endpoint not found.")

        if RUN_LOCK.locked():
            return self._send_error_json(HTTPStatus.CONFLICT, "A CTI run is already in progress.")

        content_length = int(self.headers.get("Content-Length", "0") or "0")
        raw_body = self.rfile.read(content_length) if content_length else b"{}"
        try:
            payload = json.loads(raw_body.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            return self._send_error_json(HTTPStatus.BAD_REQUEST, "Request body must be valid JSON.")

        goal = str(payload.get("goal", "") or "").strip() or None

        with RUN_LOCK:
            try:
                agent = AutonomousCTIAgent()
                result = agent.run(goal=goal)
                save_latest_run(result)
            except Exception as exc:
                return self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

        dashboard = build_dashboard_payload()
        dashboard["run_result"] = result
        return self._send_json(dashboard)


def run_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    if not WEB_DIR.exists():
        raise FileNotFoundError(f"Web assets directory is missing: {WEB_DIR}")

    server = ThreadingHTTPServer((host, port), DashboardHandler)
    print(f"CTI dashboard running at http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    run_server()
