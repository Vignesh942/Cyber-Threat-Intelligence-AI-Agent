from __future__ import annotations

from datetime import datetime
from pathlib import Path
from textwrap import wrap
from typing import Any, Dict, List, Optional


PROJECT_DIR = Path(__file__).resolve().parent


def build_operational_recommendations(top_threats: List[Dict[str, Any]]) -> List[str]:
    if not top_threats:
        return ["No urgent action is required, but continue continuous monitoring."]

    return [
        "Patch or mitigate any critical or high-severity CVEs first.",
        "Review external-facing systems, identity infrastructure, and exposed services for matching indicators.",
        "Tune detections for exploit attempts, suspicious authentication activity, and ransomware precursor behaviors.",
        "Validate backups, privileged access controls, and incident-response escalation paths.",
    ]


def render_markdown_report(
    goal: str,
    report_type: str,
    top_threats: List[Dict[str, Any]],
    decisions: List[Dict[str, Any]],
    errors: List[str],
    ai_summary: str = "",
) -> str:
    lines: List[str] = []
    lines.append("# Cyber Threat Intelligence Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Report Type: {report_type.upper()}")
    lines.append(f"Mission Goal: {goal}")
    lines.append("")

    lines.append("## Executive Summary")
    if ai_summary.strip():
        lines.extend(ai_summary.strip().splitlines())
    else:
        critical_count = sum(1 for item in top_threats if item.get("priority") == "critical")
        high_count = sum(1 for item in top_threats if item.get("priority") == "high")
        lines.append(
            f"The agent identified {len(top_threats)} prioritized threats, including "
            f"{critical_count} critical and {high_count} high-priority items."
        )
        if top_threats:
            lead = top_threats[0]
            lines.append(
                "The highest-risk item is "
                f"{lead.get('title', 'Unknown threat')} with a score of {lead.get('threat_score', 0)}/100."
            )
        lines.append("Priority was based on severity, exploitation indicators, recency, source quality, and novelty.")
    lines.append("")

    lines.append("## Top Prioritized Threats")
    if not top_threats:
        lines.append("- No actionable threats were collected during this run.")
    for index, threat in enumerate(top_threats, start=1):
        lines.append(
            f"### {index}. {threat.get('title', 'Untitled Threat')} "
            f"(Priority: {threat.get('priority', 'low').upper()}, Score: {threat.get('threat_score', 0)}/100)"
        )
        lines.append(f"- Source: {threat.get('source_name', 'Unknown')} ({threat.get('source_type', 'intel')})")
        lines.append(f"- Published: {threat.get('published_at', 'Unknown')}")
        if threat.get("severity"):
            lines.append(f"- Severity: {threat.get('severity')}")
        if threat.get("cvss_score") is not None:
            lines.append(f"- CVSS Score: {threat.get('cvss_score')}")
        if threat.get("related_cves"):
            lines.append(
                "- Related CVEs: "
                + ", ".join(cve.get("id", "") for cve in threat.get("related_cves", []) if cve.get("id"))
            )
        description = threat.get("description") or threat.get("content") or "No description provided."
        lines.append(f"- Summary: {description}")
        lines.append(f"- Link: {threat.get('url', 'N/A')}")
        if threat.get("score_reasons"):
            lines.append("- Why Prioritized: " + ", ".join(threat.get("score_reasons", [])))
        lines.append("")

    lines.append("## Agent Decisions")
    if decisions:
        for decision in decisions:
            lines.append(f"- {decision.get('timestamp')}: {decision.get('step')} -> {decision.get('detail')}")
    else:
        lines.append("- No decision records were captured.")
    lines.append("")

    lines.append("## Operational Recommendations")
    for recommendation in build_operational_recommendations(top_threats):
        lines.append(f"- {recommendation}")
    lines.append("")

    if errors:
        lines.append("## Errors")
        for error in errors:
            lines.append(f"- {error}")
        lines.append("")

    return "\n".join(lines).strip() + "\n"


def create_pdf(content: str, report_type: str = "standard", output_dir: Optional[Path] = None) -> str:
    target_dir = output_dir or PROJECT_DIR
    filename = target_dir / f"Cyber_Threat_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    lines = _layout_report_lines(content, report_type)
    pdf_bytes = _build_pdf(lines)
    filename.write_bytes(pdf_bytes)
    return str(filename)


def _layout_report_lines(content: str, report_type: str) -> List[Dict[str, Any]]:
    lines: List[Dict[str, Any]] = []

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            lines.append({"text": "", "font_size": 10, "is_blank": True})
            continue

        if line.startswith("# "):
            lines.extend(_wrapped_lines(line[2:], font_size=18, max_chars=52))
        elif line.startswith("## "):
            lines.extend(_wrapped_lines(line[3:], font_size=14, max_chars=68))
        elif line.startswith("### "):
            lines.extend(_wrapped_lines(line[4:], font_size=12, max_chars=76))
        elif line.startswith("- "):
            lines.extend(_wrapped_lines(f"- {line[2:]}", font_size=10, max_chars=100))
        else:
            lines.extend(_wrapped_lines(line, font_size=10, max_chars=102))

    if lines:
        lines[0]["font_size"] = 20 if report_type == "urgent" else 18
    return lines


def _wrapped_lines(text: str, font_size: int, max_chars: int) -> List[Dict[str, Any]]:
    safe_text = text.encode("latin-1", "replace").decode("latin-1")
    wrapped = wrap(safe_text, width=max_chars, break_long_words=False, replace_whitespace=False) or [safe_text]
    return [{"text": line, "font_size": font_size, "is_blank": False} for line in wrapped]


def _escape_pdf_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _paginate_lines(lines: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
    pages: List[List[Dict[str, Any]]] = []
    current_page: List[Dict[str, Any]] = []
    current_y = 742

    for line in lines:
        if line["is_blank"]:
            required_height = 10
        else:
            required_height = line["font_size"] + 8

        if current_y - required_height < 54 and current_page:
            pages.append(current_page)
            current_page = []
            current_y = 742

        current_page.append(line)
        current_y -= required_height

    if current_page:
        pages.append(current_page)

    return pages or [[{"text": "Empty report", "font_size": 12, "is_blank": False}]]


def _page_stream(page_lines: List[Dict[str, Any]]) -> bytes:
    commands: List[str] = []
    y_position = 742

    for line in page_lines:
        if line["is_blank"]:
            y_position -= 10
            continue

        font_size = int(line["font_size"])
        text = _escape_pdf_text(line["text"])
        commands.append(f"BT /F1 {font_size} Tf 54 {y_position} Td ({text}) Tj ET")
        y_position -= font_size + 8

    return "\n".join(commands).encode("latin-1", "replace")


def _build_pdf(lines: List[Dict[str, Any]]) -> bytes:
    pages = _paginate_lines(lines)
    objects: List[bytes] = []

    def add_object(payload: bytes) -> int:
        objects.append(payload)
        return len(objects)

    catalog_id = add_object(b"<< /Type /Catalog /Pages 2 0 R >>")
    add_object(b"<< /Type /Pages /Count 0 /Kids [] >>")
    font_id = add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    page_ids: List[int] = []
    for page_lines in pages:
        content_stream = _page_stream(page_lines)
        content_id = add_object(
            f"<< /Length {len(content_stream)} >>\nstream\n".encode("latin-1")
            + content_stream
            + b"\nendstream"
        )
        page_id = add_object(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>".encode("latin-1")
        )
        page_ids.append(page_id)

    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects[1] = f"<< /Type /Pages /Count {len(page_ids)} /Kids [{kids}] >>".encode("latin-1")

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, payload in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{index} 0 obj\n".encode("latin-1"))
        pdf.extend(payload)
        pdf.extend(b"\nendobj\n")

    xref_start = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("latin-1"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("latin-1"))

    pdf.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\n"
            f"startxref\n{xref_start}\n%%EOF"
        ).encode("latin-1")
    )
    return bytes(pdf)
