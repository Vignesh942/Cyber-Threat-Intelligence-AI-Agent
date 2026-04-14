from langchain_groq import ChatGroq
from langgraph.graph import StateGraph, END
from typing import TypedDict, List, Dict, Optional, Literal
from dotenv import load_dotenv
import os
import json
import logging
from datetime import datetime
import sys
import time

# Your modules
from news import get_news
from blogs import fetch_security_blogs
from cve import fetch_cve_data
from correlation import correlate_data
from scoring import score_threats
from memory import update_memory
from report import create_pdf

# Fix Windows console encoding
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# Logging setup
class SafeStreamHandler(logging.StreamHandler):
    def emit(self, record):
        try:
            if sys.platform == "win32" and hasattr(record, 'msg') and isinstance(record.msg, str):
                # Remove emojis for Windows console
                import re
                record.msg = re.sub(r'[^\x00-\x7F]+', '', record.msg)
            super().emit(record)
        except Exception:
            pass

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cti_agent.log', encoding='utf-8'),
        SafeStreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load env
load_dotenv()

# LLM
llm = ChatGroq(
    model="llama-3.1-8b-instant",
    temperature=0.1,
    max_tokens=1000,
    groq_api_key=os.getenv("GROQ_API_KEY")
)

# -------------------------------
# Enhanced Agent State
# -------------------------------
class AgentState(TypedDict):
    messages: List[str]
    data: Dict
    report: Optional[str]
    errors: List[str]
    iteration: int
    high_severity_found: bool
    decision_log: List[Dict]


# -------------------------------
# Nodes with Error Handling
# -------------------------------

def fetch_news_node(state: AgentState) -> AgentState:
    """Fetch news with retry logic and error handling"""
    try:
        news = get_news(days=2)
        
        new_state = state.copy()
        if "data" not in new_state:
            new_state["data"] = {}
        new_state["data"]["news"] = news
        new_state["messages"].append(f"Fetched {len(news)} news articles")
        
        logger.info(f"News fetched: {len(news)} articles")
        
        if len(news) < 5:
            new_state["messages"].append("Low news volume, may need alternative sources")
            logger.warning("Low news article count")
        
        return new_state
        
    except Exception as e:
        logger.error(f"News fetch failed: {str(e)}")
        new_state = state.copy()
        if "data" not in new_state:
            new_state["data"] = {}
        new_state["errors"].append(f"News fetch error: {str(e)}")
        new_state["data"]["news"] = []
        return new_state


def fetch_blogs_node(state: AgentState) -> AgentState:
    """Fetch security blogs with error handling"""
    try:
        blogs = fetch_security_blogs()
        
        new_state = state.copy()
        if "data" not in new_state:
            new_state["data"] = {}
        new_state["data"]["blogs"] = blogs
        new_state["messages"].append(f"Fetched {len(blogs)} blog posts")
        
        logger.info(f"Blogs fetched: {len(blogs)} posts")
        return new_state
        
    except Exception as e:
        logger.error(f"Blog fetch failed: {str(e)}")
        new_state = state.copy()
        if "data" not in new_state:
            new_state["data"] = {}
        new_state["errors"].append(f"Blog fetch error: {str(e)}")
        new_state["data"]["blogs"] = []
        return new_state


def fetch_cves_node(state: AgentState) -> AgentState:
    """Fetch CVEs with error handling"""
    try:
        cves = fetch_cve_data(days=2)
        
        new_state = state.copy()
        if "data" not in new_state:
            new_state["data"] = {}
        new_state["data"]["cves"] = cves
        new_state["messages"].append(f"Fetched {len(cves)} CVEs")
        
        logger.info(f"CVEs fetched: {len(cves)}")
        
        critical_cves = [c for c in cves if c.get("severity", "").upper() in ["CRITICAL", "HIGH"]]
        if critical_cves:
            new_state["high_severity_found"] = True
            new_state["messages"].append(f"ALERT: {len(critical_cves)} critical/high CVEs detected")
            logger.warning(f"High severity CVEs found: {len(critical_cves)}")
        
        return new_state
        
    except Exception as e:
        logger.error(f"CVE fetch failed: {str(e)}")
        new_state = state.copy()
        if "data" not in new_state:
            new_state["data"] = {}
        new_state["errors"].append(f"CVE fetch error: {str(e)}")
        new_state["data"]["cves"] = []
        return new_state


def analyze_node(state: AgentState) -> AgentState:
    """Analyze and score threats"""
    try:
        news = state.get("data", {}).get("news", [])
        blogs = state.get("data", {}).get("blogs", [])
        cves = state.get("data", {}).get("cves", [])

        total_items = len(news) + len(blogs) + len(cves)
        if total_items == 0:
            logger.warning("No data to analyze")
            new_state = state.copy()
            if "data" not in new_state:
                new_state["data"] = {}
            new_state["messages"].append("No data available for analysis")
            new_state["data"]["scored"] = []
            return new_state

        logger.info(f"Analyzing {total_items} items")

        correlated = correlate_data(news, cves)
        merged = correlated + blogs

        seen = set()
        unique = []
        for item in merged:
            title = item.get("title", "")
            if title and title not in seen:
                seen.add(title)
                unique.append(item)

        scored = score_threats(unique)
        update_memory(scored)

        new_state = state.copy()
        if "data" not in new_state:
            new_state["data"] = {}
        new_state["data"]["scored"] = scored
        new_state["messages"].append(f"Analyzed {len(scored)} unique threats")
        
        high_threats = [t for t in scored if t.get("score", 0) >= 7.0]
        if high_threats:
            new_state["high_severity_found"] = True
            if "decision_log" not in new_state:
                new_state["decision_log"] = []
            new_state["decision_log"].append({
                "timestamp": datetime.now().isoformat(),
                "decision": "high_severity_detected",
                "count": len(high_threats),
                "action": "will_prioritize_in_report"
            })
            logger.warning(f"High-severity threats detected: {len(high_threats)}")
        
        logger.info(f"Analysis complete: {len(scored)} threats scored")
        return new_state
        
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        new_state = state.copy()
        if "data" not in new_state:
            new_state["data"] = {}
        new_state["errors"].append(f"Analysis error: {str(e)}")
        new_state["data"]["scored"] = []
        return new_state


def decision_node(state: AgentState) -> AgentState:
    """Agent makes intelligent decisions about report generation"""
    scored_data = state.get("data", {}).get("scored", [])
    
    new_state = state.copy()
    if "data" not in new_state:
        new_state["data"] = {}
    if "decision_log" not in new_state:
        new_state["decision_log"] = []
    
    if len(scored_data) == 0:
        new_state["decision_log"].append({
            "timestamp": datetime.now().isoformat(),
            "decision": "insufficient_data",
            "action": "skip_report_generation"
        })
        new_state["messages"].append("No threats to report")
        logger.warning("Skipping report: no data")
        new_state["report"] = "NO_DATA"
        return new_state
    
    high_severity = [t for t in scored_data if t.get("score", 0) >= 7.0]
    
    if len(high_severity) >= 3:
        new_state["data"]["report_type"] = "urgent"
        new_state["data"]["threat_limit"] = 10
        new_state["decision_log"].append({
            "timestamp": datetime.now().isoformat(),
            "decision": "high_threat_volume",
            "action": "generate_extended_urgent_report",
            "high_severity_count": len(high_severity)
        })
        logger.warning(f"Generating URGENT report: {len(high_severity)} high-severity threats")
    elif len(high_severity) > 0:
        new_state["data"]["report_type"] = "priority"
        new_state["data"]["threat_limit"] = 7
        logger.info("Generating priority report")
    else:
        new_state["data"]["report_type"] = "standard"
        new_state["data"]["threat_limit"] = 5
        logger.info("Generating standard report")
    
    return new_state


def generate_report_node(state: AgentState) -> AgentState:
    """Generate intelligent report based on agent decisions"""
    try:
        if state.get("report") == "NO_DATA":
            logger.info("Skipping report generation: no data")
            return state
        
        scored_data = state.get("data", {}).get("scored", [])
        report_type = state.get("data", {}).get("report_type", "standard")
        threat_limit = state.get("data", {}).get("threat_limit", 5)
        
        top_threats = sorted(
            scored_data, 
            key=lambda x: x.get("score", 0), 
            reverse=True
        )[:threat_limit]
        
        data_str = json.dumps(top_threats, indent=2, ensure_ascii=False)
        
        urgency_context = ""
        if report_type == "urgent":
            urgency_context = """
[URGENT] Multiple high-severity threats detected.
Focus on immediate action items and critical system impact.
"""
        elif report_type == "priority":
            urgency_context = """
Priority threats identified. Emphasize risk assessment and mitigation steps.
"""
        
        prompt = f"""
You are a senior Cyber Threat Intelligence Analyst writing for a SOC team.

{urgency_context}

Generate a high-quality Cyber Threat Intelligence Report using ONLY the data below.

Data:
{data_str}

STRICT RULES:
- No generic statements
- No filler sentences
- Focus on real threats and impact
- Use specific details from the data
- For {report_type} reports: be direct and actionable

FORMAT:

## Executive Summary
- 3-4 sentences
- Highlight most critical threats with scores
- {f"URGENT: Immediate action required" if report_type == "urgent" else ""}

## Top Prioritized Threats
For each threat (sorted by severity):
- **Title** (Score: X.X/10)
- **What Happened**: Specific incident details
- **Impact**: Why it matters
- **Associated CVEs**: (if any)
- **Affected Systems**: Be specific

## Key Insights
- Attack trends or patterns
- Common vulnerabilities
- Threat actor TTPs (if identified)

## Recommendations
- Specific, actionable steps
- Prioritized by threat score
- Include detection/mitigation guidance

Tone: Professional, analytical, urgent where appropriate.
"""
        
        logger.info(f"Generating {report_type} report for {len(top_threats)} threats...")
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                report_content = llm.invoke(prompt).content
                break
            except Exception as e:
                if "429" in str(e) and attempt < max_retries - 1:
                    wait_time = (attempt + 1) * 10
                    logger.warning(f"Rate limited, waiting {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    raise
        
        filename = create_pdf(report_content, report_type=report_type)
        
        new_state = state.copy()
        new_state["report"] = filename
        new_state["messages"].append(f"{report_type.upper()} report generated: {filename}")
        if "decision_log" not in new_state:
            new_state["decision_log"] = []
        new_state["decision_log"].append({
            "timestamp": datetime.now().isoformat(),
            "decision": "report_generated",
            "type": report_type,
            "threat_count": len(top_threats),
            "filename": filename
        })
        
        logger.info(f"Report saved: {filename}")
        return new_state
        
    except Exception as e:
        logger.error(f"Report generation failed: {str(e)}")
        new_state = state.copy()
        if "errors" not in new_state:
            new_state["errors"] = []
        new_state["errors"].append(f"Report generation error: {str(e)}")
        return new_state


# -------------------------------
# Intelligent Routing
# -------------------------------

def route(state: AgentState):
    """Intelligent routing based on state and errors"""
    data = state.get("data", {})
    iteration = state.get("iteration", 0)
    
    if iteration > 10:
        logger.error("Max iterations reached, stopping")
        return END
    
    if "news" not in data:
        return "fetch_news"
    
    if "blogs" not in data:
        return "fetch_blogs"
    
    if "cves" not in data:
        return "fetch_cves"
    
    if "scored" not in data:
        return "analyze"
    
    if "report_type" not in data:
        return "decide"
    
    if not state.get("report"):
        return "generate_report"
    
    return END


# -------------------------------
# Build Graph
# -------------------------------

builder = StateGraph(AgentState)

builder.add_node("fetch_news", fetch_news_node)
builder.add_node("fetch_blogs", fetch_blogs_node)
builder.add_node("fetch_cves", fetch_cves_node)
builder.add_node("analyze", analyze_node)
builder.add_node("decide", decision_node)
builder.add_node("generate_report", generate_report_node)

builder.set_entry_point("fetch_news")

builder.add_conditional_edges("fetch_news", route)
builder.add_conditional_edges("fetch_blogs", route)
builder.add_conditional_edges("fetch_cves", route)
builder.add_conditional_edges("analyze", route)
builder.add_conditional_edges("decide", route)
builder.add_conditional_edges("generate_report", route)

graph = builder.compile()


# -------------------------------
# Run Agent
# -------------------------------

def run_ai_agent():
    """Execute the autonomous CTI agent"""
    print("Autonomous Cyber Threat Intelligence Agent v2.0\n")
    logger.info("=" * 60)
    logger.info("Starting CTI Agent Run")
    logger.info("=" * 60)

    initial_state: AgentState = {
        "messages": [],
        "data": {},
        "report": None,
        "errors": [],
        "iteration": 0,
        "high_severity_found": False,
        "decision_log": []
    }

    try:
        result = graph.invoke(
            initial_state,
            config={"recursion_limit": 50}
        )

        print("\n" + "=" * 60)
        print("Agent Execution Complete")
        print("=" * 60)
        
        print(f"\nExecution Summary:")
        print(f"  - Messages: {len(result.get('messages', []))}")
        print(f"  - Errors: {len(result.get('errors', []))}")
        print(f"  - Decisions Made: {len(result.get('decision_log', []))}")
        print(f"  - High Severity Found: {result.get('high_severity_found', False)}")
        print(f"  - Report: {result.get('report', 'N/A')}")
        
        if result.get('decision_log'):
            print(f"\nAgent Decision Log:")
            for decision in result['decision_log']:
                print(f"  - [{decision['timestamp']}] {decision['decision']}: {decision.get('action', 'N/A')}")
        
        if result.get('errors'):
            print(f"\nErrors encountered:")
            for error in result['errors']:
                print(f"  - {error}")
        
        logger.info("Agent run completed successfully")
        return result
        
    except Exception as e:
        logger.error(f"Fatal error in agent execution: {str(e)}", exc_info=True)
        print(f"\nFatal Error: {str(e)}")
        raise


if __name__ == "__main__":
    run_ai_agent()
