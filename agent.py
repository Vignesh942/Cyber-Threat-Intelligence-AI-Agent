from langchain_groq import ChatGroq
from langgraph.graph import StateGraph, END
from typing import TypedDict, List, Dict
from dotenv import load_dotenv
import os
import json

# Your modules
from news import get_news
from blogs import fetch_security_blogs
from cve import fetch_cve_data
from correlation import correlate_data
from scoring import score_threats
from memory import update_memory
from report import create_pdf

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
# Agent State
# -------------------------------
class AgentState(TypedDict):
    messages: List[str]
    data: Dict
    report: str


# -------------------------------
# Nodes
# -------------------------------

def fetch_news_node(state: AgentState):
    news = get_news(days=2)
    state["data"]["news"] = news
    state["messages"].append(f"Fetched {len(news)} news")
    print(f"📰 News fetched: {len(news)}")
    return state


def fetch_blogs_node(state: AgentState):
    blogs = fetch_security_blogs()
    state["data"]["blogs"] = blogs
    state["messages"].append(f"Fetched {len(blogs)} blogs")
    print(f"📝 Blogs fetched: {len(blogs)}")
    return state


def fetch_cves_node(state: AgentState):
    cves = fetch_cve_data(days=2)
    state["data"]["cves"] = cves
    state["messages"].append(f"Fetched {len(cves)} CVEs")
    print(f"🛡️ CVEs fetched: {len(cves)}")
    return state


def analyze_node(state: AgentState):
    if "scored" in state["data"]:
        print("⚠️ Already analyzed. Skipping...")
        return state

    news = state["data"].get("news", [])
    blogs = state["data"].get("blogs", [])
    cves = state["data"].get("cves", [])

    correlated = correlate_data(news, cves)
    merged = correlated + blogs

    # Remove duplicates
    seen = set()
    unique = []
    for item in merged:
        title = item.get("title", "")
        if title and title not in seen:
            seen.add(title)
            unique.append(item)

    scored = score_threats(unique)
    update_memory(scored)

    state["data"]["scored"] = scored
    state["messages"].append("Analysis completed")

    print(f"⚙️ Analysis complete: {len(scored)} threats")
    return state


def generate_report_node(state: AgentState):
    if state.get("report"):
        print("⚠️ Report already exists. Skipping...")
        return state

    # 🔥 Sort by score (IMPORTANT FIX)
    scored_data = state["data"].get("scored", [])
    top_threats = sorted(scored_data, key=lambda x: x.get("score", 0), reverse=True)[:5]

    data_str = json.dumps(top_threats, indent=2, ensure_ascii=False)

    prompt = f"""
You are a senior Cyber Threat Intelligence Analyst writing for a SOC team.

Generate a high-quality Cyber Threat Intelligence Report using ONLY the data.

Data:
{data_str}

STRICT RULES:
- No generic statements
- No filler sentences
- Focus on real threats and impact
- Use specific details

FORMAT:

## Executive Summary
- 3–4 sentences
- Highlight most critical threats

## Top Prioritized Threats
For each:
- Title
- What happened
- Why it matters
- Severity (score)
- Affected systems

## Key Insights
- Trends or patterns in attacks

## Recommendations
- Specific and actionable
- Avoid generic advice

Tone: Professional, analytical, no fluff.
"""

    print("🧠 Generating high-quality report...")
    report = llm.invoke(prompt).content

    filename = create_pdf(report)

    state["report"] = filename
    state["messages"].append("Report generated")

    print(f"📄 Report saved: {filename}")
    return state


# -------------------------------
# Routing (Fixed Logic)
# -------------------------------

def route(state: AgentState):
    data = state["data"]

    if "news" not in data:
        return "fetch_news"

    if "blogs" not in data:
        return "fetch_blogs"

    if "cves" not in data:
        return "fetch_cves"

    if "scored" not in data:
        return "analyze"

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
builder.add_node("generate_report", generate_report_node)

builder.set_entry_point("fetch_news")

builder.add_conditional_edges("fetch_news", route)
builder.add_conditional_edges("fetch_blogs", route)
builder.add_conditional_edges("fetch_cves", route)
builder.add_conditional_edges("analyze", route)
builder.add_conditional_edges("generate_report", route)

graph = builder.compile()


# -------------------------------
# Run Agent
# -------------------------------

def run_ai_agent():
    print("🤖 Autonomous Cyber Threat Intelligence Agent\n")

    initial_state = {
        "messages": [],
        "data": {},
        "report": ""
    }

    result = graph.invoke(
        initial_state,
        config={"recursion_limit": 50}
    )

    print("\n✅ Agent Finished")
    print("📄 Final Report:", result.get("report"))


if __name__ == "__main__":
    run_ai_agent()