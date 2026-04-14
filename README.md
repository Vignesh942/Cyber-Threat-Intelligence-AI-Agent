# 🤖 Cyber Threat Intelligence AI Agent

An **autonomous AI-powered Cyber Threat Intelligence (CTI) Agent** that collects, correlates, scores, and reports cybersecurity threats from multiple sources and generates professional PDF reports.

Built using **LangGraph + Groq LLM**, this project evolved from a simple automation script into a **true AI agent** capable of decision-making, reasoning, and structured output generation.

---

![Python](https://img.shields.io/badge/Python-3.11-blue)
![LangGraph](https://img.shields.io/badge/LangGraph-Agentic-blue)
![Groq](https://img.shields.io/badge/Groq-LLM-green)

---

## ✨ Features


- 🔍 Real-time data collection from:
  - News API  
  - Security Blogs (RSS)  
  - NVD CVE Database  
- 🔗 Intelligent **CVE correlation** with real-world incidents  
- 📊 Dynamic **threat scoring** based on severity and keywords  
- 🧠 Persistent **JSON memory** for historical tracking  
- 📄 Automatic generation of **professional PDF reports**  
- ⚙️ Built as a **LangGraph-based AI Agent** with decision logic  
- 🧩 Modular and extensible architecture  

---

## 🏗️ System Architecture

The system follows a layered, agent-driven design:

<img width="1842" height="281" alt="Untitled Diagram drawio (1)" src="https://github.com/user-attachments/assets/9443d100-ee6c-4fcc-9c78-24dbe37955a2" />


### Components:

- **Data Collection Layer** → Fetches news, blogs, and CVEs  
- **AI Agent Core** → Controls workflow using state and decision logic  
- **Processing Layer** → Correlation and threat scoring  
- **Memory Layer** → Stores historical intelligence in JSON  
- **LLM Layer** → Generates structured threat reports  
- **Output Layer** → Converts reports into PDF  

---

### 🛠️ Technologies Used
- Python 3.11
- LangChain + LangGraph → AI agent framework
- Groq (Llama 3.1 8B Instant) → Fast LLM inference
- ReportLab → PDF generation
- Feedparser → RSS parsing
- Requests → API calls


### 📊Sample Output
The agent generates structured PDF reports with:

- Executive Summary
- Top Prioritized Threats (titles, descriptions, scores, CVEs)
- Key Insights
- Actionable Recommendations

### Download the Sample PDF here:
[Cyber_Threat_Report_20260414_092605.pdf](https://github.com/user-attachments/files/26698470/Cyber_Threat_Report_20260414_092605.pdf)



### 📄 License
This project is licensed under the MIT License.

