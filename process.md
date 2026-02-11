# Project Architecture: SecOps Sentinel
**Hackathon:** 2 Fast 2 MCP  
**Goal:** Build an autonomous security agent that is "Safe by Design" using Archestra.

---

## 1. The "No-BS" Role of Archestra
*Use this section to understand WHY we are using this tool.*

We are NOT using Archestra just because it is a sponsor. We are using it because it solves the **Unsafe Agent Problem**.

* **The Problem:** A raw Python script running an LLM with `subprocess.run` access is a security nightmare. It can accidentally delete root files or block critical IPs if the LLM hallucinates.
* **The Solution (Archestra):** Archestra acts as a **Reverse Proxy and Firewall** for Tool Calls.
    * The LLM does *not* execute code directly.
    * The LLM sends a JSON request to Archestra.
    * Archestra checks its **Policy Engine** (e.g., "Is this IP on the whitelist?").
    * If Allowed -> Archestra forwards the request to our Python script.
    * If Blocked -> Archestra rejects it and asks for Human Approval.

**In this project, Archestra is the "Manager" that stops the "Intern" (AI) from crashing production.**

---

## 2. Directory Structure
The workspace must be organized into three distinct "Domains" to separate concerns.

```text
secops-sentinel/
├── 📂 hero/                     # [DOMAIN A] The MCP Server (The Worker)
│   ├── server.py               # The actual Python script performing logic
│   ├── logic/                  # C++ or optimized Python logic modules
│   ├── tools/                  # Specific tool definitions (log_parser, firewall)
│   └── requirements.txt        # Dependencies for the server only
│
├── 📂 attacker/                  # [DOMAIN B] The Attack Simulator (The Problem)
│   ├── console.py              # Textual-based TUI dashboard
│   ├── attack_scripts/         # Scripts that generate fake log entries
│   └── requirements.txt        # Dependencies for the dashboard
│
├── 📂 archestra/                # [DOMAIN C] The Orchestrator (The Boss)
│   ├── config.yaml             # Main Archestra configuration (Servers & LLMs)
│   ├── policies/               # Security Guardrails definitions
│   │   ├── network_policy.yaml # Rules for firewall/IP blocking
│   │   └── system_policy.yaml  # Rules for shutdown/reboots
│   └── docker-compose.yml      # To spin up the local Archestra instance
│
├── 📂 shared_logs/              # [SHARED STATE]
│   ├── auth.log                # File written by Villain, read by Hero
│   └── access.log              # File written by Villain, read by Hero
│
└── README.md                   # Documentation