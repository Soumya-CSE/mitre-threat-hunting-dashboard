# 🛡️ MITRE ATT&CK Threat Hunting Dashboard

A Streamlit-based SOC analyst tool that walks an alert through the full
investigation pipeline:

```
Alert → IOC → Technique → MITRE ATT&CK → Affected Host → Timeline → Recommended Investigation
```

Example flow:
```
PowerShell suspicious execution
  → IOC: encoded command
    → T1059.001 (Command and Scripting Interpreter: PowerShell)
      → Tactic: Execution
        → Host: WKSTN-FIN-014
          → Timeline: 2 other alerts on this host in the last 24h
            → Recommended steps: decode payload, check parent process,
              hunt for the same script hash across the fleet
```

## Features

- **Dashboard** — KPIs (open/critical alerts, hosts affected, techniques seen),
  alerts-by-tactic bar chart, severity donut, top-techniques chart, recent alerts feed.
- **Alert Queue** — filterable/searchable triage view (severity, status, host, free text).
- **Investigation** — the core pipeline view: each alert is decomposed into
  Alert → IOC → Technique → MITRE tactic → Host → Timeline context →
  a technique-specific recommended investigation checklist, plus detection
  and mitigation guidance. Includes an analyst workbench to update alert
  status and save investigation notes (persisted to SQLite).
- **ATT&CK Matrix** — tactic-by-technique coverage heatmap of what's actually
  been observed in the environment, plus a technique lookup with a direct
  link to attack.mitre.org.
- **Timeline** — cross-host Gantt-style timeline and alert-volume-over-time
  chart, for spotting multi-stage / coordinated attack activity.

## Tech stack

- **Streamlit** for the UI (custom dark "SOC" theme via CSS)
- **SQLite** for persistence of alert status/analyst notes across sessions
- **Plotly** for interactive charts and timelines
- **Pandas** for data wrangling
- 20 curated real MITRE ATT&CK (Enterprise) techniques with detection,
  mitigation, and investigation-checklist content, plus a lightweight
  keyword classifier (`detect_technique`) that maps free-text alert
  content to a technique — the same idea a real SOAR/SIEM enrichment
  rule uses.

## Running it

```bash
pip install -r requirements.txt
streamlit run app.py
```

The app seeds itself with 42 synthetic alerts spread across 10 hosts and a
7-day window on first run (stored in `mitre_dashboard.db`). Use the
"🔄 Reset sample data" button in the sidebar to regenerate it at any time.

## Project structure

```
mitre-dashboard/
├── app.py           # Streamlit UI — all 5 pages
├── mitre_data.py     # MITRE ATT&CK technique knowledge base + classifier
├── sample_data.py     # Synthetic alert generator
├── db.py               # SQLite persistence layer
├── requirements.txt
└── README.md
```

## Extending it for a real environment

This is built to be a realistic stand-in for a live pipeline. To wire it to
real data:

- Replace `sample_data.generate_alerts()` with an ingestion function that
  pulls from your SIEM API (Splunk, Sentinel, Elastic) or EDR (CrowdStrike,
  Defender) instead of generating synthetic alerts.
- Extend `mitre_data.TECHNIQUES` with the full ATT&CK Enterprise matrix
  (available as STIX from MITRE's `cti` GitHub repo) instead of the curated
  20-technique subset.
- Swap the keyword-based `detect_technique()` classifier for a proper
  Sigma-rule or ML-based technique classifier.
- Add authentication (e.g. `streamlit-authenticator`) before exposing this
  beyond a local/portfolio demo.

## Why this is a good SOC/Blue Team portfolio piece

It demonstrates, in one project: MITRE ATT&CK fluency (tactics, techniques,
sub-techniques), the analyst investigation mental model (alert → enrichment
→ context → response), data engineering (SQLite persistence, Pandas
transforms), and the ability to build usable internal tooling rather than
just consuming someone else's SIEM dashboard — a common ask for SOC Analyst
and Detection Engineering interviews.
