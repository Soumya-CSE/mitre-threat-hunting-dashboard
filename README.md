# 🛡️ MITRE ATT&CK Threat Hunting Dashboard

A **Streamlit-based SOC Analyst and Blue Team investigation dashboard** that demonstrates how a security alert can be investigated from initial detection to MITRE ATT&CK mapping, host correlation, timeline analysis, and recommended investigation actions.

The project simulates a lightweight **SIEM/SOC investigation workflow** using synthetic security alerts and a curated set of MITRE ATT&CK Enterprise techniques.

---

## 🎯 Project Overview

In a real SOC environment, an analyst does not investigate an alert in isolation.

A suspicious event normally needs to be:

```text
Alert
  ↓
IOC Extraction
  ↓
Technique Identification
  ↓
MITRE ATT&CK Mapping
  ↓
Affected Host
  ↓
Timeline Correlation
  ↓
Investigation
  ↓
Detection / Mitigation
```

This project recreates that workflow in a single dashboard.

### Example Investigation

```text
🚨 Alert
PowerShell suspicious execution

        ↓

🔎 IOC
Encoded PowerShell command

        ↓

🎯 MITRE ATT&CK
T1059.001
Command and Scripting Interpreter: PowerShell

        ↓

⚔️ Tactic
Execution

        ↓

💻 Affected Host
WKSTN-FIN-014

        ↓

🕒 Timeline Context
2 additional alerts detected on the same host
within the previous 24 hours

        ↓

🔬 Recommended Investigation
• Decode the PowerShell payload
• Check the parent process
• Review PowerShell execution logs
• Search for the same script hash across the fleet
• Investigate related network connections
```

---

# 🚀 Key Features

## 📊 1. SOC Dashboard

The main dashboard provides a high-level overview of the simulated security environment.

### Dashboard KPIs

* 🚨 Open Alerts
* 🔴 Critical Alerts
* 💻 Affected Hosts
* 🎯 MITRE Techniques Observed
* 📈 Alert Volume
* ⚠️ Severity Distribution

### Visualizations

The dashboard includes:

* Alerts by MITRE tactic
* Severity distribution
* Top observed techniques
* Recent alerts
* Security activity overview

This gives an analyst a quick understanding of the current environment before starting an investigation.

---

## 🚨 2. Alert Queue

The **Alert Queue** provides a searchable and filterable SOC triage interface.

Analysts can filter alerts based on:

* Severity
* Status
* Host
* Alert type
* Free-text search

Example statuses:

```text
New
Investigating
Resolved
False Positive
```

The queue allows an analyst to quickly identify alerts that require further investigation.

---

# 🔍 3. Investigation Workbench

The Investigation page is the core component of the project.

Each alert is broken down into a structured investigation pipeline:

```text
Alert
 ↓
IOC
 ↓
Technique
 ↓
MITRE ATT&CK
 ↓
Tactic
 ↓
Affected Host
 ↓
Timeline
 ↓
Investigation Checklist
 ↓
Detection Guidance
 ↓
Mitigation Guidance
```

### Investigation Information

For each selected alert, the analyst can view:

* Alert description
* Timestamp
* Severity
* Source
* Affected host
* IOC information
* MITRE technique
* MITRE tactic
* Related alerts
* Timeline context
* Recommended investigation steps
* Detection guidance
* Mitigation guidance

---

## 🧪 Analyst Workbench

The project also includes a lightweight analyst workbench.

An analyst can:

### Update Alert Status

```text
New
↓
Investigating
↓
Resolved
```

### Add Investigation Notes

Example:

```text
PowerShell executed with an encoded command.

Checked parent process:
WINWORD.EXE → powershell.exe

Further investigation required on:
- PowerShell command line
- User activity
- Network connections
- Script hash
```

Investigation notes and alert status are persisted using **SQLite**, so the information remains available across Streamlit sessions.

---

# 🎯 4. MITRE ATT&CK Mapping

The dashboard maps security alerts to the **MITRE ATT&CK Enterprise framework**.

The current project contains a curated set of **20 MITRE ATT&CK techniques/sub-techniques**.

Example:

```text
Alert:
Suspicious PowerShell execution

MITRE Technique:
T1059.001

Technique:
Command and Scripting Interpreter: PowerShell

Tactic:
Execution
```

The project also provides technique-specific:

* Detection guidance
* Investigation checklist
* Mitigation guidance

---

# 🗺️ 5. ATT&CK Matrix

The ATT&CK Matrix page provides a visual representation of observed techniques across MITRE tactics.

The dashboard displays:

```text
Tactic
  ↓
Technique
  ↓
Observed Activity
```

The matrix can help an analyst understand which ATT&CK techniques have appeared in the simulated environment.

### Technique Lookup

The project also provides a technique lookup feature.

For a selected technique, the dashboard displays:

* Technique ID
* Technique name
* Tactic
* Description
* Detection guidance
* Mitigation guidance
* Investigation checklist

A direct MITRE ATT&CK reference is also provided.

---

# 🕒 6. Security Timeline

The Timeline page provides a cross-host view of security events.

It contains:

### Gantt-style Alert Timeline

```text
Host             Timeline

WKSTN-FIN-014    ███ Alert ───── ███ Alert

WKSTN-HR-002     ───── ███ Alert ─────────

WKSTN-DEV-008    ███ Alert ── ███ Alert
```

This helps identify:

* Multiple alerts on the same host
* Repeated activity
* Multi-stage activity
* Possible coordinated activity
* Time relationships between alerts

### Alert Volume Over Time

The project also plots alert volume over the 7-day sample period.

This provides additional context for identifying periods of increased security activity.

---

# 🧠 7. Lightweight Technique Classifier

The project contains a simple keyword-based technique classifier:

```python
detect_technique()
```

It analyzes free-text alert content and attempts to map the alert to a MITRE ATT&CK technique.

For example:

```text
"PowerShell executed an encoded command"
```

can be mapped to:

```text
T1059.001
Command and Scripting Interpreter: PowerShell
```

This demonstrates the basic concept behind automated **SIEM/SOAR enrichment rules**.

> ⚠️ This classifier is intentionally lightweight and is not intended to replace production detection engineering, Sigma rules, or ML-based classification.

---

# 🧩 8. MITRE Technique Knowledge Base

The project contains a curated knowledge base in:

```text
mitre_data.py
```

Each technique contains security investigation information such as:

```text
Technique ID
Technique Name
Tactic
Description
Detection Guidance
Investigation Checklist
Mitigation Guidance
```

This allows the Investigation page to dynamically display technique-specific information.

---

# 🗄️ 9. SQLite Persistence

SQLite is used to persist analyst actions.

The database stores information such as:

* Alert status
* Investigation notes
* Alert records

Database file:

```text
mitre_dashboard.db
```

The application automatically initializes its sample data when required.

---

# 🧪 10. Synthetic Security Dataset

The project currently uses synthetic security alerts for demonstration purposes.

On the first run, the application generates:

```text
42 synthetic alerts
10 hosts
7-day investigation window
```

Example hosts:

```text
WKSTN-FIN-014
WKSTN-HR-002
WKSTN-DEV-008
```

The sample data allows the entire SOC workflow to be demonstrated without requiring access to a production SIEM.

### Reset Sample Data

The sidebar contains:

```text
🔄 Reset sample data
```

This can be used to regenerate the sample environment.

---

**Investigation flow:**

```text
Alert
 ↓
IOC
 ↓
MITRE Technique
 ↓
Tactic
 ↓
Affected Host
 ↓
Timeline Context
 ↓
Investigation Checklist
```

---

---

# 🏗️ System Architecture

```text
                    ┌─────────────────────┐
                    │   Synthetic Alerts  │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Alert Processing  │
                    └──────────┬──────────┘
                               │
                ┌──────────────┴──────────────┐
                ▼                             ▼
       ┌─────────────────┐          ┌─────────────────┐
       │ IOC Extraction  │          │ Technique       │
       │ / Alert Context │          │ Classifier      │
       └────────┬────────┘          └────────┬────────┘
                │                            │
                └──────────────┬─────────────┘
                               ▼
                    ┌─────────────────────┐
                    │ MITRE ATT&CK       │
                    │ Technique Mapping   │
                    └──────────┬──────────┘
                               │
             ┌─────────────────┼─────────────────┐
             ▼                 ▼                 ▼
        ┌─────────┐      ┌───────────┐    ┌─────────────┐
        │  Host   │      │ Timeline  │    │ Investigation│
        │ Context │      │ Analysis  │    │ Guidance     │
        └────┬────┘      └─────┬─────┘    └──────┬──────┘
             │                 │                  │
             └─────────────────┼──────────────────┘
                               ▼
                    ┌─────────────────────┐
                    │ Streamlit SOC UI    │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ SQLite Persistence  │
                    └─────────────────────┘
```

---

# 🛠️ Technology Stack

| Technology       | Purpose                             |
| ---------------- | ----------------------------------- |
| **Python**       | Core application logic              |
| **Streamlit**    | SOC dashboard and UI                |
| **SQLite**       | Alert and investigation persistence |
| **Pandas**       | Data processing and transformation  |
| **Plotly**       | Interactive charts and timelines    |
| **MITRE ATT&CK** | Threat behavior framework           |
| **CSS**          | Custom dark SOC interface           |

---

# 📁 Project Structure

```text
mitre-dashboard/
│
├── app.py
│   └── Streamlit UI and application pages
│
├── mitre_data.py
│   └── MITRE ATT&CK techniques and classifier
│
├── sample_data.py
│   └── Synthetic security alert generator
│
├── db.py
│   └── SQLite database and persistence functions
│
├── requirements.txt
│
├── README.md
```
## 📸 Screenshots

### 📊 SOC Dashboard

<img width="1892" height="908" alt="Screenshot 2026-09-14 200232" src="https://github.com/user-attachments/assets/4898c4e7-44e8-4448-963a-9a6fffdada64" />

<img width="1893" height="906" alt="Screenshot 2026-09-14 200258" src="https://github.com/user-attachments/assets/241259d8-3ede-4e26-bc32-1558307bec82" />

---

### 🚨 Alert Queue

<img width="1891" height="907" alt="Screenshot 2026-09-14 200502" src="https://github.com/user-attachments/assets/19e16ac0-4d04-4354-b0cb-4b1f26dad060" />

<img width="1902" height="910" alt="Screenshot 2026-09-14 200328" src="https://github.com/user-attachments/assets/a322c0eb-7226-42e8-b00a-6505b2ba12d5" />

---

### 🔍 Investigation Workbench

<img width="1892" height="896" alt="Screenshot 2026-09-14 200629" src="https://github.com/user-attachments/assets/5ce258a8-879f-4e17-87bd-c8e663ca534d" />

<img width="1890" height="892" alt="Screenshot 2026-09-14 200705" src="https://github.com/user-attachments/assets/566e12db-0c7a-4cfc-8863-27b7a724d1fa" />

<img width="1893" height="906" alt="Screenshot 2026-09-14 200722" src="https://github.com/user-attachments/assets/303cf43a-2026-4cbd-84f3-e0b006f73f85" />

---

### 🎯 MITRE ATT&CK Matrix

<img width="1895" height="908" alt="Screenshot 2026-09-14 200742" src="https://github.com/user-attachments/assets/f5c7c3a0-9733-4a35-9dd8-8772c5db5a3a" />

<img width="1885" height="896" alt="Screenshot 2026-09-14 200810" src="https://github.com/user-attachments/assets/13f92145-c189-4793-83e4-0dcf34e9806f" />

<img width="1895" height="886" alt="Screenshot 2026-09-14 200847" src="https://github.com/user-attachments/assets/cc99ad90-da44-426e-8913-ef62546f27ea" />

---

### 🕒 Security Timeline



### 📝 Analyst Workbench

---

# ▶️ Running the Project

## 1. Clone the Repository

```bash
git clone https://github.com/Soumya-CSE/mitre-threat-hunting-dashboard.git
```

```bash
cd mitre-threat-hunting-dashboard
```

---

## 2. Create a Virtual Environment

### Windows

```bash
python -m venv venv
```

Activate it:

```bash
venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv venv
```

```bash
source venv/bin/activate
```

---

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 4. Start the Dashboard

```bash
streamlit run app.py
```

The application will open in your browser.

---

# 🔄 Sample Data Workflow

On the first run:

```text
Application Starts
       ↓
Check SQLite Database
       ↓
No Sample Data?
       ↓
Generate 42 Alerts
       ↓
Create 10 Hosts
       ↓
Create 7-Day Timeline
       ↓
Store in SQLite
       ↓
Display SOC Dashboard
```

---

# 🔐 Example SOC Investigation

Consider the following alert:

```text
Severity:
High

Alert:
Suspicious PowerShell execution

Host:
WKSTN-FIN-014

IOC:
Encoded PowerShell command
```

The dashboard maps the activity to:

```text
MITRE ATT&CK

Tactic:
Execution

Technique:
T1059.001

Name:
Command and Scripting Interpreter:
PowerShell
```

The analyst can then investigate:

```text
☐ Decode the PowerShell payload
☐ Examine the complete command line
☐ Identify the parent process
☐ Identify the executing user
☐ Review PowerShell event logs
☐ Search for the script hash across endpoints
☐ Review related network connections
☐ Check for additional alerts on the host
```

This demonstrates the transition from:

```text
Alert Detection
      ↓
Context Enrichment
      ↓
Threat Hunting
      ↓
Investigation
```

---

# 🌐 Extending the Project to a Real SOC Environment

The current project is designed as a portfolio/demo environment.

It can be extended into a more realistic SOC pipeline.

## 🔌 SIEM Integration

Replace:

```python
sample_data.generate_alerts()
```

with an ingestion layer connected to:

* Splunk
* Microsoft Sentinel
* Elastic Security
* Wazuh
* Other SIEM platforms

Possible architecture:

```text
SIEM
 ↓
API / Query
 ↓
Alert Ingestion
 ↓
IOC Enrichment
 ↓
MITRE ATT&CK Mapping
 ↓
Threat Hunting Dashboard
```

---

# 🖥️ EDR Integration

The alert pipeline could also consume endpoint telemetry from platforms such as:

* Microsoft Defender
* CrowdStrike
* Other EDR platforms

This would provide additional information such as:

```text
Process Tree
Command Line
User
Parent Process
File Hash
Network Connection
Endpoint
Timestamp
```

---

# 🎯 Full MITRE ATT&CK Integration

The current implementation uses a curated set of 20 techniques.

A production-style implementation could use the complete **MITRE ATT&CK Enterprise** dataset through its STIX data.

Potential workflow:

```text
MITRE STIX
     ↓
Technique Database
     ↓
Local Knowledge Base
     ↓
Alert Mapping
     ↓
ATT&CK Dashboard
```

---

# 🧠 Improving Technique Detection

The current implementation uses keyword-based classification.

Example:

```text
"powershell.exe -enc ..."
```

→

```text
T1059.001
```

For a more advanced implementation, this can be replaced with:

### Sigma Rules

```text
Alert
 ↓
Sigma Rule
 ↓
Technique Mapping
```

### ML/NLP Classification

```text
Alert Text
 ↓
Feature Extraction
 ↓
ML/NLP Model
 ↓
MITRE Technique
```

This could improve automated alert enrichment while retaining analyst validation.

---

# 🔎 Future Improvements

Possible future versions could include:

* 🔐 User authentication
* 👤 Role-based access control
* 🔌 Real SIEM API integration
* 🖥️ EDR integration
* 🧬 Process-tree visualization
* 🌐 IOC enrichment
* 🔗 VirusTotal integration
* 📜 Sigma rule integration
* 🤖 ML-based technique classification
* 🗺️ Full MITRE ATT&CK Enterprise matrix
* 🚨 Automated alert prioritization
* 📧 Email alert notifications
* 📊 Detection coverage analytics
* 🔄 Automated threat-hunting queries
* 📁 Case management
* 🧾 Investigation report export
* 🐳 Docker deployment

---

# 🎓 Skills Demonstrated

This project demonstrates practical understanding of:

### Cybersecurity

* SOC Analyst workflow
* Alert triage
* Threat hunting
* IOC analysis
* MITRE ATT&CK
* Tactics and techniques
* Detection engineering concepts
* Investigation methodology
* Security event correlation

### Technical Skills

* Python
* Streamlit
* SQLite
* Pandas
* Plotly
* Data processing
* Dashboard development
* Database persistence
* Rule-based classification

### Blue Team Concepts

```text
Detection
   ↓
Enrichment
   ↓
Correlation
   ↓
MITRE Mapping
   ↓
Threat Hunting
   ↓
Investigation
   ↓
Mitigation
```

---

# 💼 Why This Project Is Relevant to SOC Roles

The project focuses on the workflow an analyst follows after receiving a security alert.

Instead of only displaying charts, it connects:

```text
Security Alert
      +
IOC
      +
MITRE ATT&CK
      +
Host Context
      +
Timeline
      +
Investigation Guidance
      +
Analyst Notes
```

This makes the project useful for demonstrating concepts relevant to:

* SOC Analyst L1
* SOC Analyst L2
* Blue Team
* Threat Hunting
* Detection Engineering
* Security Monitoring
* Incident Response

---

# ⚠️ Important Note

This project currently uses **synthetic security alerts** and a curated MITRE ATT&CK knowledge base.

It is intended for:

* Learning
* Demonstration
* Portfolio development
* SOC workflow practice
* Interview discussion

It is **not a production SIEM or incident-response platform**.

Real-world deployment would require authentication, access control, secure data ingestion, production-grade detection rules, logging, monitoring, and integration with validated security data sources.

---

# 👨‍💻 Author

**Soumya Hazra**

B.Tech Computer Science & Engineering

Interested in:

```text
Cybersecurity
SOC Analysis
Blue Team
Threat Hunting
MITRE ATT&CK
Detection Engineering
Security Automation
```

---

# ⭐ Project Goal

The goal of this project is to demonstrate how a SOC analyst can move from a raw security alert to a structured investigation using:

```text
Alert
 ↓
IOC
 ↓
MITRE ATT&CK
 ↓
Host Context
 ↓
Timeline
 ↓
Threat Hunting
 ↓
Investigation
 ↓
Response
```

**Built as a practical SOC/Blue Team learning and portfolio project.**
