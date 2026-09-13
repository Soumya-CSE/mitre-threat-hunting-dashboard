TACTICS = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]

TACTIC_COLORS = {
    "Initial Access": "#3B82F6",
    "Execution": "#F59E0B",
    "Persistence": "#8B5CF6",
    "Privilege Escalation": "#EC4899",
    "Defense Evasion": "#06B6D4",
    "Credential Access": "#EF4444",
    "Discovery": "#10B981",
    "Lateral Movement": "#F97316",
    "Collection": "#6366F1",
    "Command and Control": "#DC2626",
    "Exfiltration": "#BE123C",
    "Impact": "#991B1B",
}

# Each technique carries: name, tactic, url, description, detection guidance,
# mitigation guidance, ordered investigation checklist, and keyword triggers
# used by the lightweight classifier in detect_technique().
TECHNIQUES = {
    "T1566.001": {
        "name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "Adversary sends a malicious file via email to gain initial code execution on a host.",
        "detection": "Email gateway attachment sandboxing alerts; unusual parent process of Outlook/Thunderbird spawning Office apps or scripting hosts.",
        "mitigation": "Attachment sandboxing, macro blocking via GPO, user awareness training, disable OLE object execution.",
        "investigation_steps": [
            "Pull the original email (headers, sender, SPF/DKIM/DMARC result) from the mail gateway.",
            "Identify all recipients of the same message across the org.",
            "Detonate the attachment in an isolated sandbox to confirm malicious behavior.",
            "Check EDR for the process tree spawned from the mail client on the affected host.",
            "Determine if the payload executed successfully or was blocked.",
        ],
        "keywords": ["phishing", "attachment", "malicious email", "spearphishing", "email link", "macro"],
    },
    "T1204.002": {
        "name": "User Execution: Malicious File",
        "tactic": "Execution",
        "description": "A user opens/executes a malicious file (document macro, script, or binary) delivered to the host.",
        "detection": "EDR alert on Office app spawning cmd.exe/powershell.exe/wscript.exe; unsigned binary execution from Downloads/Temp.",
        "mitigation": "Application allow-listing, disable macros by default, restrict script host execution.",
        "investigation_steps": [
            "Identify the file path, hash, and origin (download, email, USB, network share).",
            "Submit the file hash to VirusTotal / internal sandbox for verdict.",
            "Review the full process lineage from the file execution.",
            "Check for persistence artifacts created immediately after execution.",
        ],
        "keywords": ["malicious file", "user opened", "double-clicked", "executed attachment", "macro enabled"],
    },
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": "Adversary abuses PowerShell to execute commands, download payloads, or evade logging.",
        "detection": "PowerShell ScriptBlock logging (Event ID 4104) showing encoded/obfuscated commands, use of -EncodedCommand, -WindowStyle Hidden, IEX, download cradles.",
        "mitigation": "Constrained Language Mode, PowerShell logging + AMSI, script block/module logging forwarded to SIEM, restrict execution policy.",
        "investigation_steps": [
            "Decode any Base64 / -EncodedCommand payloads found in the command line.",
            "Review PowerShell ScriptBlock (4104) and Module (4103) logs for the full command.",
            "Identify parent process — was PowerShell spawned by Office, a browser, or a scheduled task?",
            "Check for outbound network connections initiated by the PowerShell process (download cradle / C2 beacon).",
            "Search the environment for the same script hash / command line on other hosts.",
        ],
        "keywords": ["powershell", "-enc", "encodedcommand", "iex", "invoke-expression", "downloadstring", "bypass", "windowstyle hidden"],
    },
    "T1059.003": {
        "name": "Command and Scripting Interpreter: Windows Command Shell",
        "tactic": "Execution",
        "description": "Adversary uses cmd.exe to execute discovery, staging, or payload commands.",
        "detection": "Suspicious cmd.exe command lines chained with & or &&, use of certutil, bitsadmin, or whoami/net commands post-compromise.",
        "mitigation": "Command-line auditing (4688 with command-line logging), restrict LOLBins, application allow-listing.",
        "investigation_steps": [
            "Review the full command line and any chained commands (&, &&, |).",
            "Identify the parent process that spawned cmd.exe.",
            "Check whether the command performed discovery, download, or execution actions.",
            "Correlate the timestamp with any related alerts on the same host.",
        ],
        "keywords": ["cmd.exe", "certutil", "bitsadmin", "whoami", "net user", "net group", "command shell"],
    },
    "T1053.005": {
        "name": "Scheduled Task/Job: Scheduled Task",
        "tactic": "Persistence",
        "description": "Adversary creates a Windows scheduled task to establish persistence or execute payloads.",
        "detection": "Event ID 4698 (task created) with unusual task name/binary path, schtasks.exe invoked from non-admin context.",
        "mitigation": "Restrict task scheduler permissions, audit new task creation, alert on tasks referencing unusual binary paths.",
        "investigation_steps": [
            "Pull the full task definition (trigger, action, binary path, run-as account).",
            "Determine who/what created the task (parent process, user context).",
            "Check the target binary/script hash for known-bad indicators.",
            "Look for similar tasks created on other hosts around the same time.",
        ],
        "keywords": ["scheduled task", "schtasks", "at.exe", "task scheduler", "cron"],
    },
    "T1547.001": {
        "name": "Boot or Logon Autostart: Registry Run Keys",
        "tactic": "Persistence",
        "description": "Adversary adds a Run/RunOnce registry key to execute a payload at logon.",
        "detection": "Sysmon Event ID 13 (registry value set) targeting Run/RunOnce keys with an unusual executable path.",
        "mitigation": "Monitor and alert on writes to autorun registry keys, restrict write access, application allow-listing.",
        "investigation_steps": [
            "Identify the exact registry key and value written.",
            "Resolve the binary/script it points to and check its hash reputation.",
            "Determine the process that made the registry write.",
            "Check if the host has rebooted since — did the payload execute?",
        ],
        "keywords": ["registry run key", "runonce", "hkcu\\software\\microsoft\\windows\\currentversion\\run", "autostart"],
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion",
        "description": "Adversary injects code into a legitimate process's address space to evade detection.",
        "detection": "EDR alerts on CreateRemoteThread, VirtualAllocEx into another process, unsigned code mapped into a trusted process (e.g. explorer.exe, svchost.exe).",
        "mitigation": "EDR behavioral prevention, credential guard, restrict debug privileges.",
        "investigation_steps": [
            "Identify source and target process of the injection.",
            "Dump and analyze the injected memory region if possible.",
            "Check parent/child process relationships for the source process.",
            "Determine if the target process subsequently made C2 connections.",
        ],
        "keywords": ["process injection", "createremotethread", "reflective dll", "process hollowing", "virtualallocex"],
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Adversary encodes, encrypts, or packs files/commands to evade signature-based detection.",
        "detection": "AMSI flags on decoded obfuscated scripts, high-entropy binaries, Base64 blobs in command lines.",
        "mitigation": "AMSI integration, YARA rules for known packers, sandbox detonation of suspicious files.",
        "investigation_steps": [
            "Deobfuscate/decode the payload to reveal true intent.",
            "Hash the decoded content and check threat intel sources.",
            "Identify delivery mechanism for the obfuscated artifact.",
        ],
        "keywords": ["obfuscated", "base64 encoded", "packed binary", "high entropy", "encoded payload"],
    },
    "T1003.001": {
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "description": "Adversary dumps LSASS process memory to extract plaintext credentials/hashes (e.g. via Mimikatz).",
        "detection": "EDR alert on handle opened to lsass.exe with PROCESS_VM_READ, use of comsvcs.dll MiniDump, Mimikatz signatures.",
        "mitigation": "Credential Guard, LSA Protection (RunAsPPL), restrict debug privilege, EDR blocking on LSASS access.",
        "investigation_steps": [
            "Identify the process that accessed lsass.exe and its full lineage.",
            "Check for a dump file written to disk (.dmp) and its destination.",
            "Assume all credentials on the host are compromised — scope for password reset.",
            "Hunt for use of any harvested credentials elsewhere in the environment (lateral movement).",
        ],
        "keywords": ["lsass", "mimikatz", "credential dumping", "comsvcs.dll", "minidump", "procdump"],
    },
    "T1110.001": {
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "description": "Adversary attempts repeated logins with different passwords against a single account.",
        "detection": "Multiple failed auth events (4625) against one account in a short window, followed by a success.",
        "mitigation": "Account lockout policy, MFA, rate limiting on auth endpoints.",
        "investigation_steps": [
            "Count failed attempts, source IPs, and time window.",
            "Check if a successful login followed the failed attempts (password spray success).",
            "Identify the targeted account's privilege level.",
            "Geolocate the source IP(s) for anomalous origin.",
        ],
        "keywords": ["brute force", "failed login", "password guessing", "multiple failed attempts", "4625"],
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "description": "Adversary uses legitimate compromised credentials to blend in with normal activity.",
        "detection": "Impossible travel, login from new device/geo for a given account, use of stale/service accounts interactively.",
        "mitigation": "MFA everywhere, conditional access policies, disable unused accounts, monitor privileged account usage.",
        "investigation_steps": [
            "Verify with the account owner whether the activity was legitimate.",
            "Check login source (IP, device, geolocation) against baseline.",
            "Review what actions were taken under this account's session.",
            "Force password reset and session revocation if compromise is confirmed.",
        ],
        "keywords": ["valid account", "impossible travel", "new device login", "anomalous logon", "unfamiliar sign-in"],
    },
    "T1021.001": {
        "name": "Remote Services: Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "description": "Adversary uses RDP with valid or stolen credentials to move laterally between hosts.",
        "detection": "Event ID 4624 LogonType 10 from unusual source host, RDP sessions outside business hours.",
        "mitigation": "Restrict RDP to jump hosts/VPN, enforce NLA + MFA, segment networks.",
        "investigation_steps": [
            "Identify source and destination host of the RDP session.",
            "Check the account used and whether it normally accesses this host.",
            "Review session duration and any commands executed post-login.",
            "Trace the RDP session backward to find the original point of compromise.",
        ],
        "keywords": ["rdp", "remote desktop", "logontype 10", "3389", "mstsc"],
    },
    "T1021.002": {
        "name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "description": "Adversary uses SMB admin shares (C$, ADMIN$) to copy tools/payloads and execute remotely (e.g. PsExec).",
        "detection": "Admin share access from non-IT hosts, PsExec service creation (Event ID 7045), lateral file drops.",
        "mitigation": "Disable unnecessary admin shares, restrict SMB between workstations, monitor service creation events.",
        "investigation_steps": [
            "Identify the source host initiating the SMB connection.",
            "Check for files dropped via the admin share and their hashes.",
            "Review new service creation events on the target host.",
            "Determine the account used and its normal access pattern.",
        ],
        "keywords": ["admin$", "psexec", "smb lateral", "c$ share", "service creation"],
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Adversary downloads additional tools/payloads onto a compromised host from external infrastructure.",
        "detection": "Outbound connection followed by new file write, use of certutil/bitsadmin/curl/wget to fetch remote files.",
        "mitigation": "Egress filtering, proxy allow-listing, block known LOLBins from making network calls.",
        "investigation_steps": [
            "Identify the destination URL/IP and check threat intel reputation.",
            "Determine what file was downloaded and its hash.",
            "Check if the downloaded file was subsequently executed.",
            "Block the destination indicator at the perimeter.",
        ],
        "keywords": ["ingress tool transfer", "downloaded file", "curl", "wget", "invoke-webrequest", "file download"],
    },
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols (C2)",
        "tactic": "Command and Control",
        "description": "Adversary uses HTTP/HTTPS to blend C2 traffic with legitimate web traffic.",
        "detection": "Beaconing pattern (regular interval callbacks) to a rare/newly-registered domain, JA3/TLS fingerprint anomalies.",
        "mitigation": "TLS inspection where feasible, network beacon detection, domain reputation filtering.",
        "investigation_steps": [
            "Plot the connection interval to confirm beaconing behavior.",
            "Check domain registration date and reputation (newly registered = higher risk).",
            "Identify the process on the host making the connection.",
            "Block the C2 domain/IP and isolate the host if confirmed.",
        ],
        "keywords": ["beaconing", "c2 traffic", "command and control", "suspicious outbound https", "regular interval connection"],
    },
    "T1071.004": {
        "name": "Application Layer Protocol: DNS (C2)",
        "tactic": "Command and Control",
        "description": "Adversary tunnels C2 communication or exfiltrates data over DNS queries.",
        "detection": "High volume of TXT/NULL record queries, unusually long subdomains, high entropy DNS queries to a single domain.",
        "mitigation": "DNS logging and analytics, block direct-to-internet DNS bypassing internal resolver, DNS sinkholing.",
        "investigation_steps": [
            "Review the queried domain and subdomain entropy/length.",
            "Estimate data volume tunneled based on query count/size.",
            "Identify the host and process generating the DNS queries.",
            "Sinkhole or block the domain at the DNS resolver.",
        ],
        "keywords": ["dns tunneling", "dns c2", "txt record", "high entropy dns", "dns exfiltration"],
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversary exfiltrates collected data over the same channel used for command and control.",
        "detection": "Large outbound data transfer to a known/suspected C2 endpoint, archive file creation preceding transfer.",
        "mitigation": "DLP on egress, network segmentation, alert on large outbound transfers to rare destinations.",
        "investigation_steps": [
            "Quantify the volume of data transferred and to where.",
            "Identify what data/files were staged/archived prior to transfer.",
            "Determine data sensitivity and required breach-notification obligations.",
            "Block the destination and preserve evidence for IR/legal.",
        ],
        "keywords": ["exfiltration", "data transfer", "large upload", "staged archive", "data leak"],
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversary encrypts files on target systems (ransomware) to extort the victim.",
        "detection": "Mass file rename/encryption with new extensions, ransom note creation, shadow copy deletion preceding encryption.",
        "mitigation": "Offline/immutable backups, EDR ransomware behavioral blocking, network segmentation to limit blast radius.",
        "investigation_steps": [
            "Isolate the affected host(s) from the network immediately.",
            "Identify ransomware family via ransom note / file extension / encryptor sample.",
            "Determine patient zero and initial access vector.",
            "Check backup integrity and scope of encrypted systems/shares.",
            "Engage IR/legal/leadership per the ransomware playbook.",
        ],
        "keywords": ["ransomware", "files encrypted", "ransom note", "encrypted for impact", "shadow copy deleted"],
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "description": "Adversary deletes shadow copies/backups to prevent recovery, typically preceding ransomware detonation.",
        "detection": "vssadmin delete shadows, wbadmin delete catalog, bcdedit recovery disable commands.",
        "mitigation": "Restrict vssadmin/wbadmin usage via policy, offline immutable backups, alert on shadow copy deletion.",
        "investigation_steps": [
            "Treat as a high-confidence pre-ransomware indicator — escalate immediately.",
            "Identify the account/process that ran the deletion command.",
            "Check for other hosts with the same command executed around the same time.",
            "Verify offline backup integrity before further action.",
        ],
        "keywords": ["vssadmin delete", "shadow copy deleted", "wbadmin delete", "inhibit recovery", "bcdedit"],
    },
    "T1505.003": {
        "name": "Server Software Component: Web Shell",
        "tactic": "Persistence",
        "description": "Adversary installs a web shell on a public-facing server for persistent remote access.",
        "detection": "New file written to a web root with script extension, unusual w3wp.exe/httpd child processes executing shell commands.",
        "mitigation": "Web application firewall, file integrity monitoring on web roots, patch public-facing applications.",
        "investigation_steps": [
            "Locate and preserve the web shell file for analysis.",
            "Review web server access logs for the shell's URI to find source IP and command history.",
            "Check for lateral movement or further payloads dropped via the shell.",
            "Patch the vulnerability that allowed the file upload/write.",
        ],
        "keywords": ["web shell", "webshell", "w3wp.exe spawning", "asp.net shell", "suspicious upload"],
    },
}


def detect_technique(text: str):
    """Very lightweight keyword classifier: returns the best-matching
    technique_id for a piece of alert text, or None if nothing matches."""
    if not text:
        return None
    text_l = text.lower()
    best_id, best_score = None, 0
    for tid, meta in TECHNIQUES.items():
        score = sum(1 for kw in meta["keywords"] if kw in text_l)
        if score > best_score:
            best_score, best_id = score, tid
    return best_id


def get_technique(tid):
    return TECHNIQUES.get(tid)
