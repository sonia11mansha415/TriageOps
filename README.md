# TriageOps — Automated SOC Telemetry & Command Triage Engine

An incident response triage engine designed for Tier-1/2 SOC Analysts to automatically de-obfuscate PowerShell telemetry, calculate dynamic risk scores, map behaviors to the **MITRE ATT&CK® Framework**, and generate visual incident dashboards with SIEM-ready JSON logs.

---

## Key Features

- **Automated Base64 De-obfuscation**: Safely extracts and decodes multi-layered UTF-8 / UTF-16LE payloads without executing untrusted code.
- **MITRE ATT&CK® Mapping**: Maps malicious command-line patterns to standard tactics and techniques:
  - `T1059.001`: Command and Scripting Interpreter: PowerShell
  - `T1105`: Ingress Tool Transfer (Download Cradles)
  - `T1003`: OS Credential Dumping (Mimikatz / LSASS)
  - `T1490`: Inhibit System Recovery (Volume Shadow Copy Deletion)
  - `T1082`: System Information Discovery (`whoami /all`, `net group`)
  - `T1053.005`: Scheduled Task / Job Persistence (`schtasks /create`)
  - `T1562.001`: Impair Defenses (AMSI Bypass)
  - `T1070.001`: Indicator Removal (Windows Event Log Clearing)
- **Automated Triage Scoring**: Calculates risk confidence (0–100) and provides immediate SOC containment recommendations.
- **Visual Incident Dashboard**: Generates responsive dark-mode HTML reports for rapid incident reviews.
- **SIEM-Ready JSON Telemetry**: Appends structured incident events to `triage_events.json` for ingestion into Splunk, Elastic (ELK), or Microsoft Sentinel.

---

## Installation & Setup

```bash
git clone [https://github.com/your-username/TriageOps.git](https://github.com/your-username/TriageOps.git)
cd TriageOps