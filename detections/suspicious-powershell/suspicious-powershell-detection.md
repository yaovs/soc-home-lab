# Suspicious PowerShell Execution Detection

## 1. Overview
This detection identifies potentially malicious PowerShell activity based on script content, execution behavior, and known attacker techniques. PowerShell is frequently abused by attackers for execution, persistence, and lateral movement.

This detection focuses on **Script Block Logging** to provide deep visibility into PowerShell commands.

---

## 2. Detection Objective
- Detect malicious or suspicious PowerShell commands
- Identify post-exploitation activity
- Reduce dwell time by alerting on attacker behavior

---

## 3. Log Sources
| Source | Description |
|------|------------|
| Windows PowerShell Operational Log | PowerShell execution details |
| Security Log | User context |
| Sysmon (Optional) | Process execution context |

**Required Event ID:**
- **4104** – PowerShell Script Block Logging

---

## 4. Detection Logic
Trigger an alert when **Event ID 4104** contains suspicious indicators such as:
- `EncodedCommand`
- `Invoke-Expression`
- `DownloadString`
- `FromBase64String`
- `IEX`
- `WebClient`
- `Invoke-WebRequest`
- `Invoke-Command`

### Example Logic
- PowerShell script blocks containing encoded or obfuscated commands
- PowerShell downloading content from external URLs
- Execution of in-memory payloads

---

## 5. MITRE ATT&CK Mapping
| Tactic | Technique |
|------|-----------|
| Execution | **T1059.001 – PowerShell** |
| Defense Evasion | Obfuscated Files or Information |
| Command and Control | Application Layer Protocol |

---

## 6. Severity Classification
| Scenario | Severity |
|--------|----------|
| Encoded commands | High |
| External script download | High |
| Administrative scripts | Medium |
| Known IT automation | Low |

---

## 7. Sample Event Details

### Event ID 4104 – Script Block Logged
Important fields:
- `ScriptBlockText`
- `User`
- `HostApplication`
- `CommandLine`

---

## 8. False Positives
Common benign causes:
- IT automation scripts
- Configuration management tools
- Administrative troubleshooting

### Reduction Techniques
- Whitelist known scripts
- Filter trusted paths
- Exclude known admin accounts

---

## 9. Investigation Playbook
Analyst steps:
1. Review the script block content
2. Identify encoded or obfuscated commands
3. Check source URL or IP address
4. Determine user context (admin vs standard user)
5. Check for follow-on activity (downloads, process creation)

---

## 10. Response Actions
### Immediate
- Isolate affected endpoint
- Terminate malicious PowerShell process
- Block malicious domains/IPs

### Follow-up
- Reset affected user credentials
- Scan endpoint for persistence
- Review historical PowerShell activity

---

## 11. Detection Limitations
- Obfuscation may bypass simple keyword detection
- Legitimate admin scripts may appear suspicious
- Script block logging must be enabled

---

## 12. Improvement Ideas
- Add regex-based detection
- Correlate with Sysmon Event ID 1
- Add parent-child process analysis
- Use command-line length heuristics

---

## 13. Lessons Learned
- PowerShell visibility is critical in modern attacks
- Context is key to reducing false positives
- Combining script content with behavior improves detection accuracy
