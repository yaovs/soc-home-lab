# Windows Failed Login Brute-Force Detection

## 1. Overview
This detection identifies potential brute-force authentication attempts against Windows systems by analyzing repeated failed login events. Brute-force attacks are commonly used by attackers to gain initial access to corporate environments.

This detection is designed for a SOC environment and focuses on accuracy, investigation context, and response readiness.

---

## 2. Detection Objective
- Identify repeated failed login attempts
- Detect possible password guessing or brute-force attacks
- Enable analysts to respond before account compromise occurs

---

## 3. Log Sources
| Source | Description |
|------|------------|
| Windows Security Log | Authentication events |
| Sysmon (Optional) | Process context for lateral movement |

**Required Event IDs:**
- **4625** – An account failed to log on
- **4624** – An account was successfully logged on

---

## 4. Detection Logic
Trigger an alert when:
- 5 or more **Event ID 4625**
- From the same source IP address
- Targeting the same user account
- Within a 5-minute time window

### Correlation Logic
- If **4624** occurs shortly after multiple **4625** events for the same user → **High severity**
- If failures target multiple users → **Password spray behavior**

---

## 5. MITRE ATT&CK Mapping
| Tactic | Technique |
|------|-----------|
| Credential Access | **T1110 – Brute Force** |
| Initial Access | Valid Accounts |

---

## 6. Severity Classification
| Scenario | Severity |
|--------|----------|
| Multiple failures, no success | Medium |
| Failures followed by success | High |
| Internal service account | Low (possible false positive) |

---

## 7. Sample Event Details

### Event ID 4625 – Failed Logon
Common fields:
- `AccountName`
- `IpAddress`
- `LogonType`
- `FailureReason`

### Event ID 4624 – Successful Logon
Used to confirm:
- Account compromise
- Successful brute-force attempts

---

## 8. False Positives
Possible benign causes:
- User forgot password
- Misconfigured services
- Vulnerability scanners
- Password expiration events

### Reduction Techniques
- Exclude known service accounts
- Ignore internal vulnerability scanning IPs
- Raise threshold for internal traffic

---

## 9. Investigation Playbook
Analyst steps:
1. Identify affected user account
2. Review source IP reputation
3. Check if login eventually succeeded
4. Review recent password changes
5. Check for lateral movement indicators

---

## 10. Response Actions
### Immediate
- Disable or lock affected account
- Block source IP (if external)
- Force password reset

### Follow-up
- Review account activity
- Check for persistence mechanisms
- Document incident findings

---

## 11. Detection Limitations
- Cannot detect very slow brute-force attempts
- Password spraying across long time windows may evade detection
- VPN usage may mask attacker IPs

---

## 12. Improvement Ideas
- Add GeoIP-based detection
- Combine with MFA failure logs
- Add behavioral baselines per user

---

## 13. Lessons Learned
- Authentication logs are critical for early detection
- Correlation between failures and successes improves confidence
- Context reduces alert fatigue in SOC environments
