# Suspicious User Account and Privilege Changes Detection

## 1. Overview
This detection identifies potentially malicious changes to user accounts and group memberships on Windows systems. Attackers frequently modify accounts to maintain persistence or escalate privileges after gaining access.

Monitoring account management activity is critical for early detection of compromise.

---

## 2. Detection Objective
- Detect unauthorized account creation
- Identify privilege escalation attempts
- Detect persistence via group membership changes

---

## 3. Log Sources
| Source | Description |
|------|------------|
| Windows Security Log | Account and group management |

**Required Event IDs:**
- **4720** – User account created
- **4722** – User account enabled
- **4724** – Password reset attempt
- **4728** – User added to security-enabled group
- **4732** – User added to local group
- **4726** – User account deleted

---

## 4. Detection Logic
Trigger an alert when:
- A new user account is created outside business hours
- A user is added to **Administrators** or **Domain Admins**
- Multiple account changes occur in a short time window
- A disabled account is re-enabled unexpectedly

### High-Risk Groups
- Administrators
- Domain Admins
- Enterprise Admins
- Backup Operators

---

## 5. MITRE ATT&CK Mapping
| Tactic | Technique |
|------|-----------|
| Persistence | **T1136 – Create Account** |
| Privilege Escalation | **T1078 – Valid Accounts** |
| Defense Evasion | Account Manipulation |

---

## 6. Severity Classification
| Scenario | Severity |
|--------|----------|
| Domain Admin added | Critical |
| Local admin added | High |
| Account created | Medium |
| Account deleted | Low |

---

## 7. Sample Event Details

### Event ID 4728 – User Added to Group
Important fields:
- `MemberName`
- `GroupName`
- `SubjectUserName`
- `TimeCreated`

---

## 8. False Positives
Common benign activity:
- IT onboarding processes
- Group Policy automation
- Legitimate admin maintenance

### Reduction Techniques
- Exclude known admin accounts
- Restrict alerts to non-IT hours
- Monitor only high-risk groups

---

## 9. Investigation Playbook
Analyst steps:
1. Identify the account that made the change
2. Confirm change approval with IT
3. Review recent login activity
4. Check source system and IP
5. Look for related suspicious behavior

---

## 10. Response Actions
### Immediate
- Remove unauthorized group membership
- Disable suspicious accounts
- Reset affected credentials

### Follow-up
- Review audit logs
- Check for persistence mechanisms
- Document incident and root cause

---

## 11. Detection Limitations
- Legitimate admin activity may trigger alerts
- Automation tools can cause noise
- Requires proper auditing policies enabled

---

## 12. Improvement Ideas
- Correlate with login anomalies
- Add change approval validation
- Monitor group membership drift over time

---

## 13. Lessons Learned
- Account changes are high-value signals
- Privilege escalation often follows initial access
- Context and timing are key to detection accuracy
