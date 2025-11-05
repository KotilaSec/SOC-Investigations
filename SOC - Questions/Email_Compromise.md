# 🧩 Category: Identity – Email Compromise
**Investigation Worksheet**

Use this template to guide triage, data collection, and documentation during a potential email account compromise investigation.

---

## 1. Login & IP Reputation

| Question | Data Source / Tool | Findings / Notes |
|-----------|-------------------|------------------|
| What is the IP reputation for the IP Address that logged in? | AbuseIPDB, VirusTotal, CrowdStrike Intel | |
| Where did the user log in from? | Azure AD Sign-in Logs, Google Workspace Login Audit | |
| Was this an impossible travel? (Example: Canada to Japan within 10 minutes) | Identity Protection Logs, Defender for Cloud Apps | |
| Does the user normally log in from that location? | Login history in SIEM, AAD | |
| What about the user agent? | AAD Sign-in details, M365 Audit Logs | |
| Has the same IP Address, location, or user agent been observed for other email accounts? | SIEM correlation, Azure Sentinel / Splunk query | |

---

## 2. Mailbox Rules & Forwarding

| Question | Data Source / Tool | Findings / Notes |
|-----------|-------------------|------------------|
| Were there any inbox rules created? | Exchange Admin Center, PowerShell (`Get-InboxRule`) | |
| Are there any forwarding SMTP addresses recently added? | Exchange Online / Google Admin | |
| Are these addresses external to the company? | WHOIS, domain checks | |
| Were there any transport rules created? | Exchange Admin Center → Mail Flow Rules | |
| Any delegation or SendAs permissions recently modified? | Exchange Audit Logs, Admin Center | |

---

## 3. Authentication & Account Security

| Question | Data Source / Tool | Findings / Notes |
|-----------|-------------------|------------------|
| Does the user have multi-factor authentication (MFA) enabled? | Entra ID / Google Admin | |
| What multi-factor authentication methods are enabled? Are there more than one? | AAD Conditional Access / Google MFA Settings | |
| When was the last time the user changed their password? | AD or AAD Audit Logs | |
| Does this user appear in any password compromise dumps? | HaveIBeenPwned, SpyCloud | |

---

## 4. Email Activity Review

| Question | Data Source / Tool | Findings / Notes |
|-----------|-------------------|------------------|
| Were there any emails deleted, accessed, or sent from the IP Address of interest? | Exchange Message Trace, Defender for Office 365 | |
| If so, what were these emails? | Review headers, subjects, recipients | |
| Does this user have access to shared mailboxes? | Exchange permissions audit | |

---

### 🧠 Analyst Notes

- Summary of Findings:
- Indicators of Compromise (IOCs):
- Remediation Actions Taken:
- Lessons Learned:

---

**Version:** 1.0  
**Maintained by:** [Your Name / SOC Team]  
**Last Updated:** `YYYY-MM-DD`

