# Incident Report: MTS Contractor RDP Compromise (October 7, 2025)

**Author:** MahCyberDefense SOC Team  
**To:** Zach Balrog, CEO  
**Date:** October 22, 2025  
**Priority:** 🔴 Critical

---

## 🧭 Executive Summary
On **7 October 2025**, an external attacker gained remote access to the contractor workstation `MTS-REDACTED_PC` through an **exposed RDP service** using the **administrator account**.  
The intruder remained active until approximately **10:10 UTC**, executing PowerShell-based payloads, disabling security controls, and laterally moving to the domain controller (`REDACTED_DC`).  

Evidence indicates the attacker accessed **Kerberos credential material** (`krbtgt`-related artifacts).  
Defender detected and flagged three malicious binaries —  
`MicrosoftEdgeUpdate.exe`, `Quickbooks_sync.exe`, and `Svchost_update.exe` — all identified as **Trojan:Win32/SuspGolang.AG**.  

Sensitive financial and PII data were exfiltrated via `file.io`, making this a **critical incident**.

---

## 🔍 Findings

### **Initial Access**
- Attacker brute-forced RDP credentials on `MTS-REDACTED_PC`.  
- Successful authentication as **administrator** from IP `REDACTED_IP_ATTACKER_1` (UK).  

### **Post-Access Actions**
- Deleted legitimate OneDrive executables.  
- Disabled Windows Firewall.  
- Launched PowerShell to retrieve a malicious script (`kb5029244.ps1`) from `http://REDACTED_IP_C2_1:1337`.  
- PowerShell User-Agent: `Microsoft-CryptoAPI/10.0`.  

### **Persistence**
- Modified registry keys such as `OneDriveStandalone` to launch:  

- Created scheduled tasks `GoogleUpdateTaskMachineCore` and `MicrosoftEdgeUpdateTaskMachineUA` for recurring execution.  

### **Credential Theft**
- Dropped and executed `mimikatz.exe` (`C:\Windows\Temp\TMP121235\mimikatz.exe`) on both hosts.  
- Extracted Kerberos credential material (`krbtgt:************`) indicating potential for **golden ticket abuse**.  

### **Lateral Movement & Discovery**
- Used elevated privileges to connect to the domain controller.  
- Executed discovery commands and **exported the AD database** via `ntdsutil ifm create full c:\temp`.  

### **Data Collection / Exfiltration**
- Accessed sensitive files:
- `Client_SSN_Database.csv`
- `Payroll_Complete.xlsx`
- `Bank_Routing_Numbers.txt`
- Compressed into `backup.zip` and uploaded to `file.io` (`REDACTED_EXTERNAL_IP_1`, `REDACTED_EXTERNAL_IP_2`).  

### **Defense Evasion**
- Disabled Defender components through registry edits.  
- Stopped the `eventlog` service.  
- Ran `wevtutil cl` to clear logs.  
- Deleted PowerShell history.  
- Defender detections confirmed several dropped payloads (`Trojan:Win32/SuspGolang.AG`).  

---

## 🧰 Recommendations

### **Immediate (0–24 hours)**
- Isolate `REDACTED_PC` and `REDACTED_DC`.  
- Reset all privileged accounts and **rotate `krbtgt` twice**.  
- Block IPs/domains from IOC list.  
- Invoke full IR/DR plan.

### **Short-Term (1–7 days)**
- Sweep environment for IOCs (`MicrosoftEdgeUpdate.exe`, registry keys, scheduled tasks).  
- Verify Defender is active and alerting on all endpoints.  
- Confirm alerts are reaching the SOC.

### **Long-Term (30–90 days)**
- Enforce MFA for remote/admin accounts.  
- Migrate to secure VPN or ZTNA solution.  
- Review network segmentation and RDP exposure.  
- Conduct external/internal network scans.  

---

## 🧩 MITRE ATT&CK Mapping

| Tactic | Technique | ID | Observed Evidence |
|:--|:--|:--|:--|
| **Initial Access** | Valid Accounts (RDP) | T1078 | Administrator RDP from REDACTED_IP_ATTACKER_1 |
| **Execution** | PowerShell | T1059.001 | Download of kb5029244.ps1 |
| **Persistence** | Registry Run Keys / Startup Folder | T1547.001 | OneDriveStandalone launches EdgeUpdate |
| **Defense Evasion** | Impair Defenses | T1562.001 | Defender registry changes |
| **Credential Access** | Credential Dumping | T1003 | Mimikatz dump |
| **Discovery** | System Information Discovery | T1082 | systeminfo.exe |
| **Lateral Movement** | RDP | T1021.001 | RDP from REDACTED_PC to DC |
| **C2** | HTTP | T1071.001 | C2 at REDACTED_IP_C2_1 |
| **Exfiltration** | Exfiltration over Web Services | T1567.002 | file.io upload |
| **Impact** | Data Exposure | T1537 | Sensitive financial/PII exposure |

---

## 🧾 Indicators of Compromise (Sanitized)

| **Category** | **Indicator** | **Notes** |
|:--------------|:--------------|:-----------|
| IP Address | `REDACTED_IP_ATTACKER_1` | Attacker RDP source (original IP redacted) |
| IP Address | `REDACTED_IP_C2_1:1337` | C2 host serving kb5029244.ps1 (redacted) |
| IP Address | `REDACTED_EXTERNAL_IP_1` | Exfiltration endpoint (file.io) - redacted |
| Domain | `REDACTED_EXFIL_DOMAIN` | Data exfiltration service (original domain redacted) |
| File Path | `[REDACTED]\MicrosoftEdgeUpdate.exe` | Persistence binary (path sanitized) |
| File Path | `[REDACTED]\TMP121235\mimikatz.exe` | Credential dumper (path sanitized) |
| File Path | `[REDACTED]\Crypto\RSA\backup.zip` | Data archive created before exfiltration (sanitized) |
| Hash (SHA256) | `42de05f181c5d9ab2db7c74514118155838187372a56e6afb6d67a0c53e64670` | Hash associated with a dropped binary (non-PII) |
| Hash (SHA256) | `2271a79f40f56f3134614757673d385f2996b542ddb76d67f636e03bd7c9f298` | Hash associated with a dropped binary (non-PII) |
| Hash (SHA256) | `d3c2ac0b0456d1ef09764f264bb7c36297b873f55f0cf69508a0e3426b4eddaa` | Hash associated with a dropped binary (non-PII) |
| Registry Key | `HKLM\Software\Microsoft\Windows Defender\DisableAntiSpyware = 1` | Defender tamper indicator (sanitized) |
| Registry Key | `DisableAntiVirus, DisableBehaviorMonitoring, DisableIOAVProtection = 1` | Defender evasion registry flags (sanitized) |
| Scheduled Task | `GoogleUpdateTaskMachineCore` | Persistence scheduled task (sanitized) |
| Scheduled Task | `MicrosoftEdgeUpdateTaskMachineUA` | Persistence scheduled task (sanitized) |
| User-Agent | `Microsoft-CryptoAPI/10.0` | PowerShell download user-agent seen in telemetry |


---

## 🧠 KQL Queries

## 🧾 Indicators of Compromise (IOCs)

| **Category** | **Indicator** | **Notes** |
|:--------------|:--------------|:-----------|
| **IP Address** | `REDACTED_IP_ATTACKER_1` | Attacker RDP source (UK) |
| **IP Address** | `REDACTED_IP_C2_1:1337` | C2 host serving `kb5029244.ps1` |
| **IP Address** | `REDACTED_EXTERNAL_IP_1`, `REDACTED_EXTERNAL_IP_2` | `file.io` exfiltration endpoints |
| **Domain** | `www.file.io` | Data exfiltration service |
| **File Path** | `C:\Users\Public\MicrosoftEdgeUpdate.exe` | Persistence binary |
| **File Path** | `C:\Windows\Temp\TMP121235\mimikatz.exe` | Credential dumper |
| **File Path** | `C:\ProgramData\Microsoft\Crypto\RSA\backup.zip` | Data archive created before exfiltration |
| **Hash (SHA256)** | `42de05f181c5d9ab2db7c74514118155838187372a56e6afb6d67a0c53e64670` | `MicrosoftEdgeUpdate.exe` |
| **Hash (SHA256)** | `2271a79f40f56f3134614757673d385f2996b542ddb76d67f636e03bd7c9f298` | `Quickbooks_sync.exe` |
| **Hash (SHA256)** | `d3c2ac0b0456d1ef09764f264bb7c36297b873f55f0cf69508a0e3426b4eddaa` | `Svchost_update.exe` |
| **Registry Key** | `HKLM\Software\Microsoft\Windows Defender\DisableAntiSpyware = 1` | Defender disabled |
| **Registry Key** | `DisableAntiVirus`, `DisableBehaviorMonitoring`, `DisableIOAVProtection = 1` | Evasion of Defender protection |
| **Scheduled Task** | `GoogleUpdateTaskMachineCore`, `MicrosoftEdgeUpdateTaskMachineUA` | Persistence mechanisms |
| **User-Agent** | `Microsoft-CryptoAPI/10.0` | Used for malicious PowerShell download |



### KQL Queries
```kql
SecurityEvent
| where TimeGenerated between (datetime(2025-10-07 03:00:00) .. datetime(2025-10-07 11:00:00))
| where Computer == "MTS-REDACTED_PC"
| where EventID == 4624
| where Account contains "administrator"
| where IpAddress == "REDACTED_IP_ATTACKER_1"
| project TimeGenerated, Account, EventID, IpAddress, LogonType

DeviceLogonEvents
| where TimeGenerated between (datetime(2025-10-07 03:00:00) .. datetime(2025-10-07 11:00:00))
| where DeviceName == "REDACTED_DC.mts.local"
| where AccountName contains "administrator"
| project TimeGenerated, DeviceName, ActionType, LogonType, AccountName, RemoteDeviceName, RemoteIP

DeviceEvents
| where TimeGenerated between (datetime(2025-10-07 03:00:00) .. datetime(2025-10-07 11:00:00))
| where DeviceName == "REDACTED_DC.mts.local"
| where AccountName contains "administrator"
| summarize arg_max(TimeGenerated, FolderPath, SHA1, SHA256, MD5) by FileName
| top 5 by FileName

union DeviceFileEvents, DeviceProcessEvents, DeviceEvents
| where TimeGenerated between (datetime(2025-10-07 04:00:00)..datetime(2025-10-07 11:30:00))
| where InitiatingProcessId == "9188"
| where FolderPath != "C:\\Users\\Public\\MicrosoftEdgeUpdate.exe"
| where FileName != ""
| where FileName !contains "_PSScript"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, SHA1, SHA256, MD5, InitiatingProcessAccountName, InitiatingProcessId
| sort by TimeGenerated asc

DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-10-07 04:00:00)..datetime(2025-10-07 11:30:00))
| where DeviceName == "REDACTED_DC.mts.local"
| where RemoteUrl == "www.file.io"
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, RemoteUrl, LocalIP, InitiatingProcessId

---

🔒 Disclosure & Privacy

All identifying details, IPs, and file names in this report are fictionalized or sanitized for educational and portfolio purposes.
No real client, user, or environment data is shared.
