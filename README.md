# Microsoft Sentinel SOC Home Lab

## Overview
This repository documents a cloud-native Security Operations Center (SOC) home lab deployed in **Microsoft Azure**. The goal of this environment is to simulate brute-force attacks, ingest security telemetry into **Microsoft Sentinel**, and build custom **Kusto Query Language (KQL)** analytics rules for threat detection.

---

## Lab Architecture & Components
- **SIEM Platform:** Microsoft Sentinel
- **Log Management:** Azure Log Analytics Workspace (LAW)
- **Log Sources:** Windows Security Event Logs (Event IDs 4624 & 4625), Azure Activity Logs, Sysmon
- **Victim Workload:** Exposed Azure Windows Server Virtual Machine
- **Attacker Workload:** Kali Linux VM (simulating RDP & SSH brute-force attempts)

---

## Detection Engineering & KQL Queries

### 1. Detecting RDP Brute-Force Attacks
Identifies external IP addresses generating more than 10 failed logon attempts followed by a successful logon within a 10-minute window.

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedCount = count() by Account, IpAddress, bin(TimeGenerated, 10m)
| where FailedCount > 10
| join kind=inner (
    SecurityEvent
    | where EventID == 4624
    | project SuccessfulTime = TimeGenerated, Account, IpAddress
) on IpAddress
| project SuccessfulTime, Account, IpAddress, FailedCount
```

### 2. Privilege Escalation Detection
Monitors for new account additions to privileged domain or local administrator groups.

```kql
SecurityEvent
| where EventID == 4728 or EventID == 4732
| parse EventData with * 'TargetUserName">' TargetUser '<' * 'TargetSid">' TargetSid '<' *
| project TimeGenerated, Account, TargetUser, TargetSid, Activity
```

---

## Incident Response & Triage Workflow
1. **Alert Generation:** Custom analytic rules trigger an incident in Microsoft Sentinel upon threshold breach.
2. **Investigation:** Inspected raw logs, extracted source IP address, and queried third-party threat intelligence APIs (VirusTotal / AbuseIPDB) to verify IP reputation.
3. **Containment:** Executed Azure Network Security Group (NSG) inbound security rules to block malicious source IPs.
