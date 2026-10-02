# 🛡️ Microsoft Sentinel SOC Home Lab

![Azure](https://img.shields.io/badge/Azure-Microsoft_Sentinel-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)
![KQL](https://img.shields.io/badge/KQL-Query_Language-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)
![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-red?style=for-the-badge)

> A fully operational, cloud-native Security Operations Center (SOC) built on Microsoft Azure — featuring live SIEM monitoring, custom KQL detection rules, automated incident alerting, and threat hunting workflows.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Lab Environment](#lab-environment)
- [Data Sources Connected](#data-sources-connected)
- [KQL Detection Rules](#kql-detection-rules)
- [Incident Investigation Workflow](#incident-investigation-workflow)
- [Threat Hunting Queries](#threat-hunting-queries)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Screenshots](#screenshots)
- [Skills Demonstrated](#skills-demonstrated)

---

## 🎯 Overview

This lab simulates a real-world SOC environment built entirely on Microsoft Azure free tier. The goal was to move beyond certification reading and build hands-on experience with the exact tools, dashboards, and workflows used by SOC Tier 2/3 analysts in enterprise environments.

**What this lab demonstrates:**
- End-to-end SIEM deployment and configuration
- Live log ingestion from multiple Microsoft security data sources
- Custom KQL analytic rules that auto-generate incidents
- Incident triage and investigation using the Sentinel investigation graph
- Threat hunting using the Advanced Hunting blade (Microsoft Defender portal)
- Cloud security posture monitoring via Microsoft Defender for Cloud

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Microsoft Azure                        │
│                                                         │
│  ┌─────────────────┐      ┌────────────────────────┐   │
│  │  Data Sources   │─────▶│  Log Analytics         │   │
│  │                 │      │  Workspace             │   │
│  │ • Entra ID      │      │  (sc200-lab-workspace) │   │
│  │ • Azure Activity│      └──────────┬─────────────┘   │
│  │ • Defender XDR  │                 │                  │
│  │ • Defender Cloud│                 ▼                  │
│  │ • M365 Defender │      ┌────────────────────────┐   │
│  └─────────────────┘      │  Microsoft Sentinel    │   │
│                            │                        │   │
│                            │  • Analytics Rules     │   │
│                            │  • Incidents Queue     │   │
│                            │  • Investigation Graph │   │
│                            │  • Hunting Queries     │   │
│                            │  • Automation/SOAR     │   │
│                            └──────────┬─────────────┘   │
│                                       │                  │
│                                       ▼                  │
│                            ┌────────────────────────┐   │
│                            │  Defender Portal       │   │
│                            │  (security.microsoft)  │   │
│                            │  Unified SOC Interface │   │
│                            └────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

---

## 🖥️ Lab Environment

| Component | Details |
|---|---|
| **Cloud Platform** | Microsoft Azure (Free Tier) |
| **SIEM** | Microsoft Sentinel |
| **Log Storage** | Log Analytics Workspace — `sc200-lab-workspace-d3k` |
| **Region** | East US |
| **Resource Group** | SC200-Lab-RG |
| **SOC Portal** | Microsoft Defender (security.microsoft.com) |
| **Monthly Cost** | $0.00 — within free tier limits |

---

## 📡 Data Sources Connected

7 data connectors active, feeding live telemetry into Sentinel:

| Connector | Data Type | Status |
|---|---|---|
| Microsoft Entra ID | Sign-in logs, Audit logs | ✅ Connected |
| Azure Activity | Subscription-level operations | ✅ Connected |
| Microsoft Defender XDR | Cross-domain alerts | ✅ Connected |
| Microsoft Defender for Cloud | Security recommendations, alerts | ✅ Connected |
| Microsoft Defender for Endpoint | Endpoint alerts | ✅ Connected |
| Microsoft Defender for Identity | Identity-based threats | ✅ Connected |
| Microsoft Defender for Office 365 | Email & collaboration threats | ✅ Connected |

---

## 🔍 KQL Detection Rules

All detection rules are written in KQL (Kusto Query Language) and deployed as scheduled analytic rules inside Microsoft Sentinel. Each rule auto-generates an incident when triggered.

### Rule 1 — RDP Brute Force Detection

**MITRE Tactic:** Credential Access | **Technique:** T1110 — Brute Force  
**Severity:** High | **Schedule:** Every 5 minutes

```kql
// Detect RDP brute force — 5+ failed logins in 5 minutes from same IP
SecurityEvent
| where EventID == 4625
| where LogonType == 10  // Remote Interactive (RDP)
| summarize FailedAttempts = count() by 
    TargetAccount, 
    IpAddress, 
    bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
| extend Severity = "High"
| extend MitreTactic = "Credential Access"
| extend MitreTechnique = "T1110 - Brute Force"
| project TimeGenerated, TargetAccount, IpAddress, 
    FailedAttempts, Severity, MitreTactic, MitreTechnique
```

---

### Rule 2 — Privilege Escalation Detection

**MITRE Tactic:** Privilege Escalation | **Technique:** T1078 — Valid Accounts  
**Severity:** High | **Schedule:** Every 15 minutes

```kql
// Detect user added to privileged group (Admin/Domain Admins)
SecurityEvent
| where EventID == 4732  // Member added to security-enabled local group
| where TargetUserName contains "Admin"
| project TimeGenerated, 
    Account,           // Who performed the action
    TargetUserName,    // Which group was modified
    Computer,
    Activity
| extend MitreTactic = "Privilege Escalation"
| extend MitreTechnique = "T1078 - Valid Accounts"
```

---

### Rule 3 — Multiple Failed Sign-ins (Entra ID)

**MITRE Tactic:** Credential Access | **Technique:** T1110.003 — Password Spraying  
**Severity:** Medium | **Schedule:** Every 5 minutes

```kql
// Detect multiple failed Azure AD sign-ins from same IP
SigninLogs
| where ResultType != "0"  // Non-zero = failed login
| summarize FailedAttempts = count() by 
    UserPrincipalName, 
    IPAddress, 
    bin(TimeGenerated, 5m)
| where FailedAttempts >= 3
| extend MitreTactic = "Credential Access"
| extend MitreTechnique = "T1110.003 - Password Spraying"
| project TimeGenerated, UserPrincipalName, 
    IPAddress, FailedAttempts, MitreTactic, MitreTechnique
```

---

### Rule 4 — Anomalous Azure Resource Deletion

**MITRE Tactic:** Impact | **Technique:** T1485 — Data Destruction  
**Severity:** High | **Schedule:** Every 10 minutes

```kql
// Detect bulk deletion of Azure resources — possible destructive activity
AzureActivity
| where OperationNameValue contains "DELETE"
| where ActivityStatusValue == "Success"
| summarize DeletionCount = count() by 
    Caller, 
    ResourceGroup, 
    bin(TimeGenerated, 10m)
| where DeletionCount >= 3
| extend MitreTactic = "Impact"
| extend MitreTechnique = "T1485 - Data Destruction"
| project TimeGenerated, Caller, ResourceGroup, 
    DeletionCount, MitreTactic, MitreTechnique
```

---

### Rule 5 — Sign-in From New Country

**MITRE Tactic:** Initial Access | **Technique:** T1078 — Valid Accounts  
**Severity:** Medium | **Schedule:** Every 1 hour

```kql
// Hunt for logins from countries not seen in the past 30 days
let known_countries = SigninLogs
    | where TimeGenerated > ago(30d)
    | where ResultType == "0"
    | summarize by Location;
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == "0"
| where Location !in (known_countries)
| project TimeGenerated, UserPrincipalName, 
    Location, IPAddress
| extend MitreTactic = "Initial Access"
| extend MitreTechnique = "T1078 - Valid Accounts"
```

---

## 🔎 Incident Investigation Workflow

When a detection rule fires, this is the SOC analyst workflow used in this lab:

```
1. TRIAGE
   └── Incident appears in Sentinel Incidents queue
   └── Review: severity, affected entities, alert count, first/last activity

2. INVESTIGATE  
   └── Click "Investigate" → opens visual investigation graph
   └── Graph shows: User entity → IP entity → Alert → Related incidents
   └── Click User entity → view timeline of all their activity
   └── Click IP entity → geolocation, other accounts from same IP

3. ENRICH
   └── Query related logs using KQL in the Logs blade
   └── Cross-reference with threat intelligence if available
   └── Check if IP appears in other alerts

4. RESPOND
   └── Classify: True Positive / False Positive / Benign
   └── Document findings in incident comments
   └── Close incident with classification and notes

5. TUNE
   └── If false positive — adjust analytic rule threshold
   └── Add exception logic to KQL where appropriate
```

---

## 🎣 Threat Hunting Queries

Proactive threat hunting queries used in Microsoft Defender Advanced Hunting:

### Hunt 1 — Accounts With No Recent Activity (Stale Accounts)

```kql
SigninLogs
| where TimeGenerated > ago(90d)
| summarize LastLogin = max(TimeGenerated) by UserPrincipalName
| where LastLogin < ago(60d)
| project UserPrincipalName, LastLogin
| order by LastLogin asc
```

### Hunt 2 — Admin Activity Outside Business Hours

```kql
AzureActivity
| where OperationNameValue contains "write" or OperationNameValue contains "delete"
| extend Hour = datetime_part("hour", TimeGenerated)
| where Hour < 7 or Hour > 19  // Outside 7am-7pm
| project TimeGenerated, Caller, OperationNameValue, ResourceGroup, Hour
| order by TimeGenerated desc
```

### Hunt 3 — Multiple Roles Assigned To Single User

```kql
AzureActivity
| where OperationNameValue contains "roleAssignments/write"
| summarize RoleCount = count() by Caller, bin(TimeGenerated, 1h)
| where RoleCount >= 3
| project TimeGenerated, Caller, RoleCount
```

---

## 🎯 MITRE ATT&CK Coverage

| Tactic | Technique | Detection Rule |
|---|---|---|
| Initial Access | T1078 — Valid Accounts | Sign-in From New Country |
| Credential Access | T1110 — Brute Force | RDP Brute Force Detection |
| Credential Access | T1110.003 — Password Spraying | Multiple Failed Sign-ins |
| Privilege Escalation | T1078 — Valid Accounts | Privilege Escalation Detection |
| Impact | T1485 — Data Destruction | Anomalous Resource Deletion |

---

## 📸 Screenshots

> *Screenshots of the live lab environment — Sentinel dashboard, incidents queue, investigation graph, and KQL query results.*

| View | Description |
|---|---|
| `screenshots/sentinel-overview.png` | Main Sentinel overview dashboard |
| `screenshots/data-connectors.png` | 7 connected data sources |
| `screenshots/incident-queue.png` | Active incidents queue |
| `screenshots/investigation-graph.png` | Entity investigation graph |
| `screenshots/kql-editor.png` | KQL query editor with results |
| `screenshots/defender-portal.png` | Unified Defender portal view |

---

## ✅ Skills Demonstrated

| Skill | Evidence |
|---|---|
| SIEM Deployment | Built Sentinel workspace from scratch on Azure free tier |
| Data Connector Configuration | 7 Microsoft security connectors active and ingesting |
| KQL Query Writing | 5 custom detection rules + 3 threat hunting queries |
| MITRE ATT&CK Mapping | All rules tagged to tactic and technique |
| Incident Investigation | Full triage → investigate → respond → close workflow |
| Threat Hunting | Proactive hunting queries in Advanced Hunting blade |
| Cloud Security Posture | Defender for Cloud integrated, Secure Score monitored |
| SOC Analyst Workflow | End-to-end incident lifecycle practiced hands-on |

---

## 📚 Related Certifications

- 🎓 **Microsoft SC-200** — Security Operations Analyst *(in progress)*
- ✅ **CompTIA Security+** — Earned
- ✅ **AWS Cloud Practitioner** — Earned
- 🎓 **CISSP** — *(in progress)*

---

## 🔗 Connect

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=flat&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/derek-valenz/)
[![Email](https://img.shields.io/badge/Email-D14836?style=flat&logo=gmail&logoColor=white)](mailto:d3rek28@gmail.com)
[![GitHub](https://img.shields.io/badge/GitHub-100000?style=flat&logo=github&logoColor=white)](https://github.com/Fr3ddy28)

---

*Built by Frederick Valenzuela — Cybersecurity Operations Engineer | Jersey City, NJ*
