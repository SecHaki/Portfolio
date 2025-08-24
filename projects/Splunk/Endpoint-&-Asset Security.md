---
layout: default
---

# 📻-Endpoint & Asset Security]
Tracks alerts and threats on endpoints and assets, helping detect compromised devices, abnormal user behavior, and high-risk activity across the organization.

---

### 1. Top Assets Triggering EDR Alerts
```spl
index=sentinelone sourcetype="threats"
| dedup id
| stats count by agentRealtimeInfo.agentComputerName
| rename agentRealtimeInfo.agentComputerName as Asset
| sort - count
```

### 2. Top Users Triggering EDR Alerts
```spl
index=sentinelone sourcetype="threats"
| dedup id
| stats count by agentDetectionInfo.agentLastLoggedInUserName
| rename agentDetectionInfo.agentLastLoggedInUserName as User
| sort - count
```
