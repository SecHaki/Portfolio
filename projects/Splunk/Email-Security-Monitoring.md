---
layout: default
---

# 📬-Email Security Monitoring
Identifies and investigates malicious or suspicious emails, including malware and phishing attempts, to protect users and endpoints from email-borne threats.

### 1. Malware Senders
``` spl
index=o365 sourcetype=Activity Verdict=Malware
| dedup ObjectId
| rename P2Sender AS Attacker
| rex field=ThreatsAndDetectionTech{} "Malware:\s*\[(?<MalwareTech>[^\]]+)\]"
| stats count by Attacker, MalwareTech
| sort - count
```

### 2. Phishing Email Senders
``` spl
index=o365 sourcetype=Activity Verdict=Phish
| dedup ObjectId
| rename P2Sender AS Attacker
| stats count by Attacker
| sort - count
```
