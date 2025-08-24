---
layout: default
---

# 💻-Remote Access & VPN Monitoring
Monitors remote connections, VPN usage, and proxy activity to ensure secure access to the network from authorized locations while flagging anomalies.

---

### 1. VPN Connections Outside the US
```spl
index=Zscaler sourcetype="zpa-auth" SessionStatus=STATUS_AUTHENTICATED Username!="Internal IP Anchoring" CountryCode!=US
| dedup Username
| rename Username AS Email
| rename CountryCode AS Country
| table Email, City, Country
```

### 2. Top Users Triggering Proxy Blocks
```spl
index=Zscaler sourcetype="zscaler-web" user!="Internal->Other" action=Blocked
| rename user AS User
| eval Domain=lower(
    if(
        match(refererURL, "^(?:https?://)?(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"),
        replace(refererURL, "^(?:https?://)?((?:[0-9]{1,3}\\.){3}[0-9]{1,3})(/.*)?$", "\\1"),
        replace(refererURL, "^(?:https?://)?(?:[a-z0-9\\-]+\\.)*([a-z0-9\\-]+\\.(?:com|net|org|edu|gov|mil|io|co|biz|info|us|ca|uk|de|jp))(/.*)?$", "\\1")
    )
)
| search NOT (Domain="none" OR Domain="internal.example.com" OR Domain="googlesyndication.com" OR Domain="google.com")
| stats count by User
| sort by count desc
| head 10
```





