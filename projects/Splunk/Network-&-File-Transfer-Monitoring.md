---
layout: default
---

# 🔗-Network & File Transfer Monitoring
Monitors network activity and file transfers, including rare or suspicious SMB transfers and plaintext credential usage, to detect lateral movement or insecure operations.

---

### 1. SMB File Transfers (Rare Activity)
```spl
index=extrahop sourcetype=extrahop:detection type="new_smb_cifs_file_transfer"
| eval Start = strftime(start_time/1000, "%m/%d/%y %H:%M"), End = strftime(end_time/1000, "%m/%d/%y %H:%M")
| rex field=description "\[(?<Asset>[^\]]+)\]\(https:\/\/"
| rex field=description "\[[^\]]+\]\((?<URL>https:\/\/[^\)]+)\)"
| rename risk_score AS Score, title AS Alert, participants{}.object_value AS IP, participants{}.hostname AS Victim, properties.file_paths{} AS "File Transferred"
| rex field=Victim "^(?<Victim>[^.]+)"
| table Start, End, Asset, Victim, "File Transferred", URL
| sort - Start
```
### 2. Websites Using Plain HTTP (Insecure Credentials)
```spl
index=extrahop sourcetype=extrahop:detection title="*Plaintext Credentials*" properties.uri{}!="*internal.example.com*" properties.uri{}!="10.*" properties.uri{}!="gateway.zscaler.net*"
| rename properties.uri{} AS URL
| rename participants{}.object_value AS Src_IP
| dedup Src_IP
| stats count by Src_IP, URL
```
