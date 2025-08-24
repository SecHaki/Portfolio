---
layout: default
---

# 🔐 User Authentication & Access Monitoring Folder
Tracks and analyzes user login activity, including successful and failed logins, unusual access patterns, and logins from foreign locations to detect potential account compromise.

---

### Failed vs. Successful Logins (Graph)
```spl
index=O365 sourcetype=activity Workload=AzureAD Operation IN ("UserLoggedIn", "UserLoginFailed")
| timechart span=1h count by Operation
```
### Logins from Outside the US
```spl
index=Azure sourcetype=Azure:signin status.errorCode=0 AND (conditionalAccessStatus=success OR conditionalAccessStatus=notApplied) AND NOT(location.countryOrRegion="" OR location.countryOrRegion="US")
| fields userPrincipalName, userDisplayName, location.countryOrRegion, location.city
| eval Time=strftime(_time, "%m/%d/%y %H:%M")
| rename userPrincipalName AS Email
| rename userDisplayName AS Name
| rename location.countryOrRegion AS Country
| rename location.city AS City
| stats count by Time, Email, Name, Country, City
| sort by count desc
```
### Users with High Failed Login Attempts
```spl
index=Azure sourcetype=Azure:signin
| search status.errorCode=500121 OR status.errorCode=50074
| dedup _time
| rename userPrincipalName AS Email
| rename userDisplayName AS Name
| rename location.countryOrRegion AS Country
| rename location.city AS City
| stats count by Email, Name, Country, City
| sort by count desc
```




















