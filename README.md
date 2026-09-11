# Splunk SIEM Failed-Login Investigation
## Overview
This project documents a SOC investigation of Windows failed-login events in Splunk Enterprise. I used SPL queries to identify Event ID 4625 activity, analyze target accounts and source addresses, correct a multivalue-field counting issue, and determine whether the activity required escalation.
## Objectives
- Detect Windows failed-login events
- Identify the targeted accounts
- Analyze source network addresses
- Determine the logon type and failure reason
- Correct inaccurate results caused by a multivalue field
- Document the SOC disposition
## Environment
- Splunk Enterprise
- Windows Security Event Log
- Source: `WinEventLog:Security`
- Event ID: `4625`
- Analysis period: All time
- Total events investigated: 9
## Initial Detection Query
```spl
source="WinEventLog:Security" EventCode=4625
```
This search returned nine Windows failed-login events.
## Target-Account Analysis
The initial account query produced inflated totals because Windows Event ID 4625 contains multiple `Account_Name` values. I normalized the field with `mvindex()` to isolate the target account.
```spl
source="WinEventLog:Security" EventCode=4625
| eval Target_Account=mvindex(Account_Name,-1)
| stats count by Target_Account
| sort - count
```
### Results
| Target account | Failed logins |
|---|---:|
| Harold | 6 |
| SOC-Lab-User | 3 |
| **Total** | **9** |
## Source-Address Analysis
```spl
source="WinEventLog:Security" EventCode=4625
| stats count by Source_Network_Address
| sort - count
```
### Results
| Source address | Count | Interpretation |
|---|---:|---|
| `-` | 3 | No network address recorded |
| `127.0.0.1` | 3 | IPv4 loopback address |
| `::1` | 3 | IPv6 loopback address |
No external or remote IP address appeared in the results.
## Logon-Type Analysis
```spl
source="WinEventLog:Security" EventCode=4625
| stats count by Logon_Type
| sort - count
```
All nine events used **Logon Type 2**, representing interactive logon attempts at the local computer.
## Detailed Evidence Query
```spl
source="WinEventLog:Security" EventCode=4625
| eval Target_Account=mvindex(Account_Name,-1)
| fillnull value="Not recorded" Target_Account Workstation_Name Source_Network_Address Failure_Reason Logon_Type
| stats count by Target_Account, Workstation_Name, Source_Network_Address, Logon_Type, Failure_Reason
| sort - count
```
The events showed the failure reason **“Unknown user name or bad password.”**
## Evidence
### Failed Logins by Target Account
![Splunk failed logins by account](splunk-failed-logins-by-account.png)
## SOC Analysis and Disposition
- **Detection:** True positive — failed-login events occurred
- **Severity:** Informational/Low
- **Source:** Local system and loopback addresses
- **Remote threat evidence:** None identified
- **Likely cause:** Authorized lab testing and incorrect credential attempts
- **Escalation required:** No
- **Final disposition:** Benign authorized activity; document and close
## Skills Demonstrated
- Splunk Enterprise
- Search Processing Language (SPL)
- Windows Event ID 4625 analysis
- Field extraction and multivalue-field normalization
- Account and source-IP analysis
- Alert validation and incident disposition
- SOC investigation and incident documentation
## Key Takeaway
This investigation demonstrated that alert counts should be validated before making a security decision. Normalizing the multivalue `Account_Name` field prevented double-counting and produced an accurate total of nine failed-login events.
