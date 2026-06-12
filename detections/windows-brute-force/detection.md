# Detection: Windows Brute Force Attack

**Log Source:** Windows Event Logs (`WinEventLog`)
**MITRE ATT&CK:** T1110 — Brute Force
**Host:** venus

---

## Detection Logic

### Step 1 — Identify Failed Logon Attempts
```spl
index=* sourcetype=WinEventLog EventCode=4625
| bin _time span=1m
| stats count by _time Account_Name host Source_Network_Address Logon_Type
| where count > 5
```
**Threshold:** More than 5 failures per minute per account.

**Findings:**
- Target accounts: `administrator` and `Guest`
- Attack time: `2017-08-29 14:37` and `14:45`
- Logon Type 3 (network) — remote attack via SMB/NTLM
- Source IP not captured — known limitation of Type 3 
  logon events in Windows

### Step 2 — Check for Successful Logon After Failures
```spl
index=* sourcetype=WinEventLog EventCode=4624 
host=venus Account_Name=administrator
| table _time Account_Name Logon_Type Source_Network_Address
| dedup Logon_Type
```
**Findings:**
- Successful RDP logon (Type 10) from `71.39.18.121` 
  at `14:36:31` — confirmed legitimate (no prior 
  failures from this IP)
- No successful logon following the brute force attempts

---

## Analyst Conclusion
Brute force attack detected against `administrator` and `Guest` 
accounts on host `venus` via network logon (Type 3). Attack did 
not result in a successful compromise — the RDP session from 
`71.39.18.121` predates the attack and originates from a 
separate source with no associated failures.

---

## Screenshots
![Brute Force Detection](../screenshots/windows_brute_force_detection.png)
![Successful Logon Types](../screenshots/administrator_successful_logon_types.png)
![Source IP Analysis](../screenshots/brute_force_source_ip_analysis.png)
