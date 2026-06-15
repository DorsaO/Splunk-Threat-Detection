# Splunk Threat Detection Lab

Hands-on detection engineering using Splunk and BOTSv1 dataset.
Each detection includes SPL queries, analysis methodology, 
findings, and screenshots.

**Tools:** Splunk Enterprise, BOTSv1  
**Focus:** SOC Tier 1 detection use cases

---

## Detections

| Detection | Log Source | MITRE ATT&CK | Status |
|---|---|---|---|
| [windows-brute-force](./detections/windows-brute-force/detection.md) | WinEventLog | T1110 | ✅ Complete |
| [Web-Application-Brute-Force](./detections/web-brute-force/detection.md) | Stream:HTTP | T1110 | ✅ Complete |
| [C2 Beaconing Investigation](./detections/c2-beaconing-investigation/detection.md) | stream:http, suricata | T1071, T1190 | ✅ Complete |

---

## Dataset
BOTSv1 (Boss of the SOC version 1) — open source Splunk 
attack dataset by Splunk.
