# SIEM Lab: DNS Tunneling & Covert Channel Data Exfiltration Detection (Splunk)

An operational network security monitoring framework implemented within **Splunk Cloud (Dashboard Studio)**. This project engineers custom query structures to detect DNS Tunneling attempts, payload length anomalies, and automated data exfiltration channels targeting external unverified domains.

---
<img width="1440" height="900" alt="Screen Shot 2026-09-15 at 9 30 37 PM" src="https://github.com/user-attachments/assets/b1f1d839-be25-4068-a9fc-9a19bbd22291" />

## 🔍 Attack Context & Detection Logic

Adversaries abuse the foundational Domain Name System (DNS) protocol to sneak data out of corporate perimeters because standard port filters rarely block outbound DNS query queries. This laboratory models an active data exfiltration pipeline to detect malicious encoding anomalies:

1. **Query String Volumetrics**: Monitors the raw volume of outbound subdomains directed toward newly registered root domains.
2. **String Length Analysis**: Flags character length anomalies within requests, catching data obfuscated inside heavy strings.
3. **Automated SOC Classification**: Triggers an alert when an asset consistently hits non-standard external nodes with heavy query strings.

---

## 💻 Core SPL DNS Threat Detection Framework

```splunk
| makeresults count=150
| streamstats count as row
| eval time_offset = row * 1
| eval _time = _time - time_offset
| eval internal_host = "finance-workstation-12"
| eval target_domain = case(row <= 120, "google.com", 1=1, "a9f8b2c4d6e8.malicious-cc-server.xyz")
| eval query_length = case(target_domain=="google.com", 10, 1=1, 64)
| stats count as total_queries, avg(query_length) as avg_query_string_length by internal_host, target_domain
| where total_queries >= 25 AND avg_query_string_length > 50
| eval threat_indicator = "CRITICAL ALERT: COVERT CHANNEL DATA EXFILTRATION DETECTED"
| rename internal_host as "Source Host", target_domain as "Target Destination Domain", total_queries as "Total Query Count", avg_query_string_length as "Average Query Length", threat_indicator as "SOC Security Classification"
```

---

## 📊 Dashboard Engineering Details

- **Visual Dashboard Mode**: Dashboard Studio (Grid Layout Structure)
- **Primary Interface Theme**: SOC Dark Operational Standard
- **Core Visual Element**: DNS Covert Channel Analysis Grid Table
- **Monitored Indicators (IoCs)**: Internal Compromised Workstation, External Command & Control (C2) Node, Query Frequency Threshold, Payload Obfuscation Length.
