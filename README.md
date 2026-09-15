# SIEM Threat Hunting Lab: Advanced Active Directory Kerberos Golden Ticket Detection (Splunk)

An elite-tier corporate identity infrastructure threat hunting framework implemented within **Splunk Cloud (Dashboard Studio)**. This project transforms Windows Security Event Logs into an automated detection system capable of isolating Kerberos authentication anomalies, domain persistence mechanisms, and compromised Domain Controller interactions based on updated CISA and international partners' guidance for identity token forgery mitigation and defense against credential theft.

---

## 🔍 Attack Vector & Defense Architecture

Active Directory (AD) serves as the primary identity trust boundary for enterprise domains. In advanced persistent threat (APT) scenarios, adversaries compromise the long-term Key Distribution Center account (`krbtgt`) to forge custom Kerberos Ticket Granting Tickets (TGTs)—known as a **Golden Ticket Attack**. 

This analytics pipeline continuously audits domain controller transactions to detect structural and behavioral indicators of compromise (IoCs):

1. **Authentication Matrix Cross-Referencing**: Correlates Kerberos Ticket requests (`EventCode=4769`) with local interactive logon sessions (`EventCode=4624`) to isolate ghost ticket usages.
2. **Cryptographic Algorithm Auditing**: Flags older, highly vulnerable, or anomalous encryption parameter options (e.g., RC4-HMAC `0x17`) within modern enterprise environments that mandate AES-256 enforcement.
3. **Identity Verification & Alignment**: Filters out benign activity by verifying administrative escalation requests originating from non-standard workstation subnets.

---

## 💻 Core SPL Directory Threat Hunting Framework

```splunk
| makeresults count=60
| streamstats count as row
| eval time_offset = row * 3
| eval _time = _time - time_offset
| eval EventCode = case(row <= 10, "4624", 1=1, "4769")
| eval Security_ID = case(row <= 45, "CORP\user.normal", 1=1, "CORP\administrator")
| eval Ticket_Encryption_Type = case(Security_ID=="CORP\administrator", "0x17 (RC4-HMAC)", 1=1, "0x12 (AES-256-CTS-HMAC-SHA1-96)")
| eval Client_Address = case(Security_ID=="CORP\administrator", "10.0.50.201", 1=1, "10.0.10.15")
| stats count as logon_event_frequency, values(Ticket_Encryption_Type) as applied_crypto_type by Security_ID, Client_Address, EventCode

| eval is_golden_ticket = if(applied_crypto_type == "0x17 (RC4-HMAC)" AND Security_ID == "CORP\administrator", "CRITICAL ANOMALY: SUSPECTED KERBEROS TICKET FORGERY", "BASELINE TRAFFIC")
| where is_golden_ticket == "CRITICAL ANOMALY: SUSPECTED KERBEROS TICKET FORGERY"
| eval soc_threat_classification = "CRITICAL INCIDENT: GOLDEN TICKET AD DOMAIN PERSISTENCE DETECTED"
| rename Security_ID as "Target Account Context", Client_Address as "Source Workstation IP", logon_event_frequency as "Anomalous Transaction Volume", applied_crypto_type as "Downgraded Encryption Identified", soc_threat_classification as "SOC Alert Severity"
```

---

## 📊 Dashboard Studio Layout Configuration

- **Visual Dashboard Mode**: Dashboard Studio (Grid Layout Architecture)
- **Primary Interface Theme**: SOC Dark Operational Standard
- **Core Visual Element**: Active Directory Enterprise Threat Hunting Matrix
- **Monitored Indicators (IoCs)**: Target Network Identity Context, Attacker Origin Client IP, Downgraded Forged Encryption Identifier, Automated Severity Escalation Flag.

---

## 🛡️ Mitigation & Hardening Blueprint (CISA-Aligned)

Following detection, the Tier 1/2 SOC Analyst should execute the following network security configuration hardening workflow to secure enterprise environments against privilege escalation:
- **KDC Password Reset**: Perform a double-reset of the `krbtgt` account password to invalidate all existing forged tickets globally.
- **Enforce Strong Crypto**: Restrict Kerberos encryption types to disallow legacy RC4 parameter options, mandating AES-128 and AES-256.
- **Advanced Identity Defense**: Maintain rigorous baseline monitoring against advanced directory techniques including DCSync abuses, Shadow Credentials, and unauthorized identity modifications to protect organizational directory assets.
