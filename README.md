# 🚩 BlueSky Ransomware Lab Write-up

The **BlueSky Ransomware Lab** focuses on analyzing a ransomware intrusion through captured network traffic and host event logs. The goal is to reconstruct the attack, identify the attacker’s activity, and map it to the MITRE ATT&CK framework. This combines network forensics and host-based investigation to understand the infection chain, persistence mechanisms, and data exfiltration.

🔗 [CyberDefenders BlueSky Ransomware Lab](https://cyberdefenders.org/blueteam-ctf-challenges/bluesky-ransomware/)

---

## 📝 Scenario

A high-profile corporation managing critical data and services across diverse industries suffered a **suspected ransomware attack**. Key files were encrypted, disrupting operations and risking data compromise. Early signs point to a sophisticated threat actor. Your task is to analyze the evidence to uncover the attacker’s methods, assess breach extent, and assist in containing the threat to restore network integrity.

---

## 🔍 Questions & Analysis

### Q1: Identify the source IP responsible for potential port scanning activity.

I filtered the PCAP in Wireshark using `icmp` to identify reconnaissance activity such as ping sweeps. I observed a single source IP sending repeated requests, indicating the attacker’s reconnaissance phase.

<img src="https://github.com/user-attachments/assets/e922839a-a1cd-49da-9c84-c5640cdbaaf6" alt="ICMP Ping Sweep" width="980"/>

---

### Q2: Identify the targeted account username during the attack.

Repeated TDS (Tabular Data Stream) traffic raised suspicion of database activity. Filtering by `tds` in Wireshark and searching for `TDS7 Login` packets revealed authentication attempts with both username and password visible. Wireshark filters like `tds.login7.username` and `tds.login7.password` made this easier.

<img src="https://github.com/user-attachments/assets/1c4db003-3145-4ca3-95e9-6cc450af14e4" alt="TDS Username" width="1747"/>
<img src="https://github.com/user-attachments/assets/f1bd339d-4e19-40bd-85d5-9d4ef1c8e8b5" alt="TDS Password" width="816"/>
<img src="https://github.com/user-attachments/assets/1d8299ab-bae9-483c-a904-bbf55260d4c5" alt="Wireshark Filter" width="932"/>

---

### Q3: What is the password discovered by the attacker?

See the `TDS7 Login` packet where the password is clearly visible.

---

### Q4: What setting did the attacker enable to execute further commands?

The attacker used SQL Batch commands within TDS packets. They executed:

```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
