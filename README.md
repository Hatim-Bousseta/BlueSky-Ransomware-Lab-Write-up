# BlueSky-Ransomware-Lab-Write-up
The BlueSky Ransomware Lab focuses on analyzing a ransomware intrusion through captured network traffic and host event logs. The goal is to reconstruct the attack, identify the attacker’s activity, and map it to the MITRE ATT&amp;CK framework. Combines network forensics and host-based investigation to understand the infection chain, persistence mechanisms, and data exfiltration.

https://cyberdefenders.org/blueteam-ctf-challenges/bluesky-ransomware/

Scenario
A high-profile corporation that manages critical data and services across diverse industries has reported a significant security incident. Recently, their network has been impacted by a suspected ransomware attack. Key files have been encrypted, causing disruptions and raising concerns about potential data compromise. Early signs point to the involvement of a sophisticated threat actor. Your task is to analyze the evidence provided to uncover the attacker’s methods, assess the extent of the breach, and aid in containing the threat to restore the network’s integrity.



Q1-Knowing the source IP of the attack allows security teams to respond to potential threats quickly. Can you identify the source IP responsible for potential port scanning activity?

I filtered the PCAP in Wireshark using icmp to identify any reconnaissance activity such as ping sweeps ,  I observed a single source IP sending requests , This repeated pattern indicated the attacker’s reconnaissance phase, allowing me to identify the source IP responsible for the potential scanning activity.

<img width="980" height="472" alt="image" src="https://github.com/user-attachments/assets/e922839a-a1cd-49da-9c84-c5640cdbaaf6" />


