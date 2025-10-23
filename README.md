# ELK-SIEM-Investigation-Lab
<h1>ELK SIEM Investigation Lab: LSASS Memory Dump Attack Analysis</h1>
<h2>Overview</h2>

This repository documents my hands-on investigation of a credential access attack using the ELK Stack (Elasticsearch, Logstash, Kibana). Starting from a single SIEM alert, I traced the complete attack chain from initial access through persistence, demonstrating practical threat hunting and incident response skills.
Alert Details:

Index: secops-3 </br>
Alert Timestamp: September 25, 2024 @ 17:32:40 </br>
Detection Rule: Potential LSASS Process Dump Via Procdump (Sigma Rule) </br>
Affected Host: EC2AMAZ-MADVCN9 </br>
User: Administrator

<h2>Step-by-Step Investigation</h2>
<h3>Step 1: Understanding LSASS and the Threat</h3>
Before diving into the logs, I researched what LSASS is and why attackers target it.
<img width="691" height="393" alt="image" src="https://github.com/user-attachments/assets/e4b5195d-9c6a-48d8-a89a-606c0990a7af" /> </br>
What I learned: The Local Security Authority Subsystem Service (LSASS) is a critical Windows process that handles authentication and stores credentials in memory. Attackers dump LSASS memory to extract passwords, hashes, and Kerberos tickets for credential theft and lateral movement.
</br>
<h3>Step 2: MITRE ATT&CK Framework Research</h3>
I checked the MITRE ATT&CK framework to understand the attack technique.
<img width="691" height="393" alt="image" src="https://github.com/user-attachments/assets/505ae5bf-9de7-4bf2-b894-b248b018bf54" />
