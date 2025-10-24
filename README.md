
# ELK SIEM Investigation Lab: LSASS Memory Dump Attack Analysis

## Overview

This repository documents my hands-on investigation of a credential access attack using the ELK Stack (Elasticsearch, Logstash, Kibana). Starting from a single SIEM alert, I traced the complete attack chain from initial access through persistence, demonstrating practical threat hunting and incident response skills.

**Alert Details:**
- **Index:** secops-3
- **Alert Timestamp:** September 25, 2024 @ 17:32:40
- **Detection Rule:** Potential LSASS Process Dump Via Procdump (Sigma Rule)
- **Affected Host:** EC2AMAZ-MADVCN9
- **User:** Administrator

**Detection Query Used:**
```
(process.command_line:"* -ma *" and process.command_line:* lsass*)
```

---

## Step-by-Step Investigation

### Step 1: Understanding LSASS and the Threat

Before diving into the logs, I researched what LSASS is and why attackers target it.

<img width="691" height="393" alt="image" src="https://github.com/user-attachments/assets/3a881eae-0b07-4f46-aa2d-2094b65777ce" />

**What I learned:** The Local Security Authority Subsystem Service (LSASS) is a critical Windows process that handles authentication and stores credentials in memory. Attackers dump LSASS memory to extract passwords, hashes, and Kerberos tickets for credential theft and lateral movement.

---

### Step 2: MITRE ATT&CK Framework Research

I checked the MITRE ATT&CK framework to understand the attack technique.

<img width="674" height="319" alt="image" src="https://github.com/user-attachments/assets/619494d1-618b-497c-a714-a90b4adb8af3" />

**Key Finding:** This maps to **T1003.001 - OS Credential Dumping: LSASS Memory**. The framework confirms this is a common post-exploitation technique used by adversaries to obtain credentials from the LSASS process memory. This context helps me understand what I'm hunting for.

---

### Step 3: Setting Up ELK and Selecting the Time Range

I started ELK, selected the `secops-3` index, and configured the date/time range to match the alert window.

<img width="468" height="79" alt="image" src="https://github.com/user-attachments/assets/6a3059b1-b5bc-48fe-9a21-26e0336d690d" />


**Configuration:** Set the time range around September 25, 2024 @ 17:32:40 to capture events related to the alert while minimizing noise from unrelated activity.

---

### Step 4: Initial Log Volume Assessment

Without any filters applied, I checked the total log volume.

<img width="468" height="193" alt="image" src="https://github.com/user-attachments/assets/33bc162f-272b-4dff-bb06-8e7c3fe6e520" />


**Result:** Over 5,000 logs in this timeframe. This demonstrates why targeted filtering is essential - manually reviewing thousands of logs would be inefficient and time-consuming. I need to apply the detection query to narrow down to relevant events.

---

### Step 5: Applying Detection Filter - Finding the Needle

I applied the Sigma rule detection query to filter for LSASS dumping activity.

<img width="468" height="192" alt="image" src="https://github.com/user-attachments/assets/df8c2e07-de41-4605-86f0-b6d78f0e2d85" />


**Filter Applied:**
```
(process.command_line:"* -ma *" and process.command_line:* lsass*)
```

**Result:** Only **3 logs** returned. Much more manageable! 

**Key Observations from the filtered results:**
- **Process Name:** `procdump64.exe` - a legitimate Microsoft tool often abused by attackers
- **Command Line:** Contains `-ma` flag (full memory dump) targeting `lsass`
- **Process Parent PID:** 6180 - this PowerShell process spawned the dump tool
- **Similarity to MITRE:** The technique matches exactly what I researched in the ATT&CK framework

This confirms the alert is a **true positive** - someone is attempting to dump LSASS credentials.

---

### Step 6: Discovering Obfuscated PowerShell

I expanded the first event and scrolled through the details to find the parent process.

<img width="468" height="216" alt="image" src="https://github.com/user-attachments/assets/d9c4c5b2-d8bb-4f08-8852-a708fef2b7a5" />


**Critical Finding:** Under `process.parent.command_line`, I discovered PowerShell was executed with a **Base64-encoded payload**. This is a common obfuscation technique attackers use to hide malicious code from detection tools and human analysts.

**Why this matters:** Legitimate PowerShell scripts are rarely encoded. Base64 encoding is a red flag indicating the attacker is trying to evade detection.

---

### Step 7: Decoding the Malicious PowerShell

I copied the Base64 string and used CyberChef to decode it.

<img width="468" height="215" alt="image" src="https://github.com/user-attachments/assets/5b0c0e1f-6cfd-47e5-82e0-2db6f14cb8d5" />


**CyberChef Recipe:**
1. **From Base64** - Decodes the Base64 string
2. **Remove Null Bytes** - Cleans up binary artifacts for readability

This revealed the actual malicious code hidden inside the encoded command.

---

### Step 8: Analyzing the Decoded Script

I examined the decoded PowerShell script to understand what it does.

<img width="468" height="288" alt="image" src="https://github.com/user-attachments/assets/50e2d4fc-aecf-428e-b214-0b208835acc8" />


**Key Indicators Identified:**

<img width="468" height="104" alt="image" src="https://github.com/user-attachments/assets/9fe87e3d-2217-4290-ba7b-529f04e8d9ca" />


From the decoded script, I identified:
- **Username:** `wpnuser` - likely a compromised account being used by the attacker
- **C2 Server IP:** `23.21.73.249` - the attacker's command-and-control server
- **HTTP POST Communications** - data exfiltration or command receiving
- **LSASS interaction** - confirms credential dumping activity
- **Persistence mechanisms** - script appears to establish ongoing access

This decoded script confirms this is a **sophisticated attack** using encoded PowerShell to establish C2 communication and harvest credentials.

---

### Step 9: Tracing Back to the Parent PowerShell Process

Using the parent PID 6180 identified earlier, I filtered to see all activity from this PowerShell session.

<img width="468" height="217" alt="image" src="https://github.com/user-attachments/assets/8f90a3d4-9354-460f-a46c-98bad0349a7c" />


**Filter:** `process.parent.pid: 6180 AND process.name: powershell.exe`

**Result:** **62 hits** - this PowerShell process had extensive activity, indicating prolonged malicious operations. I need to trace this back further to find what spawned this malicious PowerShell session in the first place.

---

### Step 10: Discovering the Initial Infection Vector

I sorted the logs chronologically (ascending) to find the earliest event and identify the root cause. By examining the earliest logs, I discovered critical information about how this attack started.

**Critical Discoveries:**
- **Process Parent PID:** 5972
- **Parent Process Name:** `explorer.exe`
- **File Extension:** `.hta` (HTML Application file)
- **GUID in filename:** The presence of a GUID after the .hta file suggests this file was double-clicked by a user

**Root Cause Identified:** The CEO user **double-clicked a malicious .hta file**, which launched the attack chain. This is the initial access vector - likely from a phishing email or malicious download.

---

### Step 11: Confirming C2 Communication

Scrolling through the events, I found network communication matching the decoded PowerShell script.

<img width="468" height="215" alt="image" src="https://github.com/user-attachments/assets/03aba575-38f7-4169-a46c-3adab5cd3b95" />


**Network Evidence:**
- **Destination IP:** `23.21.73.249` - matches the IP from the decoded script
- **Method:** HTTP POST
- **Context:** This confirms the attacker successfully established command-and-control communication

This validates my earlier analysis and shows the attack progressed beyond just credential dumping to active C2 channels.

---

### Step 12: Tracing Explorer.exe - Confirming User Execution

I filtered for process PID 5972 (the explorer.exe process) to confirm the initial execution method.

<img width="468" height="217" alt="image" src="https://github.com/user-attachments/assets/353ad09b-9d2e-411e-9e3f-6a7b7612a0ca" />


**Finding:** Explorer.exe (PID 5972) spawned the malicious HTA file execution. This **further confirms** a user double-clicked the file, as explorer.exe is the Windows file manager.

**Attack Chain So Far:**
1. User receives malicious .hta file (phishing/download)
2. User double-clicks .hta file via explorer.exe
3. HTA launches obfuscated PowerShell
4. PowerShell dumps LSASS credentials
5. PowerShell establishes C2 communication

---

### Step 13: Hunting for the Compromised Account

I filtered for the username `wpnuser` that I found in the decoded PowerShell script.

<img width="468" height="217" alt="image" src="https://github.com/user-attachments/assets/5659dcd1-e724-4fb8-8ed0-906e494b0377" />


**Filter:** `user.name: wpnuser`

**Result:** **28 hits** showing activity under this account name.

**Analysis:** The decoded script referenced this account, and now I'm seeing evidence of it being actively used. This account is likely compromised and being used for lateral movement or maintaining access.

---

### Step 14: Filtering Out Noise to Find Beaconing

I noticed events showing "attempted" and "received" connections, so I filtered out "received" to focus on outbound attempts.

<img width="469" height="218" alt="image" src="https://github.com/user-attachments/assets/b6eff4c8-ff9e-4178-a4a6-08ec14786487" />


**Why this matters:** "Attempted" connections often indicate beaconing - periodic check-ins to a C2 server. By filtering these, I can identify the pattern and frequency of attacker communications.

---

### Step 15: Identifying the Second C2 Server

The filtered results revealed beaconing to a different IP address.

<img width="468" height="217" alt="image" src="https://github.com/user-attachments/assets/68e744cd-704c-4c6d-afb4-bdb72d236294" />


**Second C2 Server Discovered:**
- **Destination IP:** `35.173.87.161`
- **Pattern:** Regular, periodic connections (beaconing behavior)
- **Destination Port:** 80 (HTTP)

**Significance:** The attacker is using **multiple C2 servers**, likely for redundancy. Using port 80 helps blend malicious traffic with legitimate web traffic.

---

### Step 16: Privilege Escalation Evidence

I expanded one of the beaconing events to examine the details.

<img width="468" height="217" alt="image" src="https://github.com/user-attachments/assets/7311e33a-f681-4dd7-b292-cfc59bb74584" />


**Critical Finding:**
- **Destination Port:** 80 (HTTP) - confirms web protocol for C2
- **User Context:** **SYSTEM** 

**This is privilege escalation!** The attacker started with a user account (CEO) but has now escalated to SYSTEM privileges - the highest level of access on Windows. This means they have complete control over the compromised host.

---

### Step 17: Investigating Process Creation Events

I opened the process creation events to see what the attacker was executing.

<img width="468" height="219" alt="image" src="https://github.com/user-attachments/assets/cca269d8-a7b5-4aea-8c6f-90e961e26708" />


**What I'm analyzing:** Process creation logs (Sysmon Event ID 1) show every new process launched. This helps me understand what tools and commands the attacker ran after gaining access.

---

### Step 18: File Masquerading Detection

Scrolling through the process creation details, I found evidence of file renaming.

<img width="468" height="217" alt="image" src="https://github.com/user-attachments/assets/ec7550a0-c4aa-4793-b847-9e913a64cafd" />


**Evidence of Evasion:**
- **Original File Name:** Visible in the "OriginalFileName" field
- **Current File Name:** Changed to something different

**Technique:** File masquerading - the attacker renamed their malicious executable to evade detection. This maps to **MITRE ATT&CK T1036.005** (Match Legitimate Name or Location).

---

### Step 19: Discovering Persistence - HTA File Creation

I filtered for `.hta` file creation events to look for persistence mechanisms.

<img width="468" height="216" alt="image" src="https://github.com/user-attachments/assets/1975286c-a443-49b1-82e4-8a625ebcae8b" />


**Filter:** `file.extension: hta`

**Event Found:** `FileCreateStreamHash` event - this is Sysmon Event ID 15, which logs alternate data streams and file creation with hash values.

**Why this matters:** Finding additional .hta files being created suggests the attacker is establishing persistence to survive system reboots.

---

### Step 20: Confirming Startup Folder Persistence

I expanded the FileCreateStreamHash event to see the file location.

<img width="468" height="217" alt="image" src="https://github.com/user-attachments/assets/1cd8cfb7-cea3-4d50-85a5-d354fa044a36" />


**Persistence Mechanism Confirmed:**
- **File Path:** Located in the Windows Startup folder
- **File Type:** Malicious .hta file

**Impact:** By placing the .hta file in the Startup folder, the attacker ensures their malicious payload executes **every time the system restarts**. This maintains their access even after reboots, updates, or user logoffs.

---

## Attack Chain Summary

Based on my investigation, here's the complete attack timeline:

```
1. Initial Access (CEO User)
   └─> User double-clicks malicious .hta file
       └─> Likely from phishing email or malicious download

2. Execution (explorer.exe PID 5972)
   └─> HTA file spawns obfuscated PowerShell
       └─> PowerShell.exe (PID 6180) with Base64-encoded payload

3. Credential Access
   └─> PowerShell launches procdump64.exe
       └─> Dumps LSASS memory with -ma flag
           └─> Harvests passwords, hashes, Kerberos tickets

4. Privilege Escalation
   └─> Escalates from user to SYSTEM privileges
       └─> Complete control over the host

5. Command & Control
   └─> HTTP POST to 23.21.73.249
   └─> HTTP beaconing to 35.173.87.161:80
       └─> Periodic check-ins for commands

6. Persistence
   └─> Malicious .hta file copied to Startup folder
       └─> Executes on every system reboot
           └─> Maintains long-term access
```

---

## Key Indicators of Compromise (IOCs)

### Network IOCs
- **C2 IP:** 23.21.73.249
- **C2 IP:** 35.173.87.161
- **Protocol:** HTTP (Port 80)

### Host IOCs
- **Malicious Tool:** procdump64.exe
- **File Type:** .hta (HTML Application)
- **Compromised Account:** wpnuser
- **Target Process:** lsass.exe

### Behavioral IOCs
- Base64-encoded PowerShell commands
- LSASS memory dumping with `-ma` flag
- Startup folder modifications
- SYSTEM-level beaconing

---

## MITRE ATT&CK Techniques Observed

| Tactic | Technique | Evidence |
|--------|-----------|----------|
| Initial Access | T1566.001 - Spearphishing Attachment | CEO user executed malicious .hta file |
| Execution | T1059.001 - PowerShell | Base64-encoded PowerShell payload |
| Execution | T1218.005 - Mshta | HTA file execution |
| Defense Evasion | T1027 - Obfuscated Files | Base64 encoding of commands |
| Defense Evasion | T1036.005 - Masquerading | File renaming to evade detection |
| Credential Access | T1003.001 - LSASS Memory | Procdump dumping LSASS |
| Privilege Escalation | T1068 - Exploitation for Privilege Escalation | User to SYSTEM escalation |
| Command and Control | T1071.001 - Web Protocols | HTTP C2 on port 80 |
| Persistence | T1547.001 - Startup Folder | HTA file in Startup directory |

---

## Tools & Skills Demonstrated

**Tools Used:**
- **ELK Stack** (Elasticsearch, Kibana) - SIEM log analysis and visualization
- **Sysmon** - Windows event logging for detailed process monitoring
- **CyberChef** - Data decoding and transformation
- **Sigma Rules** - SIEM detection rule framework

**Skills Demonstrated:**
- SIEM log analysis and correlation
- Threat hunting and alert triage
- Process tree reconstruction and timeline analysis
- PowerShell deobfuscation (Base64 decoding)
- Network traffic analysis and C2 detection
- IOC extraction and documentation
- Attack chain mapping
- MITRE ATT&CK framework application
- Incident response methodology

---

## Recommendations

### Immediate Response Actions
1. **Isolate** EC2AMAZ-MADVCN9 from the network immediately
2. **Reset credentials** for all affected accounts (Administrator, CEO, wpnuser)
3. **Block C2 IPs** at the firewall (23.21.73.249, 35.173.87.161)
4. **Remove persistence** mechanism from Startup folder
5. **Scan network** for additional compromised hosts using the IOCs

### Long-term Detection Improvements
- Enable PowerShell Script Block Logging and Transcription
- Deploy LSASS protection using Credential Guard
- Implement Group Policy to block HTA file execution
- Deploy application whitelisting (AppLocker/WDAC)
- Enhance email filtering to block HTA attachments
- Implement network segmentation to limit lateral movement

### Enhanced Detection Rules
```
# PowerShell with Base64 Encoding
event.code:1 AND process.name:powershell.exe AND process.command_line:*-encodedcommand*

# LSASS Access Attempts
event.code:10 AND winlog.event_data.TargetImage:*lsass.exe*

# Suspicious HTA Execution
event.code:1 AND process.name:mshta.exe

# Startup Folder Modifications
event.code:11 AND file.path:*\\Startup\\*
```

---

## Lab Environment

This investigation was conducted in a controlled lab environment using the ELK Stack for security operations training and skills development.

**Platform Details:**
- **Index:** secops-3
- **SIEM Platform:** ELK Stack (Elasticsearch, Logstash, Kibana)
- **Log Sources:** Sysmon, Windows Event Logs
- **Purpose:** Cybersecurity training and threat hunting practice

---



---

## How to Use This Repository

1. **Review the Investigation:** Follow the step-by-step analysis above to understand the methodology
2. **Study the Screenshots:** Each screenshot shows a specific analysis technique in action
3. **Practice the Skills:** Try recreating this investigation in your own lab environment
4. **Apply the Knowledge:** Use these techniques in real-world threat hunting scenarios

---

## Connect With Me

Questions about this investigation or want to discuss threat hunting and incident response? Feel free to reach out!

- **LinkedIn:** [www.linkedin.com/in/abdirisaq-ali-aynab]


---

**Note:** This investigation was performed in a controlled lab environment for cybersecurity training and educational purposes. All IOCs and techniques documented here are for defensive security learning.
