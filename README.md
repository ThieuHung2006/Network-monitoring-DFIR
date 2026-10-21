# 🛡️ DIGITAL FORENSICS & INCIDENT RESPONSE (DFIR) REPORT

![Category](https://img.shields.io/badge/Category-DFIR%20%2F%20SOC-blue)
![Severity](https://img.shields.io/badge/Severity-Critical-red)
![Status](https://img.shields.io/badge/Status-Resolved-success)

**Incident Title:** Unauthorized SMB Access, Web Shell Deployment, and AgentTesla RAT Implant on Public-Facing IIS Server  
**Case Reference:** DFIR-2026-LOCKDOWN  
**Target Asset:** TechNova Systems – Cloud IIS Web Server (`10.0.2.15`)  
**Severity Level:** Critical  
**Prepared By:** Security Operations & DFIR Team  

---

## 📑 Table of Contents
1. [Executive Summary](#1-executive-summary)
2. [Scope & Forensic Artifacts](#2-scope--forensic-artifacts)
3. [Technical Investigation & Attack Reconstruction](#3-technical-investigation--attack-reconstruction)
4. [Reconstruction Timeline](#4-reconstruction-timeline)
5. [Consolidated Indicators of Compromise (IoCs)](#5-consolidated-indicators-of-compromise-iocs)
6. [Remediation & Hardening Recommendations](#6-remediation--hardening-recommendations)

---

## 1. Executive Summary

TechNova Systems' Security Operations Center (SOC) detected anomalous outbound network connections originating from a public-facing Microsoft IIS server (`10.0.2.15`). A comprehensive forensic investigation was initiated across three primary evidence sources: a network packet capture (`capture.pcapng`), a full physical memory image (`memdump.mem`), and a recovered malicious binary (`updatenow.exe`).

Forensic reconstruction confirmed a full system compromise initiated from the IP address `10.0.2.4`. The threat actor conducted aggressive TCP SYN port scanning and Nmap HTTP enumeration before authenticating to the server's SMB service using privileged credentials (`WORKGROUP\root`). After enumerating network shares and exfiltrating a sensitive internal note (`information.txt`) from the `\\10.0.2.15\Documents` share, the attacker exploited a critical architectural misconfiguration—where the writable SMB share overlapped with an IIS web-accessible virtual directory—to upload an ASP.NET web shell (`shell.aspx`).

Executing the web shell via an HTTP GET request established an interactive reverse shell over TCP port `4443` under the context of the IIS worker process (`w3wp.exe`, PID `4332`). To maintain long-term access, the attacker deployed a UPX-packed secondary payload (`updatenow.exe`, PID `900`) into the Windows All-Users Startup folder. Static and threat intelligence analysis identified the implant as **AgentTesla**, a commodity info-stealer and Remote Access Trojan (RAT) configured to beacon to the Command and Control (C2) domain `cp8nl.hyperhost.ua`.

---

## 2. Scope & Forensic Artifacts

The investigation analyzed the following evidentiary artifacts collected during incident triage:

*   **Network Capture (`capture.pcapng`):** Full packet capture recording the initial reconnaissance, lateral share enumeration, payload staging, and reverse shell traffic.
*   **Memory Image (`memdump.mem`):** Raw physical RAM snapshot acquired via FTK Imager (`PID 3628`) at `2024-09-10 06:09:42 UTC`, preserving volatile kernel structures and active processes.
*   **Malware Sample (`updatenow.exe`):** Suspicious Portable Executable (PE32) recovered from the server's global Startup directory (`SHA-256: c25a6673a24d169de1bb399d226c12cdc666e0fa534149fc9fa7896ee61d406f`).

---

## 3. Technical Investigation & Attack Reconstruction

### Phase 1: Network Reconnaissance & Service Enumeration
**MITRE ATT&CK:** *Network Service Discovery (T1046), Active Scanning (T1595)*

#### Step 1.1: Identifying the Attacker Origin via Traffic Volume Analysis
Initial triage of the packet capture began by reviewing IPv4 conversation statistics to identify abnormal communication patterns. A massive communication spike was recorded between internal hosts `10.0.2.4` and `10.0.2.15`, comprising **6,007 packets** and **4 MB** of data transfer over a 1,434-second window.

![IPv4 Conversations Traffic Spike](PCAP_IPv4_Conversations_Traffic_Spike.png)
*Figure 1.1: Wireshark IPv4 Conversations highlighting a 6,007-packet spike between 10.0.2.4 and 10.0.2.15.*

#### Step 1.2: Analyzing the TCP SYN Port Scan
Isolating traffic from `10.0.2.4` revealed a classic half-open TCP SYN scan (`nmap -sS`). The source port `55475` rapidly dispatched sequential TCP packets with only the `SYN` flag set across hundreds of destination ports on `10.0.2.15`. Applying the display filter `ip.addr==10.0.2.4 && tcp.ack==0 && tcp.flags.syn==1 && tcp.flags.ack==0` confirmed a total of **1,076 distinct SYN probe packets** originating from the attacker.

![TCP SYN Port Scan Traffic](PCAP_Filter_TCP_SYN_Scan_Probes.png)
*Figure 1.2: Filtering purely for initial SYN requests confirms 1,076 port scan probes sent by 10.0.2.4.*

#### Step 1.3: Enumerating Open Attack Surfaces
Filtering for `[SYN, ACK]` responses sent from the server confirmed exactly four open TCP ports on `10.0.2.15`:
*   **Port 80:** HTTP (Microsoft IIS Web Server)
*   **Port 135:** Microsoft EPMAP / DCE-RPC
*   **Port 139:** NetBIOS Session Service
*   **Port 445:** Microsoft-DS / SMB2 File Sharing

![Identified Open Ports Summary](PCAP_Identified_Open_Ports_Summary.png)
*Figure 1.3: Wireshark TCP Conversations filtered by SYN-ACK responses, exposing open ports 80, 135, 139, and 445.*

#### Step 1.4: Application-Layer HTTP Enumeration
Following port discovery, the attacker executed automated service and script enumeration against TCP port `80`. Inspecting the HTTP requests revealed the explicit tool signature within the header:
`User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)`.

![HTTP Nmap NSE Enumeration](PCAP_HTTP_Nmap_NSE_Enumeration.png)
*Figure 1.4: HTTP packet inspection exposing the Nmap Scripting Engine (NSE) User-Agent header.*

---

### Phase 2: SMB Exploitation & Internal Information Disclosure
**MITRE ATT&CK:** *Valid Accounts (T1078), SMB/Windows Admin Shares (T1021.002), Data from Network Shared Drive (T1039)*

#### Step 2.1: Privileged SMB Authentication & Share Discovery
Finding no immediate exploit via standard HTTP probing, the attacker pivoted to TCP port `445` (SMB2). The attacker successfully authenticated via NTLMSSP using the account **`WORKGROUP\root`** from host `KALI`. They initially issued a `Tree Connect Request` to probe the hidden administrative share **`\\10.0.2.15\IPC$`**. Shortly after, they disconnected from `IPC$` and established a new connection to the file share **`\\10.0.2.15\Documents`**, where they executed wildcard searches to list its contents.

![SMB Authentication and Tree Connect](PCAP_SMB_Auth_TreeConnect_Enumeration.png)
*Figure 2.1: SMB2 traffic showing NTLMSSP authentication as WORKGROUP\root, followed by a Tree Connect and Disconnect to IPC$, and a subsequent connection to Documents.*
#### Step 2.2: Unauthorized Exfiltration of `information.txt`
Directory enumeration inside `\\10.0.2.15\Documents` exposed a text file named `information.txt`. The attacker issued an SMB2 `Read Request` and successfully exfiltrated the 150-byte payload. 

![SMB Read File information.txt](PCAP_SMB_Read_File_information_txt.png)
*Figure 2.2: SMB2 packet sequence capturing the attacker reading 150 bytes from information.txt.*

Decoding the payload revealed a critical developer note:
> *"This server setup is under development. We are trying to link the web server with SMB. Please do not tamper with our work. Best regards, Dev Team"*

This intelligence confirmed that files written to the `Documents` SMB share were directly mapped to the IIS web server's public directory.

![Decoded Content of information.txt](Evidence_Decoded_information_txt_Content.png)
*Figure 2.3: Reconstructed plaintext content of information.txt confirming the SMB-to-IIS link.*

---

### Phase 3: Web Shell Deployment & Reverse Shell Execution
**MITRE ATT&CK:** *Server Software Component: Web Shell (T1505.003), Command and Scripting Interpreter (T1059), Non-Standard Port (T1571)*

#### Step 3.1: Uploading the Malicious ASPX Web Shell
Capitalizing on the write permissions within `\\10.0.2.15\Documents`, the attacker issued an SMB2 `Create Request` to instantiate a new file named **`shell.aspx`**. At exactly `05:48:53 UTC` (frame `#3505`), the attacker transmitted an SMB2 `Write Request` containing the malicious ASP.NET code. To verify if this uploaded payload successfully executed and established a reverse shell, we will filter subsequent network traffic for packets occurring immediately after this upload phase (e.g., using the filter `frame.number > 3505`).

![SMB Webshell Upload](PCAP_SMB_Webshell_Upload_shell_aspx.png)
*Figure 3.1: SMB2 Create and Write requests demonstrating the upload of shell.aspx at 05:48:53 UTC.*

#### Step 3.2: Triggering RCE and Catching the Reverse Shell
With `shell.aspx` planted inside the IIS virtual directory, the attacker sent an HTTP request: `GET /Documents/shell.aspx HTTP/1.1`. The IIS server compiled the script, returned `HTTP/1.1 200 OK`, and immediately initiated an outbound TCP connection back to the attacker (`10.0.2.4`) on listening port **`4443`**.

![HTTP Trigger and Reverse Shell on Port 4443](PCAP_HTTP_Trigger_Reverse_Shell_Port4443.png)
*Figure 3.2: HTTP GET request triggering the shell followed by a TCP reverse shell callback to port 4443.*

---

### Phase 4: Memory Forensics & Host Persistence Analysis
**MITRE ATT&CK:** *Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (T1547.001)*

#### Step 4.1: Process Tree Correlation & Anomaly Detection
Analyzing the memory image (`memdump.mem`) with Volatility 3 exposed the execution chain:
*   **`w3wp.exe` (PID `4332`):** The legitimate IIS Worker Process. Because `shell.aspx` ran inside the IIS application pool, `w3wp.exe` handled the outbound reverse shell.
*   **`updatenow.exe` (PID `900`):** At `06:08:23 UTC`, `w3wp.exe` spawned an unfamiliar child executable named `updatenow.exe`. An IIS worker process should never spawn standalone third-party binaries.

![Volatility Process List](Volatility_Process_Tree_w3wp_updatenow.png)
*   **`updatenow.exe` (PID `900`):** At `06:08:23 UTC`—approximately 20 minutes after the `shell.aspx` payload was uploaded (`05:48:53 UTC`) and triggered—`w3wp.exe` spawned an unfamiliar child executable named `updatenow.exe`. An IIS worker process should never spawn standalone third-party binaries, confirming this executable was deliberately launched via the active web shell connection.

![Volatility Process List](Volatility_Process_Tree_w3wp_updatenow.png)
*Figure 4.1: Volatility 3 windows.pslist output showing w3wp.exe spawning updatenow.exe at 06:08:23 UTC, correlating with the earlier web shell upload.*

#### Step 4.2: Identifying the Persistence Mechanism
Inspecting the command-line arguments of the anomalous child process revealed its exact on-disk location:
`"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe"`
By dropping `updatenow.exe` into the global `ProgramData` Startup directory, the attacker ensured the payload would automatically execute whenever any user logs into the server.

![Volatility Command Line Persistence Path](Volatility_Persistence_Startup_Path_PID900.png)
*Figure 4.2: Volatility 3 output confirming updatenow.exe was planted inside the Windows Startup folder.*
*Figure 4.2: Volatility 3 output confirming updatenow.exe was planted inside the Windows Startup folder.*

---

### Phase 5: Malware Static Analysis & Threat Intelligence
**MITRE ATT&CK:** *Obfuscated Files or Information: Software Packing (T1027.002), Application Layer Protocol (T1071)*

#### Step 5.1: Static String Inspection & Packer Identification
Running the `strings` utility against the recovered binary exposed modified PE section headers (`UPX0`, `UPX1`, `.rsrc`) alongside the version marker `3.91` and magic signature `UPX!`—confirming the binary was compressed using the **UPX (Ultimate Packer for eXecutables) v3.91** packer.

![Malware UPX Packer Signatures](Malware_Strings_UPX_Packer_Signature.png)
*Figure 5.1: String extraction revealing UPX 3.91 packer headers.*

#### Step 5.2: Application Manifest & Stealth Execution Analysis
The embedded XML Application Manifest within the `.rsrc` section is explicitly configured as `level="asInvoker"`. This ensures the binary executes silently using the caller's existing token without triggering a Windows User Account Control (UAC) elevation prompt.

![Malware XML Manifest Analysis](Malware_Manifest_UAC_Bypass_Analysis.png)
*Figure 5.2: Extracted XML Application Manifest highlighting the asInvoker execution level.*

#### Step 5.3: Malware Family Attribution & C2
Submitting the file hash to VirusTotal yielded a **57/71** malicious detection rate. Threat intelligence consensus attributes the sample to the **AgentTesla** malware family. Dynamic sandbox telemetry revealed that the AgentTesla implant beacons out to the malicious external Command and Control (C2) server **`cp8nl.hyperhost.ua`**.

![VirusTotal Malware Family Detection](VT_Detection_Malware_Family_AgentTesla.png)
*Figure 5.3: VirusTotal Detection identifying the AgentTesla malware family.*

![VirusTotal Contacted C2 Domains](VT_Network_C2_Contacted_Domains.png)
*Figure 5.4: VirusTotal Relations tab exposing the outbound C2 domain cp8nl.hyperhost.ua.*

---

## 4. Reconstruction Timeline

| Timestamp / Frame | Phase | Source / Process | Event Description |
| :--- | :--- | :--- | :--- |
| **PCAP `78.08s`** | Reconnaissance | `10.0.2.4` | Attacker launches a 1,076-packet TCP SYN port scan against `10.0.2.15`, discovering open ports `80, 135, 139, 445`. |
| **PCAP `94.42s`** | Enumeration | `10.0.2.4` | Attacker runs Nmap Scripting Engine (NSE) HTTP probes against IIS on TCP port `80`. |
| **PCAP `263.29s`** | Initial Access | `10.0.2.4` | Attacker authenticates to SMB2 as `WORKGROUP\root` and connects to `\\10.0.2.15\Documents`. |
| **PCAP `273.86s`** | Collection | `10.0.2.4` | Attacker reads `information.txt` over SMB2, learning that the SMB share is linked to the IIS web server. |
| **PCAP `342.48s`** | Weaponization | `10.0.2.4` | Attacker uploads `shell.aspx` into `\\10.0.2.15\Documents` via SMB2. |
| **PCAP `389.51s`** | Execution | `10.0.2.4` | Attacker sends `GET /Documents/shell.aspx HTTP/1.1` to trigger the web shell. |
| **PCAP `401.49s`** | C2 | `w3wp.exe` | IIS worker process (`PID 4332`) establishes a reverse shell back to `10.0.2.4` on TCP port `4443`. |
| **`06:08:23 UTC`** | Persistence | `w3wp.exe` | Web shell spawns `updatenow.exe` (`PID 900`) from the Startup folder (AgentTesla RAT). |
| **`06:09:42 UTC`** | Response | `FTK Imager` | DFIR team initiates live memory acquisition (`memdump.mem`). |

---

## 5. Consolidated Indicators of Compromise (IoCs)

| Indicator Type | Value | Context / Description |
| :--- | :--- | :--- |
| **IPv4 Address** | `10.0.2.4` | Threat actor origin IP (Port scanning, SMB exploitation, Reverse shell listener) |
| **IPv4 Address** | `10.0.2.15` | Compromised IIS Web Server |
| **FQDN / Domain** | `cp8nl.hyperhost.ua` | External Command & Control (C2) server for AgentTesla implant |
| **SHA-256 Hash** | `c25a6673a24d169de1bb399d226c12cdc666e0fa534149fc9fa7896ee61d406f` | Packed `updatenow.exe` binary (AgentTesla / AutoIt / UPX 3.91) |
| **File Path**| `\Documents\shell.aspx` | Malicious ASP.NET web shell uploaded via SMB |
| **File Path** | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe` | Persistence binary planted in All-Users Startup folder |
| **TCP Ports** | `4443` (Outbound C2), `445` (SMB), `80` (HTTP) | Ports leveraged for exploitation and reverse shell callback |

---

## 6. Remediation & Hardening Recommendations

### Immediate Containment & Eradication
1.  **Network Isolation:** Immediately quarantine host `10.0.2.15` from the internal network and block all inbound/outbound traffic to `10.0.2.4` at the perimeter firewall.
2.  **DNS & Egress Sinkholing:** Block DNS resolution and outbound traffic to `cp8nl.hyperhost.ua` across enterprise DNS resolvers and firewalls. Block unauthorized outbound connections on TCP port `4443`.
3.  **Process Termination & Artifact Removal:**
    *   Terminate the malicious process `updatenow.exe` (`PID 900`) and recycle/stop the compromised IIS Application Pool (`w3wp.exe`, `PID 4332`).
    *   Delete `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe` and remove `shell.aspx` from the `Documents` directory.
4.  **Credential Rotation:** Because AgentTesla is capable of harvesting local credentials, immediately disable or rotate the password for the `root` account and all local/domain accounts present on `10.0.2.15`.

### Long-Term Architectural Hardening
1.  **Decouple SMB Shares from IIS Web Directories:** Never map writable SMB file shares directly to IIS Virtual Directories or webroots. Enforce strict **Read-Only** permissions for network users and disable script execution (`Execute Permissions: None`) on upload directories within IIS Manager.
2.  **Restrict SMB Exposure:** Disable SMB (`TCP 445` and `139`) on public-facing interfaces. Restrict administrative share access strictly to dedicated management jump hosts over VPN/Zero-Trust segmentation.
3.  **Endpoint Detection & Attack Surface Reduction (ASR):** Deploy an EDR agent configured to alert on and block web server worker processes (`w3wp.exe`) from spawning child command interpreters or unsigned binaries from user-writable directories.
