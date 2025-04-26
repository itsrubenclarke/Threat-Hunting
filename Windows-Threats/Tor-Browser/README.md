
<p align="center">
<img src="https://github.com/user-attachments/assets/ac8338fd-fd54-4398-b02b-d5df63dc9ff9" height="30%" width="40%" alt="Tor Logo With Crosshairs"/>
</p>

# Threat Hunt Report: Unauthorised TOR Usage
- [Scenario Creation](https://github.com/itsrubenclarke/Threat-Hunting/blob/main/Windows-Threats/Tor-Browser/Threat-Hunt-Event(Tor).md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects some employees may use TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyse related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IOC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

----

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it:

On 26 Apr 2025 12:40:03, the user "employee" created a file named "tor.exe" on the device "ruben-th." The file was saved in the folder path: 
C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe. The file's SHA256 hash is fe6d44cb69780e09c3a39f499e0e668bff9aa54b6cd9f363b753d59af713bea0.	

This file held multiple artefacts of interest with names that suggest illicit activity.



**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "ruben-th"
| where InitiatingProcessAccountName == "employee" 
| where FileName contains "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

![DeviceFileEvents](https://github.com/user-attachments/assets/99863cf7-8010-4761-bb27-cfcc0ed22c18)

---


### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.exe". 

On 26 Apr 2025 12:39:47, the user "employee" created a process called "cmd.exe" on the device "ruben-th" The process was located in C:\Windows\System32\cmd.exe, with the SHA256 hash of 3a678091f74517da5d9accd391107ec3732a5707770a61e22c20c5c17e37d19a. 

The command executed was:
```
tor-browser-windows-x86_64-portable-14.5.exe /S
```
This initiated the installation of the Tor Browser, silently.


**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName  == "ruben-th"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.exe"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName, Command = ProcessCommandLine
```
![DeviceProcessEvents](https://github.com/user-attachments/assets/25ab2042-60b9-4369-b65e-fb25659a95a8)


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. The results showed user “employee” accessed tor.exe (tor browser), firefox.exe(Tor Browser) several times:

At 12:41:09 PM to 12:41:33 PM (within the same minute), multiple instances of the "firefox.exe" process were created. These processes, all related to the Tor Browser, were executed from C:\Users\labuser\Desktop\Tor Browser\Browser\firefox.exe with various command parameters to handle different processes related to the browser's content processing, tab management, utility tasks, and GPU handling. Each "firefox.exe" instance had its own set of parameters, such as channels, preferences, and other configuration settings related to how the browser should run.
The SHA256 hash for all instances of "firefox.exe" is the same: 3613fc46eab116864d28b7a3af1b7301fc0309bf3ba99c661a8c36ad5c848d02.

At 26 Apr 2025 12:41:09, the user "employee" created a process called "tor.exe" on the device "ruben-th." The process was located at C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe, with the SHA256 hash fe6d44cb69780e09c3a39f499e0e668bff9aa54b6cd9f363b753d59af713bea0. 


**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName  == "ruben-th"
| where ProcessCommandLine has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName, Command = ProcessCommandLine
```
![DeviceProcessEvents](https://github.com/user-attachments/assets/963186e9-1e68-4b93-94c6-31750a5cb53c)

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication that the TOR browser was used to establish a connection using any of the known TOR ports. The results showed user “employee” did indeed use Tor to connect to a URL.

At 26 Apr 2025 12:41:16, a successful connection was made by the user "employee" from the device "ruben-th" to the remote IP address 46.229.55.118 on port 9001. The connection was made using the file "tor.exe," and the remote URL accessed was https://www.l6po2uqsh.com


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName  == "ruben-th"
| where InitiatingProcessAccountName == "employee"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```

![DeviceNetworkEvents](https://github.com/user-attachments/assets/05cbf663-c87a-4de6-b41f-1afb40ba6401)





---
