

# Threat Hunt Report: Unauthorised TOR Usage
- [Scenario Creation](https://github.com/itsrubenclarke/Threat-Hunting/blob/main/Windows-Threats/Tor-Browser/Threat-Hunt-Event(Tor).md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects some employees may use TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyse related security incidents to mitigate potential risks. If any use of TOR is found, please let management know.

### High-Level TOR-Related IOC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

----

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it:

On 26 Apr 2025 12:45:27, the user "employee" created a file named "tor-shopping-list.txt" on the device "ruben-th." The file was saved in the folder path: 
C:\Users\employee\Desktop\TorBrowser\Browser\TorBrowser\Tor\tor.exe. 

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


<table><tr><td><img src="https://github.com/user-attachments/assets/da0a317d-6964-4d17-9db0-c225877cfb07"  alt="Tor Shopping List"></td></tr></table>

---


### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.exe". 

On 26 Apr 2025 12:39:47, the user "employee" ran a process command on the device "ruben-th" The process was located in C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.5.exe, with the SHA256 hash of 3a678091f74517da5d9accd391107ec3732a5707770a61e22c20c5c17e37d19a. 

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

<table><tr><td><img src="https://github.com/user-attachments/assets/588fad1d-0397-4d94-9bee-c626a81053f7"  alt="Silent Install"></td></tr></table>

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that the user "employee" actually opened the TOR browser. The results showed user “employee” accessed tor.exe (tor browser), firefox.exe(Tor Browser) several times:

On 26 Apr 2025 12:41:09 PM to 12:41:33 PM (within the same minute), multiple instances of the "firefox.exe" process were created. These processes, all related to the Tor Browser, were executed from C:\Users\labuser\Desktop\Tor Browser\Browser\firefox.exe with various command parameters to handle different processes related to the browser's content processing, tab management, utility tasks, and GPU handling. Each "firefox.exe" instance had its own set of parameters, such as channels, preferences, and other configuration settings related to how the browser should run.
The SHA256 hash for all instances of "firefox.exe" is the same: 3613fc46eab116864d28b7a3af1b7301fc0309bf3ba99c661a8c36ad5c848d02.

On 26 Apr 2025 12:41:09, the user "employee" created a process called "tor.exe" on the device "ruben-th." The process was located at C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe, with the SHA256 hash fe6d44cb69780e09c3a39f499e0e668bff9aa54b6cd9f363b753d59af713bea0. 


**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName  == "ruben-th"
| where ProcessCommandLine has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName, Command = ProcessCommandLine
```

<table><tr><td><img src="https://github.com/user-attachments/assets/a541b405-f111-4c09-9573-fe57a7741439"  alt="Tor Browser Execution"></td></tr></table>


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication that the TOR browser was used to establish a connection using any of the known TOR ports. The results showed user “employee” did indeed use Tor to connect to a URL.

On 26 Apr 2025 12:41:16, a successful connection was made by the user "employee" from the device "ruben-th" to the remote IP address 46.229.55.118 on port 9001. The connection was made using the file "tor.exe," and the remote URL accessed was https://www.l6po2uqsh.com


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName  == "ruben-th"
| where InitiatingProcessAccountName == "employee"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```

<table><tr><td><img src="https://github.com/user-attachments/assets/13ad1fb3-9091-4ea6-8d80-3398b3f590a8"  alt="Tor Network Connection"></td></tr></table>


---

## Chronological Event Timeline 

<details>
  <summary> [Click to Expand]</summary>
<p></p>  

### 1. File Download - TOR Installer

- **Time:** `26 Apr 2025 12:31:51`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.5.exe`

### 2. Process Execution - TOR Browser Installation

- **Time:** `26 Apr 2025 12:39:47`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.5.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** tor-browser-windows-x86_64-portable-14.5.exe /S
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.5.exe`

### 3. Process Execution - TOR Browser Launch

- **Time:** `26 Apr 2025 12:41:09 PM to 12:41:33 PM`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Time:** `26 Apr 2025 12:41:16`
- **Event:** A network connection to IP `46.229.55.118` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Time:** `26 Apr 2025 14:26:42` - Local connection to `23.15.85.200` on port `43`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Time:** `26 Apr 2025 12:45:27`
- **Event:** The user "employee" created a folder named `tor-shopping-list` on the desktop, and created several files with names that are potentially related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list`

</details>

---


## Summary

The user "employee" on the device "ruben-th" installed and used the Tor Browser, taking actions that raised concerns. First, "employee" downloaded the Tor Browser installer file (tor-browser-windows-x86_64-portable-14.5.exe) into the Downloads folder. Shortly after, they silently initiated the installation using a command with a silent execution switch (/S), avoiding any prompts or user notifications. Following the installation, the user created and executed the "tor.exe" process, initiating the Tor service with its configured settings. Additionally, multiple instances of "firefox.exe" associated with the Tor Browser were launched. Network activity confirmed that the device successfully connected to the Tor network, reaching remote IP addresses on typical Tor ports (e.g., port 9001), indicating the use of Tor for anonymous browsing. Furthermore, a folder named "tor-shopping-list" was created on the Desktop, containing several .txt and .json files, suggesting the preparation or storage of content possibly related to unauthorised activities. These actions collectively raise concerns about potential misuse of the Tor network for suspicious or unauthorised purposes

---

## Response Taken

TOR usage was confirmed on the endpoint `ruben-th` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
