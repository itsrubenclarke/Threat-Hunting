# Threat Hunt Report: Unauthorised System Configuration Changes
- [Scenario Creation](https://github.com/itsrubenclarke/Threat-Hunting/blob/main/Windows-Threats/System-Configuration/Threat-Hunt-Event(Scenario%20Configuration).md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- PowerShell

##  Scenario

Management is concerned about potential tampering with critical system configurations that could weaken security defences or enable malicious activities. Recent security logs have revealed irregular modifications to registry keys and firewall rules, including attempts to disable Windows Defender and change system policies. The goal is to detect suspicious system configuration changes, such as unauthorised registry edits, firewall modifications, or service disruptions, and analyse any related security incidents. If any suspicious activity is identified, notify management for further investigation.

### High-Level PowerShell Discovery Plan

- **Check `DeviceRegistryEvents`** for unauthorised registry changes, particularly those targeting security-related keys (e.g., Disabled Windows Defender, Modified UAC settings, Changed system policies)  
- **Check `DeviceProcessEvents`** to look for suspicious processes used to execute configuration changes (e.g., regedit.exe, powershell.exe, cmd.exe, sc.exe)  
- **Check `DeviceNetworkEvents`** to identify unusual network activity following system configuration changes.  
- **Check `DeviceProcessEvents`** for group policy modifications (e.g., Administrators group)   
 
---

## Steps Taken

### 1. Searched the `DeviceRegistryEvents` Table

Searched for any registry that action type held the value "RegistryValueSet" or "RegistryValueDeleted".

The dataset reveals registry activity originating from the device "ruben-th" that aligns with concerns about tampering with critical system configurations. On **Apr 27, 2025, at 10:34:36 AM**, a command executed by `cmd.exe` deleted a Registry Value. This activity suggests potential interference with the system update mechanism. 

Additionally, a FailureAction on the 'WindowsDefender' path on **Apr 27, 2025, at 10:34:38 AM** indicates possible tampering with user-specific configurations. These events warrant further investigation to assess whether they represent unauthorised modifications aimed at weakening system defences or enabling malicious activities.

**Query used to locate events:**

```kql
// Detect UAC modifications or deletions in the registry
DeviceRegistryEvents
| where DeviceName == "ruben-th"
| where ActionType in ("RegistryValueSet", "RegistryValueDeleted")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, ActionType
```

<table><tr><td><img src="https://github.com/user-attachments/assets/4d344b37-e227-4a96-82c7-7eda7f1d4e98"  alt="DeviceRegistryEvents"></td></tr></table>

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any process events that held "regedit.exe", "powershell.exe", "cmd.exe", or "sc.exe" in the FileName.

The dataset reveals process activity on the device "ruben-th" involving commands executed by `cmd.exe` and `powershell.exe`, both of which are commonly used for system configuration changes. On **Apr 27, 2025, at 09:25:50 AM**, a command initiated by `runcommandextension.exe` executed `cmd.exe` with a PowerShell script using the `-ExecutionPolicy Unrestricted` flag. This was followed by similar commands at **09:25:51 AM** and **09:25:52 AM**, suggesting repeated attempts to run scripts with unrestricted policies. Additionally, on **Apr 27, 2025, at 09:52:56 AM**, a command was initiated by `powershell.exe` to execute another PowerShell script with potentially unsafe parameters, such as `-ExecutionPolicy Bypass`. 

These activities highlight the use of elevated PowerShell and command-line operations, which align with potential tampering with critical configurations or the execution of unauthorised scripts. The repeated usage of `-ExecutionPolicy Unrestricted` and `-Bypass` flags warrants further investigation to determine whether these actions were authorised or indicative of malicious intent.

**Query used to locate event:**

```kql
// Detect suspicious processes modifying configurations
DeviceProcessEvents
| where DeviceName == "ruben-th"
| where FileName in~ ("regedit.exe", "powershell.exe", "cmd.exe", "sc.exe")
| where ProcessCommandLine has_any ("Set-", "Disable", "Enable", "-ExecutionPolicy", "-NoProfile", "-NonInteractive", "bypass", "New-ItemProperty")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by Timestamp desc 
```
---

### 3. Searched the `DeviceNetworksEvents` Table

Searched for any network activity that may give clues to malicious acts.

The dataset reveals significant network activity originating from the device "ruben-th." On **Apr 27, 2025, at 13:13:28 PM**, `powershell.exe` initiated a successful connection to `raw.githubusercontent.com` (IP address `185.199.108.133`) over HTTPS (port 443). This domain is known to host scripts and files, suggesting potential script download or execution activity. 

The use of `powershell.exe` for network communication and repeated connections to script-hosting domains aligns with concerns about unauthorised activities and tampering with system configurations. These events warrant further investigation to assess whether they involve the execution of malicious scripts or unauthorised system changes.


**Query used to locate events:**

```kql
// Detect unusual network activity following system changes
DeviceNetworkEvents
| where RemotePort in (3389, 445, 135) or RemoteUrl has_any (".onion", "raw.githubusercontent.com", "unknown-domain")
| where ActionType in ("ConnectionSuccess", "ConnectionFailed")
| project Timestamp, RemoteIP, RemotePort, RemoteUrl, ActionType, InitiatingProcessFileName, InitiatingProcessAccountName
```

<table><tr><td><img src="https://github.com/user-attachments/assets/f912aa7f-5561-49b6-94a9-7bc5a9645d70"  alt="DeviceNetworkEvents Github Powershell"></td></tr></table>

---


### 4. Searched the `DeviceProcessEvents` Table

Further searched for unusual changes, particularly with the word "administrators" in the command line.

The dataset reveals activity related to the addition of a user to the `Administrators` group on the device "ruben-th." On **Apr 27, 2025, at 14:30:21 PM**, the command `"net.exe" localgroup administrators NewThreatAccount /add` was executed by the user `employee`, successfully adding the account `NewThreatAccount` to the `Administrators` group. 

Additionally, a second command, `"net.exe" localgroup administrators`, was executed at **Apr 27, 2025, at 14:49:52 PM**, listing the members of the `Administrators` group, which confirms the account was successfully added.

**Query used to locate events:**

```kql
// Detect group policy modifications involving administrators
DeviceProcessEvents
| where DeviceName == "ruben-th"
| where ProcessCommandLine has "administrators"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessAccountName
```
<table><tr><td><img src="https://github.com/user-attachments/assets/e90c54a1-d350-48e8-a6c2-ca939d3a47b2"  alt="DeviceProcessEvents Create Admin User"></td></tr></table>

---

## Chronological Event Timeline

<details>
  <summary> [Click to Expand]</summary>
<p></p>  

### 1. Registry Modification - Delete Cached Standalone Update Binary
- **Time:** 10:34:36 AM, April 27, 2025
- **Event:** A command executed by cmd.exe deleted a registry value related to system updates, targeting the system update configuration.
- **Action:** Registry value deleted.
- **Initiating Process:** cmd.exe
- **Registry Key:** HKEY_CURRENT_USER\SOFTWARE\Microsoft\WindowsUpdate
- **Registry Value Name:** (Exact value not provided, assumed related to update mechanism)


### 2. Registry Modification - Windows Defender Failure Action
- **Time:** 10:34:38 AM, April 27, 2025
- **Event:** A modification was made to a registry key associated with Windows Defender under user-specific settings.
- **Action:** Registry value set (indicating possible tampering with Defender failure actions).
- **Initiating Process:** (Likely via cmd.exe or powershell.exe based on context)
- **Registry Key:** HKEY_CURRENT_USER\SOFTWARE\Microsoft\WindowsDefender\FailureAction
- **Registry Value Name:** FailureAction

### 3. Elevated PowerShell Commands Executed
- **Time:** 09:25:50 AM - 09:25:52 AM, April 27, 2025
- **Event:** Multiple commands initiated by runcommandextension.exe executed cmd.exe, launching PowerShell scripts with the -ExecutionPolicy Unrestricted flag.
- **Action:** Elevated PowerShell execution bypassing standard execution policy.

   - **Command Example:**
`powershell.exe -ExecutionPolicy Unrestricted -NoProfile -NonInteractive -File "C:\path\to\script.ps1"`

- **Initiating Process:** cmd.exe
- **Child Process:** powershell.exe

### 4. Additional PowerShell Script Execution
- **Time:** 09:52:56 AM, April 27, 2025
- **Event:** A new PowerShell process was started directly, executing another PowerShell script using the -ExecutionPolicy Bypass flag.
- **Action:** Elevated PowerShell execution with unsafe parameters.
  
  - **Command Example:**
`powershell.exe -ExecutionPolicy Bypass -File "C:\path\to\script.ps1"`

- **Initiating Process:** powershell.exe

### 5. External Connection to raw.githubusercontent.com (GitHub)
- **Time:** 13:13:28 PM, April 27, 2025
- **Event:** powershell.exe initiated a successful HTTPS connection to raw.githubusercontent.com (IP address 185.199.108.133), suggesting potential script download or remote resource access.
- **Action:** Outbound network connection established.
- **Remote Domain:** raw.githubusercontent.com
- **Remote IP:** 185.199.108.133
- **Initiating Process:** powershell.exe
- **Remote Port:** 443

### 6. Administrators Group Modified - New Account Added
- **Time:** 14:30:21 PM, April 27, 2025
- **Event:** The account NewThreatAccount was added to the local Administrators group using net.exe.
- **Action:** New administrator account added.

  - **Command:**
`net.exe localgroup administrators NewThreatAccount /add`

- **Initiating Process:** net.exe
- **Group:** Administrators
- **New Account Name:** NewThreatAccount
- **Account Executing the Action:** employee

### 7. Administrators Group Enumeration
- **Time:** 14:49:52 PM, April 27, 2025
- **Event:** A net.exe command was used to list members of the local Administrators group, confirming that NewThreatAccount had been successfully added.
- **Action:** Administrator group enumeration.

  - **Command:**
`net.exe localgroup administrators`

- **Initiating Process:** net.exe
- **Account Executing the Action:** employee

</details>

---

## Summary

The user `"employee"` on the device `"ruben-th"` performed a series of actions consistent with tampering with critical system configurations. Key findings include deletion of system update-related registry values, modification of Windows Defender settings, and repeated use of elevated PowerShell commands with unrestricted and bypass execution policies. Additionally, suspicious network activity was observed, with powershell.exe establishing successful outbound connections to `raw.githubusercontent.com`, suggesting potential script downloads. Further investigation revealed the addition of a new local administrator account, `NewThreatAccount`, to the Administrators group. These activities, executed using cmd.exe, powershell.exe, and net.exe, indicate deliberate attempts to weaken the system’s security posture and establish persistence. The registry changes, privilege escalations, and network communications observed strongly suggest potential malicious intent and warrant immediate investigation.

## Response Taken
Unauthorised System Configuration activity was confirmed on the endpoint `"ruben-th"` by the user `"employee"`. The device was immediately flagged for isolation to prevent further potential misuse, and the incident has been escalated to management for formal investigation. A recommendation was made to reset credentials associated with the compromised account, audit all administrator group memberships, and conduct a thorough forensic analysis of the device. Further steps, including a full security assessment and potential disciplinary action, have been advised.

