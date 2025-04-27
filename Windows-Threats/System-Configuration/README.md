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
DeviceProcessEvents
| where DeviceName == "ruben-th"
| where FileName in~ ("regedit.exe", "powershell.exe", "cmd.exe", "sc.exe")
| where ProcessCommandLine has_any ("Set-", "Disable", "Enable", "-ExecutionPolicy", "-NoProfile", "-NonInteractive", "bypass", "New-ItemProperty")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by Timestamp desc 
```


<table><tr><td><img src="https://github.com/user-attachments/assets/8245e424-ab0e-4f2a-b360-4ac7115aee82"  alt="DeviceProcessEvents Execution Policy Bypass"></td></tr></table>

---

