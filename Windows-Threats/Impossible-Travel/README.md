# Threat Hunt Report: Impossible Travel
- [Scenario Creation](https://github.com/itsrubenclarke/Threat-Hunting/blob/main/Windows-Threats/Impossible-Travel/Threat-Hunt-Event(Impossible%20Travel).md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- PowerShell

## Scenario

Management is concerned about potential unauthorised access attempts from geographically distant locations, which may indicate compromised credentials or unauthorised user activity. Recent security logs have revealed irregular login attempts from multiple locations within a short time frame, suggesting the possibility of impossible travel. The goal is to detect suspicious login activity, such as logins from distant IPS that occur simultaneously or within an unrealistic timeframe, and analyse any related security incidents. If such activity is identified, notify management for further investigation.

### High-Level PowerShell Discovery Plan

- **Check `DeviceLogonEvents`** for suspicious logon activities, such as multiple logins from distant IP addresses in a short time frame.  
- **Check `DeviceNetworkEvents`** to identify unusual network activity, including logins from unexpected or foreign IP addresses and VPN-related connections.  
- **Check `DeviceProcessEvents`** for evidence of tools or scripts used to simulate logins or tamper with authentication mechanisms (e.g., `powershell.exe`, `cmd.exe`).  

---
## Steps Taken

### 1. Searched the `DeviceLogonEvents' Table

Searched for any suspicious logon activities, such as multiple logins from distant IP addresses in a short time.

The dataset included login events across multiple devices and user accounts, with notable activity for the account `employee`. Logins were recorded for various devices, but the focus has been placed on the machine `ruben-th`, which exhibited activity indicative of potential compromise. Many entries lacked `RemoteIP` details, reducing their relevance to identifying geographic or source anomalies.

**Query used to locate events:**

```kql
DeviceLogonEvents
| project Timestamp, AccountName, DeviceName, RemoteIP
| order by Timestamp desc
```

<table><tr><td><img src="https://github.com/user-attachments/assets/fe07591e-c103-47f1-adb8-ef2250667d5a"  alt="DeviceLogonEvents Initial Query"></td></tr></table>

---

### 2. Searched the `DeviceLogonEvents` Table again

Searched for login events on the device `ruben-th` associated with the account `employee`.

The scope has been refined to prioritise:
- Login events originating from `ruben-th` to identify patterns of unauthorised access.
- Activity associated with the account `employee` to trace potential misuse of credentials.
- Available `RemoteIP` data to detect geographic variations and potential indicators of lateral movement or external compromise.

The dataset reveals multiple login events for the user `employee` on the device `ruben-th`, originating from two distinct IP addresses. On **Apr 27, 2025, at 07:23:50 AM**, login activity was recorded from the IP `199.188.237.194`. Earlier, at **07:10:55 AM**, a login was recorded from the IP `5.45.38.62`. These logins occurred within a short timeframe, indicating geographically disparate access points.

This activity indicates Impossible Travel, where a single account is used to log in from different locations in rapid succession. The presence of these distinct IPs suggests potential credential compromise or the use of obfuscation techniques, such as a VPN, to simulate external access. Further analysis of network and process events may provide additional context to validate this behaviour.

**Query used to locate event:**

```kql
DeviceLogonEvents
| where DeviceName == "ruben-th" and AccountName == "employee"
| project Timestamp, AccountName, DeviceName, RemoteIP
| order by Timestamp desc
```

<table><tr><td><img src="https://github.com/user-attachments/assets/8ab0c07f-4e3b-4482-b8d7-2c4db33c1835"  alt="DeviceLogonEvents Multiple IP Logins"></td></tr></table>

---

### 3. Searched the `DeviceNetworksEvents` Table

Searched for network activity on the device `ruben-th` within the specified time range, filtering for actions initiated by the account `employee`.

The dataset reveals multiple successful network connections initiated by processes tied to the account `employee`. On **Apr 27, 2025, at 07:19:33 AM**, a connection was established to the external IP `4.139.29.52` via `smartscreen.exe`, a process associated with Windows SmartScreen. Additional connections were made shortly thereafter using `SearchApp.exe` at **07:19:35 AM** and **07:20:09 AM**, reaching IPs such as `13.107.213.254` and `13.107.6.254`. These processes indicate legitimate post-login activity from the user, reinforcing evidence of interaction on the system.

While the observed network activity does not directly correspond to the `RemoteIP` addresses from the login events, it supports the timeline of events surrounding the logins. This validates that the account `employee` was actively performing actions during the specified timeframe, lending credibility to the login events as part of a larger behavioural pattern. Additional investigation of the `RemoteIP` addresses may provide further clarity, particularly regarding their geographic origins or connections to known infrastructure.

This information strengthens the case for Impossible Travel by confirming active use of the account during and immediately after the login events, supporting the broader context of the investigation.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "ruben-th" and InitiatingProcessAccountName == "employee"
| where Timestamp >= datetime(2025-04-27T07:10:39.003Z) and Timestamp <= datetime(2025-04-27T07:23:50.411Z)
| project Timestamp, DeviceName, RemoteIP, LocalIP, ActionType, InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by Timestamp desc
```

<table><tr><td><img src="https://github.com/user-attachments/assets/489f7479-1d1a-495c-b890-fd0b76be572a"  alt="DeviceNetworkEvents Smartscreen Process"></td></tr></table>

---


### 4. Searched the `DeviceProcessEvents` Table

### Analysis of `DeviceProcessEvents`

Searched for evidence of tools or scripts used to simulate logins or tamper with authentication mechanisms on the device `ruben-th`.

The dataset reveals multiple instances of `cmd.exe` executed by the account `employee` on `ruben-th`. On **Apr 27, 2025, at 07:11:45 AM**, `cmd.exe` was executed, followed by another execution at **07:19:33 AM**. An earlier execution of `cmd.exe` was recorded on the previous day, along with a `powershell.exe` command,d indicating that the machine may have been compromised a day earlier.

The use of `cmd.exe` indicates interactive activity on the system and corresponds with observed login events. Commands such as `ipconfig` may have been executed to validate network configurations or system information during user activity. While these actions may align with legitimate use, further investigation is required to determine whether they represent authorised actions or potential misuse.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "ruben-th" and AccountName == "employee"
| where FileName in ("powershell.exe", "cmd.exe")
| project Timestamp, AccountName, DeviceName, FileName, ProcessCommandLine
| order by Timestamp desc
```

<table><tr><td><img src="https://github.com/user-attachments/assets/ae6c3311-181d-4ea9-aa6e-8020d325bf23"  alt="DeviceProcessEvents cmd.exe"></td></tr></table>


---


## Chronological Event Timeline

### 1. Login Event and Command Execution
- **Time:** `07:10:55 AM, April 27, 2025`
- **Event:** A login was recorded for the account `employee` from the IP address `5.45.38.62` on the device `ruben-th`.
- **Action:** Shortly after, a process initiated by `cmd.exe` was executed, suggesting interactive user activity.
- **Initiating Process:** `cmd.exe`

### 2. Second Login Event from a Different Location
- **Time:** `07:23:50 AM, April 27, 2025`
- **Event:** Another login was recorded for the same account `employee` from the IP address `199.188.237.194` on the same device.
- **Action:** Network connections to external IPs via `smartscreen.exe` and `SearchApp.exe` were observed shortly after, indicating legitimate user interaction.
- **Initiating Process:** `cmd.exe`

---

## Summary

The user `employee` on the device `ruben-th` exhibited activity aligned with potential suspicious behaviour. Notably, logins were recorded from two geographically distinct IP addresses within a 13-minute window. This rapid succession of access from distant locations is indicative of Impossible Travel, often suggesting compromised credentials or the use of anonymising technologies such as VPNs or proxies.

Following the logins, the user executed `cmd.exe`, suggesting interactive command-line activity. Additional network activity was captured involving `smartscreen.exe` and `SearchApp.exe`, with connections to legitimate Microsoft-related infrastructure. While these processes themselves are not inherently malicious, their execution shortly after the anomalous logins strengthens the timeline linking credential use to device interaction.

Although no evidence of advanced tools (e.g., credential manipulation scripts) was detected during this window, the observed behaviour raises concerns regarding the integrity of the user's session and account.

---

## Response Taken

Suspicious activity was confirmed on the endpoint `ruben-th` by the user `employee`. Anomalous login behaviour, combined with subsequent command execution, suggests the possibility of credential misuse. The device has been flagged for monitoring, and a recommendation has been made to isolate it if further suspicious behaviour is observed. A detailed report has been provided to the manager to determine next steps, which may include credential resets for the affected account, a deeper investigation into the identified IPs, and reviewing access policies to prevent recurrence.

---

