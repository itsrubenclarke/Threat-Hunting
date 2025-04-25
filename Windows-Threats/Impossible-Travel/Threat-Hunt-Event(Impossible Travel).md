# Threat Event (Impossible Travel)
**Anomalous Login Locations**

## Steps Taken by "Bad Actor":
1. **Initial Login:**
   - Login to "Victim" computer from a VM using "compromised" credentials.
   - Run CMD and run "ipconfig" to generate logs.
2. **Simulated Travel:**
   - Use a VPN or proxy to switch to a different geographic location (e.g., Argentina).
   - Perform another login on the same "victim" computer.
   - Run CMD and run "ipconfig" to generate logs.
3. **Post-Attack Behavior:**
   - Logout after completing "suspicious" activity.
     
---

## Tables Used to Detect IoCs:

| **Parameter Name**     | **Info** | **Description**                                                                                                              |
|------------------------|----------|--------------------------------------------------------------------------------------------------------------------------|
| DeviceLogonEvents       | [Link](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/device-logon-events)       | Used to detect login events, including timestamps, usernames, and source IP addresses.                                           |
| DeviceNetworkEvents    | [Link](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/device-network-events)       | Used to detect network activity, including geographic location changes (e.g., VPN usage) and source/destination IP addresses.                                                       |
| DeviceProcessEvents    | [Link](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/device-process-events) | Used to track commands and processes executed on the victim machine, such as `ipconfig` to simulate user activity.                     |


---

## Related Queries:
```kql
// Detect all login attempts, including location and IP address details
DeviceLogonEvents
| project Timestamp, AccountName, DeviceName, RemoteIpAddress

// Narrow scope for login attempts to a suspicious machine
DeviceLogonEvents
| where DeviceName == "" and AccountName == ""
| project Timestamp, AccountName, DeviceName, RemoteIP
| order by Timestamp desc

// Detect network activity initiated by a specific user within a defined timeframe 
DeviceNetworkEvents
| where DeviceName == "" and InitiatingProcessAccountName == ""
| where Timestamp >= datetime() and Timestamp <= datetime()
| project Timestamp, DeviceName, RemoteIP, LocalIP, ActionType, InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by Timestamp desc

// // Detect process executions by a specific user involving key system tools
DeviceProcessEvents
| where DeviceName == "" and AccountName == ""
| where FileName in ("powershell.exe", "cmd.exe")
| project Timestamp, AccountName, DeviceName, FileName, ProcessCommandLine
| order by Timestamp desc
```

---

## Created By:
- **Author Name**: Ruben Clarke
- **Author Contact**: https://www.linkedin.com/in/itsrubenclarke/
- **Date**: April 25, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---


## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `April 25, 2025`  | `Ruben Clarke` 
