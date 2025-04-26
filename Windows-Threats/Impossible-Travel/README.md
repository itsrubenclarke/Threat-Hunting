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
