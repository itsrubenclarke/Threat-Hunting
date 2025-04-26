
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

