# Threat Event (Suspicious System Configuration Changes)
**Unauthorised Changes to System Configurations**

## Steps the "Bad Actor" Took Create Logs and IoCs:
1. Disable Windows Defender using PowerShell: `Set-MpPreference -DisableRealtimeMonitoring $true`
2. Modify UAC settings in the registry: `Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0`
3. Disable automatic updates by creating a registry key: `New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1 -PropertyType DWORD`
4. Create a new local administrator account: `net user NewAdminAccount Password123! /add && net localgroup administrators NewAdminAccount /add`
5. Add a firewall rule to allow inbound traffic on port 3389: `New-NetFirewallRule -DisplayName "Simulate RDP Rule" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow`

---

### Tables Used to Detect IoCs

| Parameter Name       | Info                                                                 | Purpose                                                                                                     |
|----------------------|----------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------|
| DeviceFileEvents     | [Link](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table) | Detecting TOR download and installation, shopping list creation and deletion.                              |
| DeviceProcessEvents  | [Link](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table) | Detecting silent TOR installation, browser and service launching.                                          |
| DeviceNetworkEvents  | [Link](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) | Detecting TOR-related network activity by `tor.exe` and `firefox.exe` connecting via TOR-related ports.    |

---

## Related Queries:
```kql
// Detect UAC modifications in the registry
DeviceRegistryEvents
| where RegistryKey == "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" and RegistryValueName == "EnableLUA"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData

// Detect suspicious processes modifying configurations
DeviceProcessEvents
| where FileName in~ ("regedit.exe", "powershell.exe", "cmd.exe", "sc.exe")
| where ProcessCommandLine has_any ("Set-", "Disable", "Enable", "-ExecutionPolicy", "-NoProfile", "-NonInteractive", "bypass", "New-ItemProperty")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName

// Detect unusual network activity following system changes
DeviceNetworkEvents
| where RemotePort in (3389, 445, 135) or RemoteUrl has_any (".onion", "raw.githubusercontent.com", "unknown-domain")
| where ActionType in ("ConnectionSuccess", "ConnectionFailed")
| project Timestamp, RemoteIP, RemotePort, RemoteUrl, ActionType, InitiatingProcessFileName, InitiatingProcessAccountName

// Detect group policy modifications involving administrators
DeviceProcessEvents
| where ProcessCommandLine has "administrators"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessAccountName
```

---

## Created By:
- **Author Name**: Ruben Clarke
- **Author Contact**: linkedin.com/in/itsrubenclarke/
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

