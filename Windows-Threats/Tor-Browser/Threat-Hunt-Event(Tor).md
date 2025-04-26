# Threat Event (Unauthorised TOR Usage)
**Unauthorised TOR Browser Installation and Use**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Download the TOR browser installer: https://www.torproject.org/download/
2. Install it silently: ```tor-browser-windows-x86_64-portable-14.0.1.exe /S```
3. Opens the TOR browser from the folder on the desktop
4. Connect to TOR and browse a few sites.
   - Current Dread Forum: ```dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/```
   - Dark Markets Forum: ```dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/d/DarkNetMarkets```
   - OpSec Forum: ```dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/d/OpSec```
6. Create a file on your desktop called ```tor-shopping-list.txt``` and put a few fake (illicit) items in there
7. Delete the file.

---

### Tables Used to Detect IoCs

| **Parameter Name**     | **Info** | **Description**                                                                                                             
|------------------------|----------|--------------------------------------------------------------------------------------------------------------------------|
| DeviceFileEvents       | [Link](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table)       | Detecting TOR download and installation, shopping list creation and deletion.                                           |
| DeviceProcessEvents    | [Link](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table)       | Detecting silent TOR installation, browser and service launching.                                                       |
| DeviceNetworkEvents    | [Link](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) | Detecting TOR-related network activity by tor.exe and firefox.exe connecting via TOR-related ports.                     |

---

## Related Queries:
```kql
// Installer name == tor-browser-windows-x86_64-portable-(version).exe
// Detect the installer being downloaded
DeviceFileEvents
| where FileName startswith "tor"

// TOR Browser is being silently installed
// Take note of two spaces before the /S (I don't know why)
DeviceProcessEvents
| where ProcessCommandLine startswith "tor-browser-windows"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

// TOR Browser or service was successfully installed and is present on the disk
DeviceFileEvents
| where FileName has_any ("tor.exe", "firefox.exe")
| project  Timestamp, DeviceName, RequestAccountName, ActionType, InitiatingProcessCommandLine

// TOR Browser or service was launched
DeviceProcessEvents
| where ProcessCommandLine has_any("tor.exe","firefox.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// TOR Browser or service is being used and is actively creating network connections
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

// User shopping list was created and, changed, or deleted
DeviceFileEvents
| where FileName has_any (".txt", ".json")
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
